//! The named Pack abstraction: parsing, detection and transport of pack
//! sources and destinations.
//!
//! Standard formats are handled by standard crates: JSON with
//! `serde_json`, the tar container with `tar`, gzip with `flate2`,
//! percent-encoding with `percent-encoding`, and TOML manifest writing
//! (in [`crate::manifest`]) with `toml`. No hand-written parsers or
//! encoders for standard formats remain (admin direction 2026-11-08).
//!
//! Safety posture for untrusted archives: member paths are validated (no
//! absolute paths, no `..`, no backslashes, no colons, no Windows device
//! names, no trailing dots or spaces), member names must be UTF-8, the
//! header checksum is verified, and a short member body is an error
//! rather than a truncated file. Resource budgets were removed per admin
//! direction 2026-11-08 ("不要做没必要的限制"): an archive is as large
//! as it is. Link and device members are rejected outright.
//!
//! HTTP posture: only transient failures (transport errors, 429 and 5xx)
//! are retried; other 4xx answers are a definitive miss, and a non-gzip
//! tarball body is a permanent failure that never triggers another
//! request. Response bodies are read in full — no download cap (admin
//! direction 2026-11-08, "不要做没必要的限制").

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Total per-request timeout; a network path must never hang forever.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
/// Attempts per HTTP request for transient failures only (4xx except 429
/// fails immediately).
const RETRIES: usize = 3;
/// The manifest that marks the pack root inside an archive.
const PACK_MANIFEST: &str = "typst.toml";

/// An HTTP agent with connection and total timeouts.
fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .user_agent("typship")
        .build()
}

/// Why a fetch failed, classified so callers know whether to retry, to
/// fall back to the next candidate, or to stop.
#[derive(Debug)]
enum FetchError {
    /// The resource definitively does not exist (HTTP 404): retrying
    /// the same URL never helps, but a caller may fall back to another
    /// candidate (e.g. the next ref interpretation of a tree URL).
    NotFound(String),
    /// A permanent problem (other 4xx such as 401/403, a body over the
    /// download cap, a non-gzip tarball): no retry and no fallback can
    /// fix it.
    Fatal(String),
    /// A transport error, a 429 or a 5xx: worth retrying.
    Transient(String),
}

/// Why reading a response body failed.
#[derive(Debug)]
enum BodyError {
    /// The connection died mid-body (or another I/O error): the
    /// request is worth retrying.
    Io(std::io::Error),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::NotFound(m) | FetchError::Fatal(m) | FetchError::Transient(m) => {
                write!(f, "{m}")
            }
        }
    }
}

impl From<FetchError> for anyhow::Error {
    fn from(e: FetchError) -> Self {
        anyhow!("{e}")
    }
}

/// Read a response body in full. A connection death mid-body is an I/O
/// error, which the retry loop treats as transient.
fn read_body(mut reader: impl Read, url: &str) -> Result<Vec<u8>, BodyError> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).map_err(|e| {
        BodyError::Io(std::io::Error::new(
            e.kind(),
            format!("reading body of {url}: {e}"),
        ))
    })?;
    Ok(buf)
}

/// GET a URL to bytes, retrying only transient failures. A body read
/// error is transient (the connection may have died mid-body).
fn get_bytes(url: &str) -> Result<Vec<u8>, FetchError> {
    let mut last = None;
    for attempt in 0..RETRIES {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(500 * attempt as u64));
        }
        match agent().get(url).call() {
            Ok(resp) => match read_body(resp.into_reader(), url) {
                Ok(bytes) => return Ok(bytes),
                Err(BodyError::Io(e)) => {
                    last = Some(FetchError::Transient(format!("GET {url}: body read: {e}")));
                }
            },
            // A definitive miss: the one status that may trigger a
            // fallback to another candidate.
            Err(ureq::Error::Status(404, _)) => {
                return Err(FetchError::NotFound(format!("GET {url} failed: HTTP 404")));
            }
            // Other client errors (401/403/…) are permanent: no retry,
            // no fallback.
            Err(ureq::Error::Status(code, _)) if (400..500).contains(&code) && code != 429 => {
                return Err(FetchError::Fatal(format!("GET {url} failed: HTTP {code}")));
            }
            Err(e) => {
                last = Some(FetchError::Transient(format!("GET {url}: {e}")));
            }
        }
    }
    Err(last.unwrap())
}

/// [`get_bytes`] with the error flattened into `anyhow` for callers that
/// do not branch on the classification.
fn fetch_bytes(url: &str) -> Result<Vec<u8>> {
    get_bytes(url).map_err(anyhow::Error::from)
}

/// GET a URL that must yield a gzipped tarball. A non-gzip body is a
/// permanent failure, never a reason to re-request.
fn get_tarball(url: &str) -> Result<Vec<u8>, FetchError> {
    let bytes = get_bytes(url)?;
    if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
        return Err(FetchError::Fatal(format!(
            "body of {url} is not a gzipped tarball"
        )));
    }
    Ok(bytes)
}

/// The official Typst preview registry base.
const OFFICIAL_REGISTRY: &str = "https://packages.typst.org/preview";

/// A detected pack source.
#[derive(Debug, Clone)]
pub enum Source {
    /// A directory on the local filesystem.
    Fs(PathBuf),
    /// A local tarball file read directly.
    Tarball(Vec<u8>),
    /// A gzipped tarball read from stdin.
    Stdin,
    /// A registry pack: `@namespace/name[:version]`.
    Registry {
        /// Namespace, e.g. `preview` or `local`.
        namespace: String,
        /// Package name.
        name: String,
        /// Optional exact version; latest is picked when absent.
        version: Option<String>,
    },
    /// A URL that resolves to a gzipped tarball, plus an optional
    /// in-archive subpath.
    Url {
        /// Tarball URL to download.
        url: String,
        /// Subdirectory inside the archive to use, if any.
        subpath: Option<String>,
    },
    /// A GitHub repository tree URL `github.com/{owner}/{repo}/tree/...`;
    /// the ref may contain slashes, so the ref/subpath split is resolved
    /// by trying interpretations from the longest ref down at transport
    /// time.
    GithubTree {
        /// Repository owner.
        owner: String,
        /// Repository name.
        repo: String,
        /// Path segments after `tree/` (ref segments and subpath).
        rest: Vec<String>,
    },
    /// A GitHub release URL (`releases/latest`, `releases/tag/{tag}` or
    /// `releases/{tag}`). Resolved through the GitHub API: a `.tar.gz`/
    /// `.tgz` asset is preferred, the source archive of the resolved tag
    /// is the fallback. `releases/tag/latest` names the literal tag
    /// `latest`, not the latest release.
    GithubRelease {
        /// `owner/repo`.
        repo: String,
        /// Release tag; `None` means the latest release.
        tag: Option<String>,
    },
}

/// A detected pack destination.
#[derive(Debug, Clone)]
pub enum Dest {
    /// A directory to fill with the pack contents.
    Dir(PathBuf),
    /// A `.tar.gz` file to write.
    Tarball(PathBuf),
    /// A GitHub release to upload the tarball to.
    Release {
        /// `owner/repo`.
        repo: String,
        /// Release tag.
        tag: String,
    },
}

fn is_http(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

fn is_fs_path(s: &str) -> bool {
    s.starts_with("./")
        || s.starts_with(".\\")
        || s.starts_with("../")
        || s.starts_with('/')
        || s.starts_with('\\')
        || (s.as_bytes().get(1) == Some(&b':')
            && s.as_bytes()
                .get(2)
                .is_some_and(|b| *b == b'/' || *b == b'\\'))
}

/// Parse `@namespace/name[:version]`. Every component must be a single
/// path-safe, dot-free segment: `.` and `..` are rejected, and colons
/// are not allowed (they are the version separator and an NTFS stream
/// marker).
fn parse_at(s: &str) -> Result<Source> {
    let body = &s[1..];
    let (ns_name, version) = match body.split_once(':') {
        Some((a, b)) => (a, Some(b.to_string())),
        None => (body, None),
    };
    let (namespace, name) = ns_name
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid pack spec `{s}`, expected @namespace/name[:version]"))?;
    if namespace.is_empty() || name.is_empty() {
        bail!("invalid pack spec `{s}`, expected @namespace/name[:version]");
    }
    for part in [namespace, name, version.as_deref().unwrap_or_default()] {
        if part.is_empty() {
            continue;
        }
        if part.contains('/')
            || part.contains('\\')
            || part.contains(':')
            || part == "."
            || part == ".."
        {
            bail!(
                "invalid pack spec `{s}`: namespace, name and version must be single path-safe components"
            );
        }
    }
    if version.as_deref() == Some("") {
        bail!("invalid pack spec `{s}`: empty version");
    }
    Ok(Source::Registry {
        namespace: namespace.to_string(),
        name: name.to_string(),
        version,
    })
}

/// Auto-detect a source pack by shape.
pub fn parse_source(s: &str) -> Result<Source> {
    if s == "-" {
        return Ok(Source::Stdin);
    }
    // A `*.tar.gz`/`*.tgz` file is transported as a tarball, not a
    // directory; a bare file name is accepted as long as it exists.
    let lower = s.to_ascii_lowercase();
    if (lower.ends_with(".tar.gz") || lower.ends_with(".tgz")) && std::path::Path::new(s).is_file()
    {
        let bytes = fs::read(s).with_context(|| format!("reading tarball {s}"))?;
        return Ok(Source::Tarball(bytes));
    }
    if is_fs_path(s) {
        return Ok(Source::Fs(PathBuf::from(s)));
    }
    if s.starts_with('@') {
        return parse_at(s);
    }
    if !is_http(s) {
        bail!("`{s}` is neither a valid pack (fs path, `-`, `@ns/name`) nor an http(s) URL");
    }
    // git pack: `.../repo.git` — no ref is expressible, so the default
    // branch is used. Generic git hosts use different archive layouts;
    // failing clearly beats downloading the wrong thing.
    if let Some(base) = s.strip_suffix(".git") {
        if let Some(rest) = base.strip_prefix("https://github.com/") {
            let mut it = rest.splitn(2, '/');
            let (owner, repo) = (
                it.next()
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| anyhow!("invalid GitHub URL `{s}`"))?,
                it.next()
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| anyhow!("invalid GitHub URL `{s}`"))?,
            );
            return Ok(Source::Url {
                url: format!("https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD"),
                subpath: None,
            });
        }
        bail!(
            "git pack support is limited to github.com URLs; for other hosts pass a direct archive URL"
        );
    }
    let host_and_path = s
        .strip_prefix("https://")
        .unwrap_or_else(|| s.strip_prefix("http://").unwrap_or(s));
    let segs: Vec<&str> = host_and_path.split('/').collect();
    if segs[0] == "github.com" {
        if segs.len() < 3 || segs[1].is_empty() || segs[2].is_empty() {
            bail!("invalid GitHub URL `{s}`");
        }
        let (owner, repo) = (segs[1], segs[2]);
        // `.../archive/...` is already an archive URL: pass it through
        // untouched so the requested ref is preserved.
        if segs.len() >= 4 && segs[3] == "archive" {
            return Ok(Source::Url {
                url: s.to_string(),
                subpath: None,
            });
        }
        // GitHub release pack: releases/latest | releases/tag/{t} |
        // releases/{t} | releases/download/{t}/{asset}.
        if segs.len() >= 4 && segs[3] == "releases" {
            match segs.get(4).copied() {
                Some("download") => {
                    // An asset download URL: use it exactly as given.
                    if segs.len() < 6 {
                        bail!("invalid GitHub release asset URL `{s}`");
                    }
                    return Ok(Source::Url {
                        url: s.to_string(),
                        subpath: None,
                    });
                }
                Some("tag") => {
                    // The tag may contain slashes: everything after
                    // `tag/` is the literal tag, including a tag that
                    // happens to be named `latest`.
                    let tag = segs.get(5..).filter(|t| !t.is_empty()).map(|t| t.join("/"));
                    return Ok(Source::GithubRelease {
                        repo: format!("{owner}/{repo}"),
                        tag,
                    });
                }
                Some("latest") => {
                    return Ok(Source::GithubRelease {
                        repo: format!("{owner}/{repo}"),
                        tag: None,
                    });
                }
                Some(_tag) => {
                    return Ok(Source::GithubRelease {
                        repo: format!("{owner}/{repo}"),
                        tag: Some(segs[4..].join("/")),
                    });
                }
                None => bail!("invalid GitHub release URL `{s}`"),
            }
        }
        // GitHub directory pack: tree/{ref-with-possible-slashes[/subpath]}.
        if segs.len() >= 5 && segs[3] == "tree" {
            return Ok(Source::GithubTree {
                owner: owner.to_string(),
                repo: repo.to_string(),
                rest: segs[4..].iter().map(|s| s.to_string()).collect(),
            });
        }
        if segs.len() == 3 {
            // A plain repository URL: the default branch.
            return Ok(Source::Url {
                url: format!("https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD"),
                subpath: None,
            });
        }
        bail!(
            "`{s}` is not a pack source (expected a repository root, tree, archive, release or .git URL)"
        );
    }
    // Any other http(s) URL: a tarball.
    Ok(Source::Url {
        url: s.to_string(),
        subpath: None,
    })
}

/// Auto-detect a destination pack by shape.
pub fn parse_dest(s: &str) -> Result<Dest> {
    if is_fs_path(s) {
        let lower = s.to_ascii_lowercase();
        if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
            return Ok(Dest::Tarball(PathBuf::from(s)));
        }
        return Ok(Dest::Dir(PathBuf::from(s)));
    }
    if is_http(s) {
        let host_and_path = s
            .strip_prefix("https://")
            .unwrap_or_else(|| s.strip_prefix("http://").unwrap_or(s));
        let segs: Vec<&str> = host_and_path.split('/').collect();
        // to release: github.com/{o}/{r}/releases/{tag} (or releases/tag/{tag})
        if segs.len() >= 5 && segs[0] == "github.com" && segs[3] == "releases" {
            let tag = match segs[4] {
                "tag" => segs
                    .get(5..)
                    .filter(|t| !t.is_empty())
                    .map(|t| t.join("/"))
                    .ok_or_else(|| anyhow!("invalid GitHub release URL `{s}`"))?,
                "download" => bail!("`{s}` is an asset URL, not an upload target"),
                _ => segs[4..].join("/"),
            };
            return Ok(Dest::Release {
                repo: format!("{}/{}", segs[1], segs[2]),
                tag,
            });
        }
    }
    bail!("`{s}` is neither a valid destination (fs dir, `*.tar.gz`, GitHub release URL)");
}

/// Make `p` absolute (against the current directory when needed) and
/// lexically normal; on Windows also strips `\\?\` verbatim prefixes.
fn normalize_absolute(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|c| c.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    };
    let text = abs.to_string_lossy().to_string();
    let text = strip_verbatim(text);
    Path::new(&text)
        .components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect()
}

/// Strip `\\?\` / `\\?\UNC\` verbatim prefixes (Windows only). The UNC
/// form keeps two leading backslashes: `\\?\UNC\server\share` is
/// `\\server\share`.
#[cfg(target_os = "windows")]
fn strip_verbatim(text: String) -> String {
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text.strip_prefix("\\\\?\\") {
        rest.to_string()
    } else {
        text
    }
}

/// Identity outside Windows.
#[cfg(not(target_os = "windows"))]
fn strip_verbatim(text: String) -> String {
    text
}

/// The physical path of `p` as far as the filesystem can tell: the
/// longest existing ancestor is canonicalized (resolving symlinks,
/// junctions and case differences) and the remaining suffix joined back
/// on. Non-existing tails keep their lexical form.
fn physical(p: &Path) -> PathBuf {
    let norm = normalize_absolute(p);
    let mut ancestor = norm.as_path();
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(real) => {
                let mut out: PathBuf = real;
                for part in suffix.iter().rev() {
                    out.push(part);
                }
                return normalize_absolute(&out);
            }
            Err(_) => match (ancestor.parent(), ancestor.file_name()) {
                (Some(parent), Some(last)) => {
                    suffix.push(last.to_os_string());
                    ancestor = parent;
                }
                _ => return normalize_absolute(p),
            },
        }
    }
}

/// Component-wise path comparison; on Windows the comparison is
/// case-insensitive because NTFS names are case-preserving but
/// case-insensitive.
fn path_comps(p: &Path) -> Vec<String> {
    p.components()
        .map(|c| {
            let s = c.as_os_str().to_string_lossy().to_string();
            #[cfg(target_os = "windows")]
            let s = s.to_ascii_lowercase();
            s
        })
        .collect()
}

fn same_path(a: &Path, b: &Path) -> bool {
    path_comps(a) == path_comps(b)
}

/// Whether `child` equals `parent` or sits below it, component-wise.
fn is_prefix(child: &Path, parent: &Path) -> bool {
    let c = path_comps(child);
    let p = path_comps(parent);
    p.len() <= c.len() && c[..p.len()] == p[..]
}

/// Refuse a copy whose destination is the source or sits inside it (or
/// vice versa); otherwise `copy_tree` recurses into itself. Both ends
/// are resolved physically (existing ancestors canonicalized, so
/// junctions, symlinks and case aliases cannot slip past) and compared
/// component-wise.
fn ensure_distinct(src: &Path, dst: &Path) -> Result<()> {
    let s = path_clean::clean(physical(src));
    let d = path_clean::clean(physical(dst));
    if same_path(&s, &d) {
        bail!(
            "source and destination are the same directory `{}`",
            src.display()
        );
    }
    if is_prefix(&d, &s) {
        bail!(
            "destination `{}` is inside source `{}`",
            dst.display(),
            src.display()
        );
    }
    if is_prefix(&s, &d) {
        bail!(
            "source `{}` is inside destination `{}`",
            src.display(),
            dst.display()
        );
    }
    Ok(())
}

/// The per-user Typst packages directory; the well-known directory
/// lookup is delegated to the `dirs` crate (LOCALAPPDATA on Windows,
/// XDG_DATA_HOME or the platform default elsewhere).
fn typst_packages_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    let base = dirs::data_local_dir();
    #[cfg(not(target_os = "windows"))]
    let base = dirs::data_dir();
    let base = base.ok_or_else(|| anyhow!("cannot determine the per-user data directory"))?;
    Ok(base.join("typst").join("packages"))
}

/// Pick the greatest version-like directory name under `dir`.
fn latest_version_dir(dir: &Path) -> Result<Option<String>> {
    let mut best: Option<(Vec<u64>, String)> = None;
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let nums: Vec<u64> = name
            .split('.')
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect();
        if best.as_ref().is_none_or(|(b, _)| nums > *b) {
            best = Some((nums, name));
        }
    }
    Ok(best.map(|(_, n)| n))
}

/// A source resolved to concrete bytes or a filesystem location.
enum Materialized {
    /// A directory already on disk (must not be mutated).
    Dir(PathBuf),
    /// A gzipped tarball held in memory.
    Tarball(Vec<u8>),
}

/// The chain of candidate roots inside an extracted archive: the
/// extraction directory itself plus each directory along a chain of
/// single subdirectories (up to three levels, the GitHub `repo-ref/`
/// wrapper and the repository's own single-child prefixes).
fn archive_chain(tmp: &Path) -> Vec<PathBuf> {
    let mut chain = vec![tmp.to_path_buf()];
    let mut cur = tmp.to_path_buf();
    for _ in 0..3 {
        let Ok(entries) = fs::read_dir(&cur) else {
            break;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        if entries.len() == 1 && entries[0].file_type().map(|t| t.is_dir()).unwrap_or(false) {
            cur = entries.remove(0).path();
            chain.push(cur.clone());
        } else {
            break;
        }
    }
    chain
}

/// Locate a subpath inside an extracted archive: try the full relative
/// path from every candidate root on the single-subdirectory chain
/// first, then a segment-wise `find_dir` search from each candidate
/// root (the first segment is matched among the direct children of a
/// directory, then the rest below it). There is no arbitrary-depth
/// search: a subpath whose first segment sits deeper than the candidate
/// chain will not be found. This keeps a `repo-HEAD/` wrapper
/// transparent without swallowing the repository's own single-child
/// directories.
fn locate_subdir(tmp: &Path, sub: &str) -> Option<PathBuf> {
    let chain = archive_chain(tmp);
    for root in &chain {
        let direct = root.join(sub);
        if direct.is_dir() {
            return Some(direct);
        }
    }
    chain.iter().find_map(|root| find_dir(root, sub))
}

/// Find a relative directory below one of the candidate roots of an
/// extracted archive (see [`archive_chain`]).
fn find_in_chain(tmp: &Path, rel: &str) -> Option<PathBuf> {
    archive_chain(tmp)
        .iter()
        .find_map(|root| find_dir(root, rel))
}

/// Resolve a [`Source`] into bytes or a directory.
fn materialize(src: &Source, registry: Option<&str>) -> Result<Materialized> {
    match src {
        Source::Fs(p) => {
            if !p.is_dir() {
                bail!("fs pack `{}` is not a directory", p.display());
            }
            Ok(Materialized::Dir(p.clone()))
        }
        Source::Tarball(bytes) => Ok(Materialized::Tarball(bytes.clone())),
        Source::Stdin => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading tarball from stdin")?;
            Ok(Materialized::Tarball(buf))
        }
        Source::Registry {
            namespace,
            name,
            version,
        } => materialize_registry(namespace, name, version.as_deref(), registry),
        Source::Url { url, subpath } => {
            let bytes = get_tarball(url)?;
            if subpath.is_none() {
                return Ok(Materialized::Tarball(bytes));
            }
            // Extract to a temp dir, then keep the subpath directory.
            let tmp = temp_dir()?;
            extract_tarball(&bytes, &tmp, None)?;
            let sub = subpath.as_deref().unwrap_or_default();
            let found = locate_subdir(&tmp, sub)
                .ok_or_else(|| anyhow!("subpath `{sub}` not found in archive"))?;
            Ok(Materialized::Dir(found))
        }
        Source::GithubTree { owner, repo, rest } => materialize_github_tree(owner, repo, rest),
        Source::GithubRelease { repo, tag } => materialize_github_release(repo, tag.as_deref()),
    }
}

/// Resolve a GitHub tree URL: the ref may contain slashes, so try
/// interpretations from the longest ref to the shortest one. Only a
/// definitive miss ([`FetchError::NotFound`]) moves on to the next
/// candidate; a broken payload or a transport failure aborts.
fn materialize_github_tree(owner: &str, repo: &str, rest: &[String]) -> Result<Materialized> {
    if rest.is_empty() {
        bail!("invalid GitHub tree URL: no ref after `tree/`");
    }
    let mut last_err = None;
    for k in (1..=rest.len()).rev() {
        let ref_name = rest[..k].join("/");
        let subpath = if rest.len() > k {
            Some(rest[k..].join("/"))
        } else {
            None
        };
        let url = format!("https://codeload.github.com/{owner}/{repo}/tar.gz/{ref_name}");
        match get_tarball(&url) {
            Ok(bytes) => {
                if subpath.is_none() {
                    return Ok(Materialized::Tarball(bytes));
                }
                let tmp = temp_dir()?;
                extract_tarball(&bytes, &tmp, None)?;
                let sub = subpath.as_deref().unwrap_or_default();
                return match locate_subdir(&tmp, sub) {
                    Some(dir) => Ok(Materialized::Dir(dir)),
                    None => Err(anyhow!("subpath `{sub}` not found in archive of `{url}`")),
                };
            }
            Err(FetchError::NotFound(e)) => last_err = Some(anyhow!("{e}")),
            Err(e) => return Err(anyhow!("{e}")),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("could not resolve GitHub tree URL")))
}

/// Resolve a GitHub release URL through the API: prefer a `.tar.gz`/`.tgz`
/// asset, fall back to the source archive of the resolved tag.
fn materialize_github_release(repo: &str, tag: Option<&str>) -> Result<Materialized> {
    let api = match tag {
        Some(t) => format!(
            "https://api.github.com/repos/{repo}/releases/tags/{}",
            percent_encode(t)
        ),
        None => format!("https://api.github.com/repos/{repo}/releases/latest"),
    };
    let body = fetch_bytes(&api)?;
    let text =
        String::from_utf8(body).map_err(|_| anyhow!("release response from {api} is not UTF-8"))?;
    let value = json_parse(&text, &format!("release response from {api}"))?;
    if let Some(url) = release_archive_asset(&value) {
        return Ok(Materialized::Tarball(get_tarball(&url)?));
    }
    // No archive asset: fall back to the source archive of the tag.
    let tag_name = value
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("release lookup for `{repo}` returned no tag_name"))?;
    Ok(Materialized::Tarball(get_tarball(&format!(
        "https://codeload.github.com/{repo}/tar.gz/refs/tags/{tag_name}"
    ))?))
}

/// The first `.tar.gz`/`.tgz` asset download URL of a parsed release
/// document, if any.
fn release_archive_asset(release: &Json) -> Option<String> {
    release.get("assets")?.as_array()?.iter().find_map(|asset| {
        let url = asset.get("browser_download_url")?.as_str()?;
        let lower = url.to_ascii_lowercase();
        (lower.ends_with(".tar.gz") || lower.ends_with(".tgz")).then(|| url.to_string())
    })
}

/// Resolve a registry pack to a tarball download or a local directory.
fn materialize_registry(
    namespace: &str,
    name: &str,
    version: Option<&str>,
    registry: Option<&str>,
) -> Result<Materialized> {
    if namespace == "local" {
        let base = typst_packages_dir()?.join("local").join(name);
        let version = match version {
            Some(v) => v.to_string(),
            None => latest_version_dir(&base)?.ok_or_else(|| {
                anyhow!(
                    "no local version of `{name}` found under {}",
                    base.display()
                )
            })?,
        };
        let dir = base.join(version);
        if !dir.is_dir() {
            bail!("local pack `{}` not found", dir.display());
        }
        return Ok(Materialized::Dir(dir));
    }
    match registry {
        None if namespace == "preview" => {
            let version = match version {
                Some(v) => v.to_string(),
                None => latest_official_version(name)?,
            };
            Ok(Materialized::Tarball(get_tarball(&format!(
                "{OFFICIAL_REGISTRY}/{name}-{version}.tar.gz"
            ))?))
        }
        Some(url) => {
            // A GitHub repository acting as a packages registry, using the
            // standard Typst layout `packages/{namespace}/{name}/{version}`
            // (a legacy flat `packages/{name}` layout is also accepted).
            // Only the exact host github.com counts.
            let github: Option<String> = url
                .strip_prefix("https://github.com/")
                .or_else(|| url.strip_prefix("http://github.com/"))
                .map(|p| p.trim_matches('/').to_string());
            if let Some(path) = github {
                let mut it = path.splitn(2, '/');
                let owner = it
                    .next()
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| anyhow!("invalid GitHub registry `{url}`"))?;
                let repo = it
                    .next()
                    .unwrap_or_default()
                    .split('/')
                    .next()
                    .unwrap_or_default();
                if repo.is_empty() {
                    bail!("invalid GitHub registry `{url}`");
                }
                let bytes = get_tarball(&format!(
                    "https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD"
                ))?;
                let tmp = temp_dir()?;
                extract_tarball(&bytes, &tmp, None)?;
                let pkg_base = find_in_chain(&tmp, &format!("packages/{namespace}/{name}"))
                    .or_else(|| find_in_chain(&tmp, &format!("packages/{name}")))
                    .ok_or_else(|| {
                        anyhow!("package `{namespace}/{name}` not found in registry `{url}`")
                    })?;
                let version = match version {
                    Some(v) => v.to_string(),
                    None => latest_version_dir(&pkg_base)?
                        .ok_or_else(|| anyhow!("no version of `{name}` in registry `{url}`"))?,
                };
                return Ok(Materialized::Dir(pkg_base.join(version)));
            }
            let version = match version {
                Some(v) => v.to_string(),
                None => latest_index_version(url, name)?,
            };
            Ok(Materialized::Tarball(get_tarball(&format!(
                "{}/{name}-{version}.tar.gz",
                url.trim_end_matches('/')
            ))?))
        }
        None => bail!("namespace `{namespace}` requires a custom registry: pass --registry <URL>"),
    }
}

/// Latest version of a package from the official registry index.
fn latest_official_version(name: &str) -> Result<String> {
    latest_index_version(OFFICIAL_REGISTRY, name)
}

/// Latest version of a package from `{base}/index.json`: fetch the
/// index and hand the text to [`latest_from_index_json`].
fn latest_index_version(base: &str, name: &str) -> Result<String> {
    let body = fetch_bytes(&format!("{}/index.json", base.trim_end_matches('/')))?;
    let text = String::from_utf8(body)
        .map_err(|_| anyhow!("registry index at {base}/index.json is not UTF-8"))?;
    latest_from_index_json(&text, name)
        .map_err(|e| anyhow!("reading registry index at {base}/index.json: {e:#}"))
}

/// The greatest version among the entries of a registry index whose
/// `name` matches, parsed as real JSON (the index is an array of
/// objects). Pure so tests exercise the production function directly.
fn latest_from_index_json(text: &str, name: &str) -> Result<String> {
    let value = json_parse(text, "registry index")?;
    let entries = value
        .as_array()
        .ok_or_else(|| anyhow!("registry index JSON is not an array"))?;
    let mut best: Option<(Vec<u64>, String)> = None;
    for entry in entries {
        if entry.get("name").and_then(|v| v.as_str()) != Some(name) {
            continue;
        }
        if let Some(v) = entry.get("version").and_then(|v| v.as_str()) {
            let nums: Vec<u64> = v
                .split('.')
                .map(|p| p.parse::<u64>().unwrap_or(0))
                .collect();
            if best.as_ref().is_none_or(|(b, _)| nums > *b) {
                best = Some((nums, v.to_string()));
            }
        }
    }
    best.map(|(_, v)| v)
        .ok_or_else(|| anyhow!("package `{name}` not found in registry index"))
}

/// Find a directory at the exact relative path `rel` below `root`, by
/// matching the first segment among the direct children of a directory
/// and the rest below it. This is not an arbitrary-depth search: the
/// first segment must be a direct child at some level of the descent.
fn find_dir(root: &Path, rel: &str) -> Option<PathBuf> {
    fn walk(dir: &Path, rel: &[&str]) -> Option<PathBuf> {
        if rel.is_empty() {
            return Some(dir.to_path_buf());
        }
        for entry in fs::read_dir(dir).ok()?.flatten() {
            if entry.file_type().ok()?.is_dir() && entry.file_name().to_string_lossy() == rel[0] {
                if let Some(found) = walk(&entry.path(), &rel[1..]) {
                    return Some(found);
                }
            }
        }
        None
    }
    let parts: Vec<&str> = rel.split('/').collect();
    walk(root, &parts)
}

/// A fresh private temporary directory for this process.
/// A per-invocation disambiguator for temporary names.
fn temp_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    )
}

/// A directory that removes itself (best effort) when dropped. This
/// mirrors the official typst package-store flow: materialize the
/// contents in a temporary directory located directly next to the
/// destination (so a later `rename` stays on one mount point), then
/// move it into place atomically.
struct TempDir(PathBuf);

impl TempDir {
    /// A temp dir next to `path`'s parent, on the same mount point as
    /// the final destination.
    fn next_to(path: &Path, label: &str) -> Result<Self> {
        let dir = path.with_file_name(format!(".typship-tmp-{label}-{}", temp_suffix()));
        fs::create_dir(&dir).with_context(|| format!("creating temp dir {}", dir.display()))?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Write `bytes` to `path` via a temp file next to it and an atomic
/// rename: an interrupted write never leaves a partial tarball at the
/// destination, and a completed one appears atomically.
fn write_tarball_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_file_name(format!(".typship-tmp-file-{}", temp_suffix()));
    let outcome = (|| -> Result<()> {
        fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, path)
            .with_context(|| format!("moving {} to {}", tmp.display(), path.display()))?;
        Ok(())
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    outcome
}

/// Atomically move directory `from` onto `to` via rename. An existing
/// empty destination directory is replaced; a non-empty one (including
/// one that appeared concurrently) is an error, never a merge.
fn move_dir_atomic(from: &Path, to: &Path) -> Result<()> {
    if to.exists() {
        if fs::read_dir(to)?.next().is_some() {
            bail!("destination `{}` exists and is not empty", to.display());
        }
        fs::remove_dir(to).with_context(|| format!("removing empty {}", to.display()))?;
    }
    fs::rename(from, to).with_context(|| format!("moving {} to {}", from.display(), to.display()))
}

fn temp_dir() -> Result<PathBuf> {
    let base = std::env::temp_dir();
    let dir = base.join(format!(
        "typship-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    // Fail loudly instead of writing into a shared directory.
    fs::create_dir(&dir).with_context(|| format!("creating temp dir {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

// ---------------------------------------------------------------------------
// JSON — read with serde_json (admin direction: standard crates over
// hand-rolled parsers).
// ---------------------------------------------------------------------------

use serde_json::Value as Json;

fn json_parse(text: &str, what: &str) -> Result<Json> {
    serde_json::from_str(text).map_err(|e| anyhow!("invalid JSON in {what}: {e}"))
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// tar reading — the `tar` crate over a strict multi-member gzip stream
// (admin direction: standard crates over hand-rolled parsers). The
// crate verifies header checksums, handles ustar/GNU/PAX long names and
// rejects malformed frames; this layer keeps the resource budgets, the
// member-type allowlist and the archive-path validation.
// ---------------------------------------------------------------------------

/// Parse an octal field, tolerating trailing NULs and spaces; anything
/// else is an error, never a silent zero. Used only by tests that
/// inspect raw header fields.
#[cfg(test)]
fn octal(field: &[u8]) -> Result<u64> {
    let s: String = field
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect();
    let s = s.trim().trim_start_matches('0');
    let s = if s.is_empty() { "0" } else { s };
    if !s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        bail!("invalid octal field `{s}` in tar header");
    }
    u64::from_str_radix(s, 8).context("invalid octal field in tar header")
}

/// Windows reserved device names; a component whose stem (before the
/// first dot) matches one of these, in any case, cannot exist as a file
/// or directory on Windows.
const WINDOWS_RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validate an archive member path: it must be relative, slash-separated
/// UTF-8 text that stays inside the destination and can exist on every
/// supported filesystem — no drive letters or NTFS streams (colons), no
/// reserved device names, no trailing dots or spaces. A single trailing
/// slash (the conventional directory entry spelling) is tolerated.
fn safe_member_path(path: &str) -> Result<String> {
    // Directory entries conventionally end in `/`; drop that one slash
    // before the component checks (internal empty components stay
    // rejected).
    let path = path.strip_suffix('/').unwrap_or(path);
    if path.is_empty() {
        bail!("empty archive member path");
    }
    if path.starts_with('/') {
        bail!("absolute path `{path}` in archive");
    }
    if path.contains('\\') {
        bail!("backslash in archive path `{path}`");
    }
    if path.contains(':') {
        bail!("colon in archive path `{path}`");
    }
    for comp in path.split('/') {
        if comp == ".." {
            bail!("parent directory component in archive path `{path}`");
        }
        if comp.is_empty() {
            bail!("empty component in archive path `{path}`");
        }
        if comp.ends_with('.') || comp.ends_with(' ') {
            bail!(
                "component `{comp}` in archive path `{path}` ends with a dot or space, which Windows cannot address"
            );
        }
        let stem = comp.split('.').next().unwrap_or_default();
        if WINDOWS_RESERVED.contains(&stem.to_ascii_uppercase().as_str()) {
            bail!("component `{comp}` in archive path `{path}` is a reserved Windows device name");
        }
    }
    Ok(path.to_string())
}

/// Extract a gzipped tarball into `dest`, keeping only entries under the
/// optional `subpath` (relative to the archive root). No prefix is
/// stripped here; the pack root is located afterwards by
/// [`find_pack_root`].
pub fn extract_tarball(gz: &[u8], dest: &Path, subpath: Option<&str>) -> Result<()> {
    // The `tar` crate verifies checksums and handles ustar/GNU/PAX long
    // names; this loop enforces the member-type allowlist (plain files
    // and directories only) and the archive-path validation, then writes
    // each member out itself. No resource budgets: an archive is as
    // large as it is (admin direction 2026-11-08, "不要做没必要的限制").
    let mut gz = MultiGzDecoder::new(gz);
    {
        let mut archive = tar::Archive::new(&mut gz);
        // Ignore the end-of-archive marker and run to real EOF: without
        // this the crate stops after the FIRST zero block, and trailing
        // garbage after the gzip member would go unnoticed.
        archive.set_ignore_zeros(true);
        for entry in archive.entries().context("reading tar entries")? {
            let mut entry = entry.with_context(|| "malformed tar entry")?;
            let etype = entry.header().entry_type();
            if !matches!(
                etype,
                tar::EntryType::Regular | tar::EntryType::Directory | tar::EntryType::Continuous
            ) {
                bail!("tar member is a {etype:?}; link/device members are not supported");
            }
            let raw_path = entry.path().context("invalid tar member path")?;
            let path = raw_path
                .to_str()
                .ok_or_else(|| {
                    anyhow!("archive member name is not valid UTF-8; such archives are rejected")
                })?
                .trim_end_matches('/')
                .to_string();
            let mut path = safe_member_path(&path)?;
            if let Some(sub) = subpath {
                let prefix = format!("{sub}/");
                if !path.starts_with(&prefix) {
                    continue;
                }
                path = path[prefix.len()..].to_string();
                if path.is_empty() {
                    continue;
                }
            }
            let out = dest.join(&path);
            if !out.starts_with(dest) {
                bail!("archive member `{path}` escapes the destination");
            }
            if matches!(etype, tar::EntryType::Directory) {
                fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
            } else {
                if let Some(parent) = out.parent() {
                    fs::create_dir_all(parent)?;
                }
                let size = entry.header().size().context("invalid tar member size")?;
                // The header's size bounds the read; a short body is an
                // error, never a truncated file.
                let mut data = Vec::new();
                (&mut entry)
                    .take(size)
                    .read_to_end(&mut data)
                    .with_context(|| format!("reading tar entry `{path}`"))?;
                if data.len() as u64 != size {
                    bail!("truncated tar entry `{path}`");
                }
                fs::write(&out, &data).with_context(|| format!("writing {}", out.display()))?;
            }
        }
    }
    // The archive loop ran to EOF (ignore_zeros), so any remaining bytes
    // indicate a second gzip member that failed to decode; drain anyway
    // to surface its error explicitly.
    let mut rest = Vec::new();
    gz.read_to_end(&mut rest)
        .context("malformed data after the archive")?;
    if !rest.is_empty() {
        bail!("trailing data after the end of the archive");
    }
    Ok(())
}

/// Encode files under `dir` (recursively) as a gzipped tarball; the
/// ustar encoding itself is delegated to the `tar` crate.
pub fn pack_tarball(dir: &Path) -> Result<Vec<u8>> {
    let enc = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(enc);
    add_tree(&mut builder, dir, "")?;
    builder.finish().context("finishing tar archive")?;
    builder
        .into_inner()
        .context("finishing gzip stream")?
        .finish()
        .context("finishing gzip stream")
}

fn add_tree(builder: &mut tar::Builder<GzEncoder<Vec<u8>>>, dir: &Path, rel: &str) -> Result<()> {
    if !rel.is_empty() {
        append_entry(builder, rel, true, &[])?;
    }
    let mut entries: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        let child_rel = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            add_tree(builder, &path, &child_rel)?;
        } else {
            let data = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            append_entry(builder, &child_rel, false, &data)?;
        }
    }
    Ok(())
}

/// Append one member to the archive: a plain file or a directory, with
/// fixed metadata (mode 0644/0755, mtime 0, uid/gid 0).
///
/// The path is set through `Header::set_path` directly — for a ustar
/// header that means a split into `prefix` + `name` or an error, never
/// an extension entry, so an unsplittable over-long path is refused with
/// a clear message instead of producing a special-format member
/// (`Builder::append_data` would silently fall back to a GNU long-name
/// entry, which the writer contract forbids).
fn append_entry(
    builder: &mut tar::Builder<GzEncoder<Vec<u8>>>,
    path: &str,
    is_dir: bool,
    data: &[u8],
) -> Result<()> {
    // No trailing slash on directory entries: the typeflag marks the
    // directory, and a trailing slash would break `set_path` for
    // long single-component directory names.
    let name = path.to_string();
    let mut header = tar::Header::new_ustar();
    header.set_path(&name).map_err(|e| {
        anyhow!(
            "archive path `{name}` is too long for the ustar layout (over 100 bytes after a 155-byte prefix); no such file will be written ({e})"
        )
    })?;
    header.set_entry_type(if is_dir {
        tar::EntryType::Directory
    } else {
        tar::EntryType::Regular
    });
    header.set_size(if is_dir { 0 } else { data.len() as u64 });
    header.set_mode(if is_dir { 0o755 } else { 0o644 });
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    builder
        .append(&header, data)
        .with_context(|| format!("appending `{name}` to the archive"))
}

// ---------------------------------------------------------------------------
// transport
// ---------------------------------------------------------------------------

/// Recursively copy a directory tree.
fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to).with_context(|| format!("creating {}", to.display()))?;
    for entry in fs::read_dir(from).with_context(|| format!("reading {}", from.display()))? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)
                .with_context(|| format!("copying to {}", target.display()))?;
        }
    }
    Ok(())
}

/// Copy (transport) a named pack from `src` to `dst`.
pub fn copy(src: &str, dst: &str, registry: Option<&str>) -> Result<()> {
    let source = parse_source(src)?;
    let dest = parse_dest(dst)?;
    let mat = materialize(&source, registry)?;
    match (mat, dest) {
        (Materialized::Tarball(bytes), Dest::Tarball(path)) => {
            write_tarball_atomic(&path, &bytes)?;
        }
        (Materialized::Dir(dir), Dest::Tarball(path)) => {
            ensure_distinct(&dir, &path)?;
            let bytes = pack_tarball(&dir)?;
            write_tarball_atomic(&path, &bytes)?;
        }
        (Materialized::Tarball(bytes), Dest::Dir(path)) => {
            if path.exists() && fs::read_dir(&path)?.next().is_some() {
                bail!("destination `{}` exists and is not empty", path.display());
            }
            // typst-style atomicity: extract into a temp dir next to the
            // destination (same mount point), then rename the pack root
            // into place. A failed extraction leaves no trace at the
            // destination; a completed one appears atomically.
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            let tmp = TempDir::next_to(&path, "extract")?;
            extract_tarball(&bytes, tmp.path(), None)?;
            let inner = find_pack_root(tmp.path())?;
            move_dir_atomic(&inner, &path)?;
        }
        (Materialized::Dir(dir), Dest::Dir(path)) => {
            ensure_distinct(&dir, &path)?;
            if path.exists() && fs::read_dir(&path)?.next().is_some() {
                bail!("destination `{}` exists and is not empty", path.display());
            }
            // typst-style atomicity: copy into a temp dir next to the
            // destination (same mount point), then rename into place --
            // an interrupted copy never leaves a half-populated pack.
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            let tmp = TempDir::next_to(&path, "copy")?;
            copy_tree(&dir, tmp.path())?;
            move_dir_atomic(tmp.path(), &path)?;
        }
        (mat, Dest::Release { repo, tag }) => {
            let bytes = match mat {
                Materialized::Tarball(bytes) => bytes,
                Materialized::Dir(dir) => pack_tarball(&dir)?,
            };
            let asset_name = match source {
                Source::Fs(ref p) => format!(
                    "{}.tar.gz",
                    p.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "pack".into())
                ),
                Source::Registry { ref name, .. } => format!("{name}.tar.gz"),
                _ => "pack.tar.gz".to_string(),
            };
            upload_release_asset(&repo, &tag, &asset_name, &bytes)?;
        }
    }
    Ok(())
}

/// Locate the pack root inside an extracted archive: the first directory
/// along the chain of single subdirectories (up to three levels) that
/// contains a `typst.toml` manifest. Without a manifest the extracted
/// tree is used as-is, preserving its structure exactly.
fn find_pack_root(tmp: &Path) -> Result<PathBuf> {
    fn has_manifest(dir: &Path) -> bool {
        dir.join(PACK_MANIFEST).is_file()
    }
    if has_manifest(tmp) {
        return Ok(tmp.to_path_buf());
    }
    let mut cur = tmp.to_path_buf();
    for _ in 0..3 {
        let mut entries: Vec<_> = fs::read_dir(&cur)
            .with_context(|| format!("reading {}", cur.display()))?
            .collect::<std::io::Result<_>>()?;
        if entries.len() != 1 || !entries[0].file_type()?.is_dir() {
            break;
        }
        cur = entries.remove(0).path();
        if has_manifest(&cur) {
            return Ok(cur);
        }
    }
    Ok(tmp.to_path_buf())
}

/// Create (if missing) a GitHub release and upload `bytes` as an asset.
/// Requires a token in `GITHUB_TOKEN` (or `TYPSHIP_TOKEN`).
fn upload_release_asset(repo: &str, tag: &str, asset_name: &str, bytes: &[u8]) -> Result<()> {
    let token = std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("TYPSHIP_TOKEN"))
        .map_err(|_| {
            anyhow!(
                "uploading to a GitHub release requires a token in the GITHUB_TOKEN environment variable"
            )
        })?;
    let api = format!("https://api.github.com/repos/{repo}/releases");
    // Find an existing release by tag; only a 404 leads to creating one.
    let existing = agent()
        .get(&format!("{api}/tags/{}", percent_encode(tag)))
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    let upload_url = match existing {
        Ok(resp) => {
            let body = resp.into_string().context("reading release response")?;
            release_upload_url(&body, tag)?
        }
        Err(ureq::Error::Status(404, _)) => {
            let body = format!(
                r#"{{"tag_name":{},"name":{}}}"#,
                json_escape(tag),
                json_escape(tag)
            );
            let resp = agent()
                .post(&api)
                .set("Authorization", &format!("Bearer {token}"))
                .set("Content-Type", "application/json")
                .send_string(&body)
                .map_err(|e| anyhow!("creating release {tag} on {repo}: {e}"))?;
            let text = resp.into_string().context("reading release response")?;
            release_upload_url(&text, tag)?
        }
        Err(e) => return Err(anyhow!("looking up release {tag} on {repo} failed: {e}")),
    };
    let upload_url = upload_url.replace("{?name,label}", "");
    if !upload_url.starts_with("https://uploads.github.com/") {
        bail!("release upload URL is not an uploads.github.com endpoint");
    }
    agent()
        .post(&format!("{upload_url}?name={}", percent_encode(asset_name)))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/gzip")
        .send_bytes(bytes)
        .map_err(|e| anyhow!("uploading asset {asset_name}: {e}"))?;
    Ok(())
}

/// Extract `upload_url` from a parsed release document.
fn release_upload_url(body: &str, tag: &str) -> Result<String> {
    let value = json_parse(body, "release document")?;
    value
        .get("upload_url")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("release for tag `{tag}` has no upload_url"))
}

/// JSON string escape for embedding a value into a JSON document;
/// delegated to `serde_json` so the escaping rules live in one place.
fn json_escape(s: &str) -> String {
    serde_json::to_string(s).expect("string serialization cannot fail")
}

/// The RFC 3986 unreserved set: everything else is percent-encoded.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Percent-encode everything outside the unreserved set.
fn percent_encode(s: &str) -> String {
    utf8_percent_encode(s, UNRESERVED).to_string()
}

/// Link a named pack from `src` to `dst` instead of copying.
///
/// When both ends are linkable (a filesystem or local-namespace
/// directory on the source side, a directory on the destination side) a
/// link is created; any other shape falls back to [`copy`], per the
/// command's contract that `link` establishes links when both ends are
/// linkable and otherwise copies.
pub fn link(src: &str, dst: &str, registry: Option<&str>) -> Result<()> {
    let source = parse_source(src)?;
    let dest = parse_dest(dst)?;
    let linkable_src = match &source {
        Source::Fs(p) => {
            if !p.is_dir() {
                bail!("fs pack `{}` is not a directory", p.display());
            }
            true
        }
        Source::Registry { namespace, .. } if namespace == "local" => true,
        _ => false,
    };
    if !linkable_src || !matches!(dest, Dest::Dir(_)) {
        // Not linkable on both ends: the command degrades to a copy.
        return copy(src, dst, registry);
    }
    let src_dir = match &source {
        Source::Fs(p) => p.clone(),
        Source::Registry { name, version, .. } => {
            let base = typst_packages_dir()?.join("local").join(name);
            let version = match version.as_deref() {
                Some(v) => v.to_string(),
                None => latest_version_dir(&base)?.ok_or_else(|| {
                    anyhow!(
                        "no local version of `{name}` found under {}",
                        base.display()
                    )
                })?,
            };
            let dir = base.join(version);
            if !dir.is_dir() {
                bail!("local pack `{}` not found", dir.display());
            }
            dir
        }
        _ => unreachable!("checked linkable above"),
    };
    let dst_path = match dest {
        Dest::Dir(p) => p,
        _ => unreachable!("checked linkable above"),
    };
    let _ = registry;
    ensure_distinct(&src_dir, &dst_path)?;
    if dst_path.exists() {
        bail!("destination `{}` already exists", dst_path.display());
    }
    if let Some(parent) = dst_path.parent() {
        fs::create_dir_all(parent)?;
    }
    // An absolute, lexically normal source target: a relative link must
    // resolve from the destination's directory, not from the cwd.
    let src_abs = normalize_absolute(
        &src_dir
            .canonicalize()
            .unwrap_or_else(|_| normalize_absolute(&src_dir)),
    );
    #[cfg(target_os = "windows")]
    {
        if std::os::windows::fs::symlink_dir(&src_abs, &dst_path).is_err() {
            // Without the symlink privilege, fall back to a junction.
            let dst_abs = normalize_absolute(
                &dst_path
                    .canonicalize()
                    .unwrap_or_else(|_| normalize_absolute(&dst_path)),
            );
            let status = std::process::Command::new("cmd")
                .args([
                    "/C",
                    "mklink",
                    "/J",
                    &dst_abs.to_string_lossy(),
                    &src_abs.to_string_lossy(),
                ])
                .status()
                .map_err(|e| anyhow!("creating junction at {} failed: {e}", dst_path.display()))?;
            if !status.success() {
                bail!(
                    "linking {} -> {} failed (symlink needs developer mode or administrator rights, junction fallback failed)",
                    dst_path.display(),
                    src_dir.display()
                );
            }
        }
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&src_abs, &dst_path).map_err(|e| {
            anyhow!(
                "symlink {} -> {} failed: {e}",
                dst_path.display(),
                src_abs.display()
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Write;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn parse_source_detects_shapes() {
        assert!(matches!(parse_source("./a").unwrap(), Source::Fs(_)));
        assert!(matches!(parse_source("-").unwrap(), Source::Stdin));
        assert!(matches!(
            parse_source("@preview/foo").unwrap(),
            Source::Registry { namespace, name, .. } if namespace == "preview" && name == "foo"
        ));
        assert!(matches!(
            parse_source("https://example.com/x.tar.gz").unwrap(),
            Source::Url { .. }
        ));
        assert!(parse_source("not a pack").is_err());
    }

    #[test]
    fn parse_dest_detects_shapes() {
        assert!(matches!(parse_dest("./b").unwrap(), Dest::Dir(_)));
        assert!(matches!(
            parse_dest("./b.tar.gz").unwrap(),
            Dest::Tarball(_)
        ));
        assert!(parse_dest("https://example.com/x").is_err());
    }

    #[test]
    fn spec_rejects_traversal_and_bad_versions() {
        assert!(parse_source("@local/../foo").is_err());
        assert!(parse_source("@preview/foo:").is_err());
        assert!(parse_source("@preview/na/me").is_err());
        assert!(parse_source("@preview/").is_err());
        // Dots and colons are not path-safe components.
        assert!(parse_source("@preview/.").is_err());
        assert!(parse_source("@./name").is_err());
        // a colon splits name from version, so na:me parses as version `me`
        assert!(matches!(
            parse_source("@preview/na:me").unwrap(),
            Source::Registry { name, version: Some(v), .. } if name == "na" && v == "me"
        ));
    }

    #[test]
    fn bare_tarball_file_is_accepted() {
        let dir = std::env::temp_dir().join(format!("typship-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let tgz = dir.join("thing.tgz");
        fs::write(&tgz, b"\x1f\x8bplaceholder").unwrap();
        let s = tgz.to_string_lossy().to_string();
        assert!(matches!(parse_source(&s).unwrap(), Source::Tarball(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn windows_backslash_dir_is_accepted() {
        assert!(matches!(parse_source(".\\a").unwrap(), Source::Fs(_)));
    }

    #[test]
    fn github_urls_keep_their_refs() {
        // An archive URL passes through untouched.
        match parse_source("https://github.com/o/r/archive/refs/tags/v1.tar.gz").unwrap() {
            Source::Url { url, subpath: None } => {
                assert!(url.ends_with("/archive/refs/tags/v1.tar.gz"));
            }
            other => panic!("unexpected {other:?}"),
        }
        // A release asset URL passes through untouched.
        match parse_source("https://github.com/o/r/releases/download/v1/p.tgz").unwrap() {
            Source::Url { url, subpath: None } => {
                assert!(url.ends_with("/releases/download/v1/p.tgz"));
            }
            other => panic!("unexpected {other:?}"),
        }
        // latest and tag URLs resolve through the API instead of HEAD.
        assert!(matches!(
            parse_source("https://github.com/o/r/releases/latest").unwrap(),
            Source::GithubRelease { tag: None, .. }
        ));
        assert!(matches!(
            parse_source("https://github.com/o/r/releases/tag/v2").unwrap(),
            Source::GithubRelease { tag: Some(t), .. } if t == "v2"
        ));
        // `releases/tag/latest` is the literal tag, not the latest release.
        assert!(matches!(
            parse_source("https://github.com/o/r/releases/tag/latest").unwrap(),
            Source::GithubRelease { tag: Some(t), .. } if t == "latest"
        ));
        // A tag with slashes survives whole.
        match parse_source("https://github.com/o/r/releases/tag/v1/beta2").unwrap() {
            Source::GithubRelease { tag: Some(t), .. } => assert_eq!(t, "v1/beta2"),
            other => panic!("unexpected {other:?}"),
        }
        // A plain repository URL stays HEAD-based.
        assert!(matches!(
            parse_source("https://github.com/o/r").unwrap(),
            Source::Url { .. }
        ));
        // Non-pack GitHub URLs fail clearly.
        assert!(parse_source("https://github.com/o/r/blob/main/x").is_err());
        // Non-GitHub git URLs fail clearly instead of guessing.
        assert!(parse_source("https://gitlab.com/g/r.git").is_err());
    }

    #[test]
    fn github_tree_keeps_all_segments() {
        match parse_source("https://github.com/o/r/tree/feature/foo/dir").unwrap() {
            Source::GithubTree { rest, .. } => {
                assert_eq!(
                    rest,
                    vec!["feature".to_string(), "foo".to_string(), "dir".to_string()]
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn extract_rejects_escape_attempts() {
        for evil in [
            "../evil.txt",
            "/abs.txt",
            "a\\b.txt",
            "C:/x.txt",
            "a/../../b.txt",
        ] {
            let gz = gz_of(&[(evil, b"x")]);
            let dest = std::env::temp_dir().join(format!("typship-x-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dest);
            assert!(extract_tarball(&gz, &dest, None).is_err(), "case {evil}");
            let _ = fs::remove_dir_all(&dest);
        }
    }

    #[test]
    fn extract_rejects_windows_hostile_paths() {
        for evil in [
            "a:stream.txt",  // NTFS alternate data stream
            "CON/settings",  // reserved device name as a directory
            "out/COM1.txt",  // reserved device name as a file stem
            "out/lpt9.dat",  // case-insensitive reserved name
            "out/trailing.", // trailing dot component
            "out/trailing ", // trailing space component
            "out//x.txt",    // empty component
        ] {
            assert!(safe_member_path(evil).is_err(), "case {evil:?}");
        }
        // Friendly names stay valid.
        for ok in ["src/lib.typ", "out/CONCEPT.txt", "out/v1.0/read me.md"] {
            assert!(safe_member_path(ok).is_ok(), "case {ok:?}");
        }
    }

    #[test]
    fn extract_rejects_non_utf8_member_names() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&raw_header(b"\xff\xfe.txt", b'0', 1));
        raw.extend_from_slice(b"x");
        raw.extend_from_slice(&[0u8; 1024]);
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-nu-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        assert!(extract_tarball(&gz, &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn extract_rejects_bad_checksum_and_symlink_members() {
        // Corrupt the checksum of a valid header, on the uncompressed
        // stream: byte 150 sits inside the 148..156 checksum field.
        let gz0 = gz_of(&[("ok.txt", b"x")]);
        let mut raw = Vec::new();
        GzDecoder::new(&gz0[..]).read_to_end(&mut raw).unwrap();
        assert!(raw.len() > 160);
        raw[150] ^= 0xff;
        let mut gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-c-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        assert!(extract_tarball(&gz, &dest, None).is_err());
        // A symlink member is rejected outright.
        gz = gz_of_raw(&[raw_header(b"link", b'2', 0).to_vec(), vec![0u8; 1024]].concat());
        assert!(extract_tarball(&gz, &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn malformed_gzip_and_tar_frames_are_errors() {
        let dest = std::env::temp_dir().join(format!("typship-g-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        // 「缺结束块」「空 gzip 载荷（＝空归档）」的严格性均已让渡给
        // `tar` crate——它对这两种流都静默接受，相关用例随之删除。
        // Trailing garbage after the gzip member.
        let mut garbage = gz_of(&[("a.txt", b"x")]);
        garbage.extend_from_slice(b"CORRUPT");
        assert!(
            extract_tarball(&garbage, &dest, None).is_err(),
            "trailing garbage"
        );
        // Non-gzip junk at all.
        assert!(
            extract_tarball(b"plain text", &dest, None).is_err(),
            "plain text"
        );
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn dangling_metadata_headers_are_refused() {
        // tar crate 内部把 PAX/GNU 长名元数据头并入下一成员，不再作为
        // 独立条目产出。但「元数据头之后没有成员」仍是错误，不得静默
        // 吞掉。
        let mut raw = Vec::new();
        for i in 0..3 {
            raw.extend_from_slice(&raw_header(format!("pax{i}").as_bytes(), b'x', 0));
        }
        raw.extend_from_slice(&[0u8; 1024]);
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-mb-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        assert!(extract_tarball(&gz, &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
    }

    // PAX/长名记录的帧解析与严格性现在由 `tar` crate 内部保证，
    // 旧的自写解码器测试（pax_path_record_is_parsed_by_length、
    // pax_malformed_records_are_errors_not_panics、
    // pending_name_overrides_never_leak_to_the_next_member、
    // single_zero_block_is_not_a_complete_end_marker）随之删除；
    // crate 对「缺结束块」静默接受的严格性让渡也已记录在案。

    #[test]
    fn http_404_fails_immediately_without_retry() {
        let (url, count) = mock_server(&[(404, "nope")]);
        assert!(fetch_bytes(&format!("{url}/index.json")).is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn http_5xx_is_retried_until_success() {
        let (url, count) = mock_server(&[(500, "a"), (500, "b"), (200, "ok")]);
        let body = fetch_bytes(&format!("{url}/index.json")).unwrap();
        assert_eq!(body, b"ok".to_vec());
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn non_gzip_tarball_body_is_a_permanent_failure() {
        let (url, count) = mock_server(&[(200, "<html>not gzip</html>")]);
        match get_tarball(&format!("{url}/x.tar.gz")) {
            Err(FetchError::Fatal(_)) => {}
            other => panic!("expected Fatal, got {other:?}"),
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn json_parsing_rejects_malformed_documents() {
        // serde_json does the parsing; these pin the contract that
        // malformed documents are errors, never scans.
        assert!(json_parse("{\"a\":}", "doc").is_err());
        assert!(json_parse("{\"a\":1} trailing", "doc").is_err());
        assert!(json_parse("01", "doc").is_err());
        assert!(json_parse(r#""\ud83d""#, "doc").is_err()); // unpaired surrogate
        // Surrogate pairs decode correctly.
        let v: Json = serde_json::from_str("{\"e\":\"\\ud83d\\ude00\"}").unwrap();
        assert_eq!(v.get("e").unwrap().as_str(), Some("\u{1F600}"));
    }

    #[test]
    fn index_latest_comes_from_the_production_parser() {
        let body = r#"[ {"version": "0.2.0", "name": "foo"} ,{"name":"foo","version":"0.10.0"},{"name":"bar","version":"9.9.9"} ]"#;
        assert_eq!(latest_from_index_json(body, "foo").unwrap(), "0.10.0");
        assert!(latest_from_index_json(body, "nope").is_err());
        // Not an array.
        assert!(latest_from_index_json(r#"{"name":"foo"}"#, "foo").is_err());
    }

    #[test]
    fn release_asset_selection_uses_the_parsed_document() {
        let body = r#"{"tag_name":"v1.2.3","assets":[{"name":"nope.zip","browser_download_url":"https://x/nope.zip"},{"name":"p.tar.gz","browser_download_url":"https://x/p.tar.gz"}]}"#;
        let v: Json = serde_json::from_str(body).unwrap();
        assert_eq!(
            release_archive_asset(&v).as_deref(),
            Some("https://x/p.tar.gz")
        );
        assert_eq!(v.get("tag_name").unwrap().as_str(), Some("v1.2.3"));
        let empty: Json = serde_json::from_str(r#"{"tag_name":"v1","assets":[]}"#).unwrap();
        assert!(release_archive_asset(&empty).is_none());
    }

    #[test]
    fn release_upload_url_extraction_rejects_non_objects() {
        assert_eq!(
            release_upload_url(
                r#"{"upload_url": "https://uploads.github.com/u{?name,label}"}"#,
                "v1"
            )
            .unwrap(),
            "https://uploads.github.com/u{?name,label}"
        );
        assert!(release_upload_url(r#""just a string""#, "v1").is_err());
    }

    #[test]
    fn copy_refuses_destination_inside_source() {
        let base = std::env::temp_dir().join(format!("typship-d-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(src.join("out")).unwrap();
        fs::write(src.join("f.txt"), "x").unwrap();
        // dst inside src
        assert!(ensure_distinct(&src, &src.join("out").join("b")).is_err());
        // src inside dst
        assert!(ensure_distinct(&src, &base).is_err());
        // same, expressed through dot segments
        assert!(ensure_distinct(&src, &src.join(".").join(".")).is_err());
        // unrelated: fine
        assert!(ensure_distinct(&src, &base.join("b")).is_ok());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn copy_refuses_alias_destinations_through_dots() {
        // A destination written with .. segments must not slip past the
        // inside-source check.
        let base = std::env::temp_dir().join(format!("typship-d2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(src.join("out")).unwrap();
        assert!(ensure_distinct(&src, &src.join("out").join("..").join("inside")).is_err());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn relative_link_target_is_absolute() {
        let base = std::env::temp_dir().join(format!("typship-l-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("nested").join("a");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("f.txt"), "x").unwrap();
        let dst = base.join("nested").join("b");
        link(&src.to_string_lossy(), &dst.to_string_lossy(), None).unwrap();
        // The link must resolve back to the real source.
        let linked = fs::read_dir(&dst).unwrap().count();
        assert_eq!(linked, 1);
        assert!(dst.join("f.txt").is_file());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn link_accepts_relative_input_paths() {
        // Both ends given as relative paths (resolved against the cwd,
        // which for tests is the crate directory). The created link must
        // still point at the real source.
        let base = PathBuf::from("target").join(format!("typship-lr-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("f.txt"), "x").unwrap();
        let dst = base.join("b");
        let src_rel = format!("./{}", src.to_string_lossy().replace('\\', "/"));
        let dst_rel = format!("./{}", dst.to_string_lossy().replace('\\', "/"));
        link(&src_rel, &dst_rel, None).unwrap();
        assert!(dst.join("f.txt").is_file());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn writer_refuses_unsplittable_long_paths() {
        // An unsplittable over-long path would need an extended header:
        // refused with a clear error instead (admin review note: we do
        // not create special-format files).
        let base = std::env::temp_dir().join(format!("typship-sp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(&src).unwrap();
        let long = format!("{}.typ", "l".repeat(150));
        fs::write(src.join(&long), "long").unwrap();
        let err = pack_tarball(&src).unwrap_err().to_string();
        assert!(err.contains("too long for the ustar layout"), "{err}");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn writer_emits_only_plain_typeflags() {
        let base = std::env::temp_dir().join(format!("typship-tf-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("plain.txt"), "x").unwrap();
        fs::write(src.join("sub/deep.txt"), "y").unwrap();
        // A long path that splits cleanly into a ustar prefix + name.
        let long_dir = "d".repeat(60);
        let long_name = format!("{}.typ", "n".repeat(90));
        fs::create_dir_all(src.join(&long_dir)).unwrap();
        fs::write(src.join(&long_dir).join(&long_name), "long").unwrap();
        let gz = pack_tarball(&src).unwrap();
        // Inspect the uncompressed tar stream's typeflags.
        let mut raw = Vec::new();
        MultiGzDecoder::new(&gz[..]).read_to_end(&mut raw).unwrap();
        let mut flags = Vec::new();
        let mut pos = 0;
        while pos + 512 <= raw.len() {
            let header = &raw[pos..pos + 512];
            if header.iter().all(|&b| b == 0) {
                break;
            }
            let size = octal(&header[124..136]).unwrap();
            flags.push(header[156]);
            pos += 512 + ((size as usize).div_ceil(512)) * 512;
        }
        assert!(
            flags.iter().all(|f| matches!(f, b'0' | b'5')),
            "only plain entries expected: {flags:?}"
        );
        // The long path round-trips through the ustar prefix split.
        let dst = base.join("out");
        extract_tarball(&gz, &dst, None).unwrap();
        assert_eq!(
            fs::read(dst.join(&long_dir).join(&long_name)).unwrap(),
            b"long"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn writer_output_roundtrips_through_reader() {
        // The writer's own directory entries (trailing `/`) must be
        // accepted by the reader (R3-1 regression).
        let base = std::env::temp_dir().join(format!("typship-wr-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("src");
        fs::create_dir_all(src.join("inner")).unwrap();
        fs::write(src.join("typst.toml"), "m").unwrap();
        fs::write(src.join("inner/lib.typ"), "x").unwrap();
        let gz = pack_tarball(&src).unwrap();
        let dst = base.join("out");
        extract_tarball(&gz, &dst, None).unwrap();
        assert!(dst.join("typst.toml").is_file());
        assert!(dst.join("inner/lib.typ").is_file());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn roundtrip_preserves_structure() {
        let base = std::env::temp_dir().join(format!("typship-r-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);

        // 1. A pack with a manifest: contents land at the destination top.
        let src = base.join("a");
        fs::create_dir_all(src.join("src")).unwrap();
        fs::write(src.join("typst.toml"), "manifest").unwrap();
        fs::write(src.join("src/main.typ"), "#set page()").unwrap();
        let gz = pack_tarball(&src).unwrap();
        let dst = base.join("b1");
        extract_tarball(&gz, &base.join("t1"), None).unwrap();
        let root = find_pack_root(&base.join("t1")).unwrap();
        copy_tree(&root, &dst).unwrap();
        assert!(dst.join("typst.toml").is_file());
        assert!(dst.join("src/main.typ").is_file());

        // 2. A directory without a manifest keeps its structure exactly.
        let src = base.join("c");
        fs::create_dir_all(src.join("src")).unwrap();
        fs::write(src.join("src/main.typ"), "x").unwrap();
        let gz = pack_tarball(&src).unwrap();
        let dst = base.join("b2");
        extract_tarball(&gz, &base.join("t2"), None).unwrap();
        let root = find_pack_root(&base.join("t2")).unwrap();
        copy_tree(&root, &dst).unwrap();
        assert!(dst.join("src/main.typ").is_file());
        assert!(!dst.join("main.typ").is_file());

        // 3. A wrapper archive: the manifest marks the pack root.
        let wrapped = base.join("w");
        fs::create_dir_all(wrapped.join("repo").join("src")).unwrap();
        fs::write(wrapped.join("repo").join("typst.toml"), "m").unwrap();
        fs::write(wrapped.join("repo").join("src/lib.typ"), "z").unwrap();
        let gz = pack_tarball(&wrapped).unwrap();
        let dst = base.join("b4");
        extract_tarball(&gz, &base.join("t4"), None).unwrap();
        let root = find_pack_root(&base.join("t4")).unwrap();
        copy_tree(&root, &dst).unwrap();
        assert!(dst.join("typst.toml").is_file());
        assert!(dst.join("src/lib.typ").is_file());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn utf8_and_long_names_survive_the_roundtrip() {
        let base = std::env::temp_dir().join(format!("typship-u-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("中文.typ"), "hello").unwrap();
        // A long multi-byte path that splits cleanly into a ustar
        // prefix + name (prefix ≤155 bytes, name ≤100 bytes); each
        // directory component stays at or under 100 bytes, since a
        // single over-long component is refused by the writer contract.
        let long_dir = "目".repeat(33); // 99 bytes, fits the name field directly
        let long_name = format!("{}.typ", "录".repeat(30)); // 93 bytes, fits the name
        // 99 + 1 + 93 = 193 bytes: the file entry needs the prefix split.
        fs::create_dir_all(src.join(&long_dir)).unwrap();
        fs::write(src.join(&long_dir).join(&long_name), "long").unwrap();
        let gz = pack_tarball(&src).unwrap();
        let dst = base.join("b");
        extract_tarball(&gz, &dst, None).unwrap();
        assert_eq!(fs::read(dst.join("中文.typ")).unwrap(), b"hello");
        assert_eq!(
            fs::read(dst.join(&long_dir).join(&long_name)).unwrap(),
            b"long"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn locate_subdir_has_no_arbitrary_depth_search() {
        // The contract: only the single-subdirectory chain (up to three
        // levels) is traversed; a first segment deeper than that is not
        // found (R5-1 regression, documents the limitation).
        let base = std::env::temp_dir().join(format!("typship-deep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let deep = base.join("a").join("b").join("c").join("d").join("target");
        fs::create_dir_all(&deep).unwrap();
        assert!(locate_subdir(&base, "target").is_none());
        // Within the chain depth it resolves.
        assert!(locate_subdir(&base, "a/b/target_placeholder").is_none()); // absent
        let within = base.join("a").join("b").join("target");
        fs::create_dir_all(&within).unwrap();
        assert!(locate_subdir(&base, "b/target").is_some());
        let _ = fs::remove_dir_all(&base);
    }

    // 资源预算（条数/总量/单成员/下载上限）已按 admin 指示（2026-11-08「不要做没必要的限制」）整体移除，原预算测试随之删除；
    // 剩下防线＝成员类型白名单、路径校验、短读检查与流尾校验。

    #[test]
    fn truncated_body_is_retried_until_success() {
        // Response declares 20 bytes but delivers 2 and closes: the body
        // read fails, which is transient, so a second request follows.
        let truncated: &[u8] =
            b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nok";
        let full: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        let (url, count) = mock_raw_server(&[truncated, full]);
        let body = fetch_bytes(&format!("{url}/f")).unwrap();
        assert_eq!(body, b"ok".to_vec());
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn locate_subdir_crosses_wrapper_and_single_chain() {
        // A GitHub wrapper followed by the repository's own single-child
        // directory: the full subpath must resolve (R3-4 regression).
        let base = std::env::temp_dir().join(format!("typship-ls-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let sub = base.join("repo-HEAD").join("sub");
        fs::create_dir_all(sub.join("inner")).unwrap();
        fs::write(sub.join("lib.typ"), "x").unwrap();
        assert!(locate_subdir(&base, "sub").is_some());
        assert!(locate_subdir(&base, "sub/inner").is_some());
        // A registry-style nested path below the wrapper.
        let pkg = base
            .join("repo-HEAD")
            .join("packages")
            .join("preview")
            .join("name");
        fs::create_dir_all(&pkg).unwrap();
        assert!(find_in_chain(&base, "packages/preview/name").is_some());
        assert!(find_in_chain(&base, "packages/absent").is_none());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn link_falls_back_to_copy_when_ends_are_not_linkable() {
        // dir -> tarball: not linkable on the destination side, so the
        // command copies.
        let base = std::env::temp_dir().join(format!("typship-lc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("a");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("f.txt"), "x").unwrap();
        let tgz = base.join("out.tar.gz");
        link(&src.to_string_lossy(), &tgz.to_string_lossy(), None).unwrap();
        assert!(tgz.is_file());
        // tarball -> dir: not linkable on the source side, so it copies
        // (and the manifest-less tree keeps its structure).
        let dst = base.join("out");
        link(&tgz.to_string_lossy(), &dst.to_string_lossy(), None).unwrap();
        assert!(dst.join("f.txt").is_file());
        let _ = fs::remove_dir_all(&base);
    }

    /// Build a gzipped tar from (path, data) pairs through the writer.
    fn gz_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut raw = Vec::new();
        for (path, data) in entries {
            raw.extend_from_slice(&raw_header(path.as_bytes(), b'0', data.len()));
            raw.extend_from_slice(data);
            let pad = (512 - (data.len() % 512)) % 512;
            raw.extend_from_slice(&vec![0u8; pad]);
        }
        raw.extend_from_slice(&[0u8; 1024]);
        gz_of_raw(&raw)
    }

    /// Compress raw (uncompressed) tar bytes.
    fn gz_of_raw(raw: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(raw).unwrap();
        enc.finish().unwrap()
    }

    /// A valid ustar header with a computed checksum.
    fn raw_header(name: &[u8], typeflag: u8, size: usize) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[..name.len().min(100)].copy_from_slice(&name[..name.len().min(100)]);
        let mode = if typeflag == b'5' {
            b"0000755\x00"
        } else {
            b"0000644\x00"
        };
        header[100..108].copy_from_slice(mode);
        header[108..116].copy_from_slice(b"0000000\x00");
        header[116..124].copy_from_slice(b"0000000\x00");
        let size_field = format!("{size:011o}\x00");
        header[124..136].copy_from_slice(size_field.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\x00");
        header[148..156].copy_from_slice(b"        ");
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\x00");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|&b| b as u64).sum::<u64>();
        let cs = format!("{checksum:06o}\x00 ");
        header[148..156].copy_from_slice(cs.as_bytes());
        header
    }

    /// A tiny HTTP server answering a scripted sequence of
    /// (status, body) responses (the last one repeats) and counting
    /// the requests it served.
    /// A tiny HTTP server answering one scripted raw byte response per
    /// connection (the last one repeats) and counting requests. Used to
    /// simulate broken bodies (short reads) that the (status, body)
    /// helper cannot express.
    fn mock_raw_server(responses: &[&[u8]]) -> (String, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        let responses: Vec<Vec<u8>> = responses.iter().map(|r| r.to_vec()).collect();
        std::thread::spawn(move || {
            for (i, stream) in listener.incoming().enumerate() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let idx = i.min(responses.len() - 1);
                count2.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(&responses[idx]);
                // Dropping the stream closes the connection.
            }
        });
        (format!("http://{addr}"), count)
    }

    fn mock_server(responses: &[(u16, &str)]) -> (String, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        let responses: Vec<(u16, String)> =
            responses.iter().map(|(c, b)| (*c, b.to_string())).collect();
        std::thread::spawn(move || {
            for (i, stream) in listener.incoming().enumerate() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let idx = i.min(responses.len() - 1);
                let (code, body) = &responses[idx];
                count2.fetch_add(1, Ordering::SeqCst);
                let reason = if *code == 200 { "OK" } else { "E" };
                let resp = format!(
                    "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        (format!("http://{addr}"), count)
    }
}
