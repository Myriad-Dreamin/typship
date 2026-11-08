//! The named Pack abstraction: parsing, detection and transport of pack
//! sources and destinations.
//!
//! Standard formats are handled by standard crates: JSON with
//! `serde_json`, the tar container with `tar`, gzip with `flate2`,
//! percent-encoding with `percent-encoding`, and TOML manifest writing
//! (in [`crate::manifest`]) with `toml`. No hand-written parsers or
//! encoders for standard formats remain (admin direction 2026-11-08).
//! Directory traversal uses `walkdir`, URL parsing uses `url`, and
//! verbatim-free canonicalization uses `dunce`.
//!
//! Safety posture for untrusted archives, aligned with typst's own
//! unpacking rules: member paths are validated (no absolute paths, no
//! `..` components), member names must be UTF-8, and member types are
//! restricted to plain files and directories -- link and device members
//! are rejected outright. No backslash/colon/device-name/trailing-dot
//! rules: on unix those are ordinary characters, and the `tar` crate
//! unpacks them the same way typst does. PAX record-level validation
//! was removed with the same alignment (the crate silently drops
//! malformed records). The header checksum is verified, and a short
//! member body is an error rather than a truncated file. Resource
//! budgets were removed per admin direction 2026-11-08 ("不要做没必
//! 要的限制"): an archive is as large as it is.
//!
//! HTTP posture: only transient failures (transport errors, 429 and 5xx)
//! are retried; other 4xx answers are a definitive miss, and a non-gzip
//! tarball body is a permanent failure that never triggers another
//! request. Response bodies are read in full — no download cap (admin
//! direction 2026-11-08, "不要做没必要的限制").

use std::borrow::Cow;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use walkdir::WalkDir;

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
    /// A GitHub repository root or `.git` URL: the default branch,
    /// cloned with git.
    GithubRepo {
        /// Repository owner.
        owner: String,
        /// Repository name (without a `.git` suffix).
        repo: String,
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
    [".", ".."]
        .iter()
        .any(|p| s.starts_with(&format!("{p}/")) || s.starts_with(&format!("{p}\\")))
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
    // git pack: `.../repo.git` -- no ref is expressible, so the default
    // branch is cloned. Generic git hosts use different layouts; failing
    // clearly beats downloading the wrong thing.
    if s.ends_with(".git") {
        let url = url::Url::parse(s).map_err(|e| anyhow!("invalid URL `{s}`: {e}"))?;
        if url.host_str().map(|h| h.eq_ignore_ascii_case("github.com")) != Some(true) {
            bail!(
                "git pack support is limited to github.com URLs; for other hosts pass a direct archive URL"
            );
        }
        let segs: Vec<&str> = url
            .path_segments()
            .map(|segs| segs.filter(|p| !p.is_empty()).collect())
            .unwrap_or_default();
        if segs.len() != 2 {
            bail!("invalid GitHub URL `{s}`");
        }
        return Ok(Source::GithubRepo {
            owner: segs[0].to_string(),
            repo: segs[1].trim_end_matches(".git").to_string(),
        });
    }
    let url = url::Url::parse(s).map_err(|e| anyhow!("invalid URL `{s}`: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("`{s}` is neither a valid pack (fs path, `-`, `@ns/name`) nor an http(s) URL");
    }
    let segs: Vec<&str> = url
        .path_segments()
        .map(|segs| segs.filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();
    if url.host_str().map(|h| h.eq_ignore_ascii_case("github.com")) != Some(true) {
        // Any other http(s) URL: a tarball.
        return Ok(Source::Url {
            url: s.to_string(),
            subpath: None,
        });
    }
    if segs.len() < 2 {
        bail!("invalid GitHub URL `{s}`");
    }
    let (owner, repo) = (segs[0], segs[1]);
    // `.../archive/...` is already an archive URL: pass it through
    // untouched so the requested ref is preserved.
    if segs.len() >= 4 && segs[2] == "archive" {
        return Ok(Source::Url {
            url: s.to_string(),
            subpath: None,
        });
    }
    // GitHub release pack: releases/latest | releases/tag/{t} |
    // releases/{t} | releases/download/{t}/{asset}.
    if segs.len() >= 4 && segs[2] == "releases" {
        match segs.get(3).copied() {
            Some("download") => {
                // An asset download URL: use it exactly as given.
                if segs.len() < 5 {
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
                let tag = segs.get(4..).filter(|t| !t.is_empty()).map(|t| t.join("/"));
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
                    tag: Some(segs[3..].join("/")),
                });
            }
            None => bail!("invalid GitHub release URL `{s}`"),
        }
    }
    // GitHub directory pack: tree/{ref-with-possible-slashes[/subpath]}.
    if segs.len() >= 4 && segs[2] == "tree" {
        return Ok(Source::GithubTree {
            owner: owner.to_string(),
            repo: repo.to_string(),
            rest: segs[3..].iter().map(|s| s.to_string()).collect(),
        });
    }
    if segs.len() == 2 {
        // A plain repository URL: the default branch, cloned with git.
        return Ok(Source::GithubRepo {
            owner: owner.to_string(),
            repo: repo.to_string(),
        });
    }
    bail!(
        "`{s}` is not a pack source (expected a repository root, tree, archive, release or .git URL)"
    )
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
/// lexically cleaned, via the path-clean crate.
fn absolute_lexical(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|c| c.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    };
    path_clean::clean(&abs)
}

/// The physical path of `p` as far as the filesystem can tell: the
/// longest existing ancestor is canonicalized (resolving symlinks,
/// junctions and case differences; the `dunce` crate keeps Windows
/// paths non-verbatim) and the remaining suffix joined back on.
/// Non-existing tails keep their lexically cleaned form.
fn physical(p: &Path) -> PathBuf {
    let abs = absolute_lexical(p);
    let mut ancestor = abs.as_path();
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match dunce::canonicalize(ancestor) {
            Ok(real) => {
                let mut out: PathBuf = real;
                for part in suffix.iter().rev() {
                    out.push(part);
                }
                return out;
            }
            Err(_) => match (ancestor.parent(), ancestor.file_name()) {
                (Some(parent), Some(last)) => {
                    suffix.push(last.to_os_string());
                    ancestor = parent;
                }
                _ => return abs,
            },
        }
    }
}

/// The comparison key of one path component; on Windows the comparison
/// is case-insensitive because NTFS names are case-preserving but
/// case-insensitive. Borrowing, not allocating (except the Windows
/// lowercase fold).
fn comp_key(c: Component<'_>) -> Cow<'_, str> {
    let s = c.as_os_str().to_string_lossy();
    #[cfg(target_os = "windows")]
    {
        s.to_ascii_lowercase().into()
    }
    #[cfg(not(target_os = "windows"))]
    {
        s
    }
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.components()
        .map(comp_key)
        .eq(b.components().map(comp_key))
}

/// Whether `child` equals `parent` or sits below it, component-wise.
fn is_prefix(child: &Path, parent: &Path) -> bool {
    let mut c = child.components().map(comp_key);
    let mut p = parent.components().map(comp_key);
    loop {
        match (p.next(), c.next()) {
            (None, _) => return true,
            (Some(pv), Some(cv)) => {
                if pv != cv {
                    return false;
                }
            }
            (Some(_), None) => return false,
        }
    }
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

/// The per-user Typst packages directory, matching the official typst
/// package loader's `system_data`: `dirs::data_dir()` everywhere, i.e.
/// `%APPDATA%/typst/packages` on Windows (NOT the LOCALAPPDATA cache
/// directory), `$XDG_DATA_HOME` or `~/.local/share` on Linux and
/// `~/Library/Application Support` on macOS.
fn typst_packages_dir() -> Result<PathBuf> {
    let base =
        dirs::data_dir().ok_or_else(|| anyhow!("cannot determine the per-user data directory"))?;
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
    /// A directory on disk: an existing local pack, or a git clone in a
    /// temporary directory that removes itself when the transport is
    /// done.
    Dir {
        path: PathBuf,
        #[allow(dead_code)]
        guard: Option<TempDir>,
    },
    /// A gzipped tarball held in memory, with an optional in-archive
    /// subpath to locate when unpacking at the destination.
    Tarball {
        bytes: Vec<u8>,
        subpath: Option<String>,
    },
}

/// The chain of candidate roots inside an extracted archive: the
/// extraction directory itself plus each directory along a chain of
/// single subdirectories (up to three levels, the GitHub `repo-ref/`
/// wrapper and the repository's own single-child prefixes).
fn archive_chain(tmp: &Path) -> Vec<PathBuf> {
    let mut chain = vec![tmp.to_path_buf()];
    for _ in 0..3 {
        let Ok(entries) = fs::read_dir(chain.last().expect("chain is never empty")) else {
            break;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        if entries.len() == 1 && entries[0].file_type().map(|t| t.is_dir()).unwrap_or(false) {
            chain.push(entries.remove(0).path());
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
            Ok(Materialized::Dir {
                path: p.clone(),
                guard: None,
            })
        }
        Source::Tarball(bytes) => Ok(Materialized::Tarball {
            bytes: bytes.clone(),
            subpath: None,
        }),
        Source::Stdin => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading tarball from stdin")?;
            Ok(Materialized::Tarball {
                bytes: buf,
                subpath: None,
            })
        }
        Source::Registry {
            namespace,
            name,
            version,
        } => materialize_registry(namespace, name, version.as_deref(), registry),
        Source::Url { url, subpath } => Ok(Materialized::Tarball {
            bytes: get_tarball(url)?,
            subpath: subpath.clone(),
        }),
        Source::GithubRepo { owner, repo } => materialize_github_repo(owner, repo),
        Source::GithubTree { owner, repo, rest } => materialize_github_tree(owner, repo, rest),
        Source::GithubRelease { repo, tag } => materialize_github_release(repo, tag.as_deref()),
    }
}

/// Resolve a GitHub tree URL by cloning the repository with git: the
/// ref may contain slashes, so try interpretations from the longest ref
/// to the shortest one. A clone failure moves on to the next candidate
/// ref (the tree may simply not exist under it).
fn materialize_github_tree(owner: &str, repo: &str, rest: &[String]) -> Result<Materialized> {
    if rest.is_empty() {
        bail!("invalid GitHub tree URL: no ref after `tree/`");
    }
    let mut last_err = None;
    for k in (1..=rest.len()).rev() {
        let ref_name = rest[..k].join("/");
        let subpath = (rest.len() > k).then(|| rest[k..].join("/"));
        let tmp = TempDir::system("clone")?;
        match git_clone_shallow(
            &format!("https://github.com/{owner}/{repo}"),
            Some(&ref_name),
            tmp.path(),
        ) {
            Ok(()) => {
                let dir = match subpath {
                    Some(sub) => locate_subdir(tmp.path(), &sub).ok_or_else(|| {
                        anyhow!("subpath `{sub}` not found in `{owner}/{repo}` at `{ref_name}`")
                    })?,
                    None => find_pack_root(tmp.path())?,
                };
                return Ok(Materialized::Dir {
                    path: dir,
                    guard: Some(tmp),
                });
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("could not resolve GitHub tree URL")))
}

/// Clone the default branch of a GitHub repository root (or `.git`
/// URL) into a self-cleaning temporary directory.
fn materialize_github_repo(owner: &str, repo: &str) -> Result<Materialized> {
    let tmp = TempDir::system("clone")?;
    git_clone_shallow(
        &format!("https://github.com/{owner}/{repo}"),
        None,
        tmp.path(),
    )?;
    // Git metadata is not pack content; leaving it in would ship it in
    // the tarball and confuse pack-root detection.
    let git_dir = tmp.path().join(".git");
    if git_dir.is_dir() {
        fs::remove_dir_all(&git_dir)?;
    }
    let dir = find_pack_root(tmp.path())?;
    Ok(Materialized::Dir {
        path: dir,
        guard: Some(tmp),
    })
}

/// Run `git` with the network red-line applied: the child process is
/// killed once the 120 s total budget is used up, so the command never
/// hangs.
fn run_git(args: &[String]) -> Result<()> {
    let mut child = std::process::Command::new("git")
        .args(args)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    let mut stderr_pipe = child.stderr.take().expect("stderr was piped");
    // Drain stderr on its own thread: git writes progress to stderr and
    // a filled pipe buffer would otherwise deadlock the wait.
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match child.try_wait()? {
            Some(status) => {
                let stderr = stderr_thread.join().unwrap_or_default();
                if !status.success() {
                    bail!(
                        "git {} failed: {}",
                        args.join(" "),
                        String::from_utf8_lossy(&stderr).trim()
                    );
                }
                return Ok(());
            }
            None if Instant::now() >= deadline => {
                // Kill the whole process tree: git spawns transport
                // children that a plain kill on the parent misses.
                #[cfg(windows)]
                {
                    let _ = std::process::Command::new("taskkill")
                        .args(["/F", "/T", "/PID", &child.id().to_string()])
                        .status();
                }
                #[cfg(not(windows))]
                {
                    let _ = child.kill();
                }
                let _ = child.wait();
                bail!("git {} timed out", args.join(" "));
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// `git clone --depth 1 [--branch <ref>] url dest`. `--branch` covers
/// branches and tags; for commit SHAs it falls back to a default-branch
/// clone plus an explicit detached checkout.
fn git_clone_shallow(url: &str, git_ref: Option<&str>, dest: &Path) -> Result<()> {
    let mut args = vec!["clone".to_string(), "--depth".to_string(), "1".to_string()];
    if let Some(r) = git_ref {
        args.push("--branch".to_string());
        args.push(r.to_string());
    }
    args.push(url.to_string());
    args.push(dest.to_string_lossy().to_string());
    if git_ref.is_none() {
        run_git(&args)?;
        return Ok(());
    }
    if run_git(&args).is_ok() {
        return Ok(());
    }
    // A failed clone may have left a partial directory behind; a fresh
    // clone needs it gone.
    let _ = fs::remove_dir_all(dest);
    // Retry without `--branch`, then make the requested ref reachable.
    let retry = vec![
        "clone".to_string(),
        "--depth".to_string(),
        "1".to_string(),
        url.to_string(),
        dest.to_string_lossy().to_string(),
    ];
    run_git(&retry)?;
    let checkout = vec![
        "-C".to_string(),
        dest.to_string_lossy().to_string(),
        "checkout".to_string(),
        git_ref.unwrap().to_string(),
    ];
    if run_git(&checkout).is_ok() {
        return Ok(());
    }
    // A commit SHA is not part of a default-branch shallow clone;
    // fetch it explicitly (GitHub serves arbitrary SHAs).
    let fetch = vec![
        "-C".to_string(),
        dest.to_string_lossy().to_string(),
        "fetch".to_string(),
        "--depth".to_string(),
        "1".to_string(),
        "origin".to_string(),
        git_ref.unwrap().to_string(),
    ];
    run_git(&fetch)?;
    let detach = vec![
        "-C".to_string(),
        dest.to_string_lossy().to_string(),
        "checkout".to_string(),
        "FETCH_HEAD".to_string(),
    ];
    run_git(&detach)
}

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
    let value = serde_json::from_str(&text)
        .map_err(|e| anyhow!("invalid JSON in release response from {api}: {e}"))?;
    if let Some(url) = release_archive_asset(&value) {
        return Ok(Materialized::Tarball {
            bytes: get_tarball(&url)?,
            subpath: None,
        });
    }
    // No packaged archive: fail, per admin direction -- no source
    // archive fallback.
    bail!("release for `{repo}` has no packaged `.tar.gz`/`.tgz` asset to download")
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
        return Ok(Materialized::Dir {
            path: dir,
            guard: None,
        });
    }
    match registry {
        None if namespace == "preview" => {
            let version = match version {
                Some(v) => v.to_string(),
                None => latest_official_version(name)?,
            };
            Ok(Materialized::Tarball {
                bytes: get_tarball(&format!("{OFFICIAL_REGISTRY}/{name}-{version}.tar.gz"))?,
                subpath: None,
            })
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
                let tmp = TempDir::system("clone")?;
                git_clone_shallow(
                    &format!("https://github.com/{owner}/{repo}"),
                    None,
                    tmp.path(),
                )?;
                let pkg_base = find_in_chain(tmp.path(), &format!("packages/{namespace}/{name}"))
                    .or_else(|| find_in_chain(tmp.path(), &format!("packages/{name}")))
                    .ok_or_else(|| {
                        anyhow!("package `{namespace}/{name}` not found in registry `{url}`")
                    })?;
                let version = match version {
                    Some(v) => v.to_string(),
                    None => latest_version_dir(&pkg_base)?
                        .ok_or_else(|| anyhow!("no version of `{name}` in registry `{url}`"))?,
                };
                return Ok(Materialized::Dir {
                    path: pkg_base.join(version),
                    guard: Some(tmp),
                });
            }
            let version = match version {
                Some(v) => v.to_string(),
                None => latest_index_version(url, name)?,
            };
            Ok(Materialized::Tarball {
                bytes: get_tarball(&format!(
                    "{}/{name}-{version}.tar.gz",
                    url.trim_end_matches('/')
                ))?,
                subpath: None,
            })
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
    let value: Json =
        serde_json::from_str(text).map_err(|e| anyhow!("invalid JSON in registry index: {e}"))?;
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
    fn walk(dir: &Path, rel: &str) -> Option<PathBuf> {
        let (first, rest) = match rel.split_once('/') {
            Some((f, r)) => (f, Some(r)),
            None => (rel, None),
        };
        for entry in fs::read_dir(dir).ok()?.flatten() {
            if entry.file_type().ok()?.is_dir() && entry.file_name().to_string_lossy() == first {
                match rest {
                    None => return Some(entry.path()),
                    Some(rest) => {
                        if let Some(found) = walk(&entry.path(), rest) {
                            return Some(found);
                        }
                    }
                }
            }
        }
        None
    }
    walk(root, rel)
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

    /// A temp dir under the system temporary directory.
    fn system(label: &str) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!(".typship-tmp-{label}-{}", temp_suffix()));
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

// ---------------------------------------------------------------------------
// JSON — read with serde_json (admin direction: standard crates over
// hand-rolled parsers).
// ---------------------------------------------------------------------------
use serde_json::Value as Json;

// ---------------------------------------------------------------------------
// tar reading — the `tar` crate over a strict multi-member gzip stream
// (admin direction: standard crates over hand-rolled parsers). The
// crate verifies header checksums, handles ustar/GNU/PAX long names and
// rejects malformed frames; this layer keeps the member-type allowlist
// and the archive-path validation.
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
        for entry in archive.entries().context("reading tar entries")? {
            let mut entry = entry.with_context(|| "malformed tar entry")?;
            let etype = entry.header().entry_type();
            if !matches!(
                etype,
                tar::EntryType::Regular
                    | tar::EntryType::Directory
                    | tar::EntryType::Continuous
                    | tar::EntryType::XGlobalHeader
            ) {
                bail!("tar member is a {etype:?}; link/device members are not supported");
            }
            // A global PAX header carries defaults this reader does not
            // apply: the crate skips it during unpack, and so do we.
            if etype == tar::EntryType::XGlobalHeader {
                continue;
            }
            let raw_path = entry.path().context("invalid tar member path")?;
            // The tar crate's own unpack rules (which typst relies on)
            // are exactly these: no absolute paths, no `..` components.
            // Nothing more is invented here.
            if raw_path.is_absolute()
                || raw_path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir))
            {
                bail!(
                    "archive member `{}` escapes the destination",
                    raw_path.display()
                );
            }
            let path = raw_path
                .to_str()
                .ok_or_else(|| {
                    anyhow!("archive member name is not valid UTF-8; such archives are rejected")
                })?
                .trim_end_matches('/')
                .to_string();
            let mut path = path;
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
                let size = entry.size();
                // The resolved size (PAX `size` record included) bounds
                // the read; a short body is an error, never a truncated
                // file.
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
    // The archive loop stops at the end-of-archive marker (the first
    // zero block). Whatever follows — the second zero block, tar-style
    // zero padding up to the record size, or further gzip members —
    // must be all zeros: a concatenated archive or trailing garbage is
    // refused, so no member can be smuggled past the end marker.
    let mut rest = Vec::new();
    gz.read_to_end(&mut rest)
        .context("malformed data after the archive")?;
    if rest.iter().any(|&b| b != 0) {
        bail!("non-zero data after the end of the archive");
    }
    Ok(())
}

/// Encode files under `dir` (recursively) as a gzipped tarball; the
/// ustar encoding itself is delegated to the `tar` crate.
pub fn pack_tarball(dir: &Path) -> Result<Vec<u8>> {
    let enc = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(enc);
    add_tree(&mut builder, dir)?;
    builder.finish().context("finishing tar archive")?;
    builder
        .into_inner()
        .context("finishing gzip stream")?
        .finish()
        .context("finishing gzip stream")
}

fn add_tree(builder: &mut tar::Builder<GzEncoder<Vec<u8>>>, dir: &Path) -> Result<()> {
    // Deterministic depth-first walk with sorted names (the same order
    // the hand-written recursion produced), via the walkdir crate.
    for entry in WalkDir::new(dir).sort_by_file_name().min_depth(1) {
        let entry = entry.with_context(|| format!("walking {}", dir.display()))?;
        let rel = entry
            .path()
            .strip_prefix(dir)
            .expect("walkdir paths are below the walked root")
            .to_string_lossy()
            .to_string();
        if entry.file_type().is_symlink() {
            // Cloned repositories are untrusted input too: a symlink
            // would read outside the tree when packed or copied.
            bail!("symlink `{}` is not pack content", entry.path().display());
        }
        if entry.file_type().is_dir() {
            append_entry(builder, &rel, true, &[])?;
        } else {
            let data = fs::read(entry.path())
                .with_context(|| format!("reading {}", entry.path().display()))?;
            append_entry(builder, &rel, false, &data)?;
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
    // uid/gid/mtime stay at 0: `Header::new_ustar` zeroes every field.
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
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            // Same rule as pack_tarball: cloned repositories are
            // untrusted input; never follow links out of the tree.
            bail!("symlink `{}` is not pack content", entry.path().display());
        }
        if ft.is_dir() {
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
        (Materialized::Tarball { bytes, subpath }, Dest::Tarball(path)) => {
            match subpath {
                None => write_tarball_atomic(&path, &bytes)?,
                Some(sub) => {
                    // Unpack next to the destination, locate the
                    // subpath, and re-pack just that directory.
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent)
                            .with_context(|| format!("creating {}", parent.display()))?;
                    }
                    let tmp = TempDir::next_to(&path, "extract")?;
                    extract_tarball(&bytes, tmp.path(), None)?;
                    let found = locate_subdir(tmp.path(), &sub)
                        .ok_or_else(|| anyhow!("subpath `{sub}` not found in archive"))?;
                    let bytes = pack_tarball(found.as_path())?;
                    write_tarball_atomic(&path, &bytes)?;
                }
            }
        }
        (
            Materialized::Dir {
                path: dir,
                guard: _,
            },
            Dest::Tarball(path),
        ) => {
            ensure_distinct(&dir, &path)?;
            let bytes = pack_tarball(&dir)?;
            write_tarball_atomic(&path, &bytes)?;
        }
        (Materialized::Tarball { bytes, subpath }, Dest::Dir(path)) => {
            if path.exists() && fs::read_dir(&path)?.next().is_some() {
                bail!("destination `{}` exists and is not empty", path.display());
            }
            // typst-style atomicity: extract into a temp dir next to the
            // destination (same mount point), locate the pack root (or
            // the requested subpath), then rename it into place. A
            // failed extraction leaves no trace at the destination; a
            // completed one appears atomically.
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            let tmp = TempDir::next_to(&path, "extract")?;
            extract_tarball(&bytes, tmp.path(), None)?;
            let inner = match subpath.as_deref() {
                Some(sub) => locate_subdir(tmp.path(), sub)
                    .ok_or_else(|| anyhow!("subpath `{sub}` not found in archive"))?,
                None => find_pack_root(tmp.path())?,
            };
            let inner = find_pack_root(&inner)?;
            move_dir_atomic(&inner, &path)?;
        }
        (
            Materialized::Dir {
                path: dir,
                guard: _,
            },
            Dest::Dir(path),
        ) => {
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
                Materialized::Tarball { bytes, .. } => bytes,
                Materialized::Dir { path, .. } => pack_tarball(&path)?,
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
    let value: Json =
        serde_json::from_str(body).map_err(|e| anyhow!("invalid JSON in release document: {e}"))?;
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

/// Download a registry pack into the cache directory as
/// `{cache}/{name}@{version}`: the latest version is resolved when
/// none is given, and the pack is fetched and placed atomically via
/// [`copy`] (temp dir next to the destination, then `rename`).
pub fn download(
    name: &str,
    version: Option<&str>,
    registry: Option<&str>,
    cache: &Path,
) -> Result<PathBuf> {
    let version = match version {
        Some(v) => v.to_string(),
        None => latest_registry_version(registry, name)?,
    };
    // The cache must be an absolute fs path so it parses as a
    // destination; create it up front.
    fs::create_dir_all(cache)
        .with_context(|| format!("creating cache directory {}", cache.display()))?;
    let cache = dunce::canonicalize(cache)?;
    let dest = cache.join(format!("{name}@{version}"));
    copy(
        &format!("@preview/{name}:{version}"),
        &dest.to_string_lossy(),
        registry,
    )?;
    Ok(dest)
}

/// Latest version of `name` in the registry: the official index when
/// `registry` is None, else `{registry}/index.json`. GitHub-hosted
/// registries are directory-based rather than index-based and are not
/// supported here (use copy with `@namespace/name` instead).
pub fn latest_registry_version(registry: Option<&str>, name: &str) -> Result<String> {
    match registry {
        None => latest_official_version(name),
        Some(url) if url.contains("github.com") => bail!(
            "download does not support GitHub registries (`{url}`); use copy with `@namespace/name` instead"
        ),
        Some(url) => latest_index_version(url, name),
    }
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
    let src_abs = dunce::canonicalize(&src_dir).unwrap_or_else(|_| absolute_lexical(&src_dir));
    #[cfg(target_os = "windows")]
    {
        if std::os::windows::fs::symlink_dir(&src_abs, &dst_path).is_err() {
            // Without the symlink privilege, fall back to a junction.
            let dst_abs =
                dunce::canonicalize(&dst_path).unwrap_or_else(|_| absolute_lexical(&dst_path));
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
        // A plain repository URL: the default branch, cloned with git.
        assert!(matches!(
            parse_source("https://github.com/o/r").unwrap(),
            Source::GithubRepo { .. }
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
        for evil in ["../evil.txt", "/abs.txt", "a/../../b.txt"] {
            let gz = gz_of(&[(evil, b"x")]);
            let dest = std::env::temp_dir().join(format!("typship-x-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dest);
            assert!(extract_tarball(&gz, &dest, None).is_err(), "case {evil}");
            let _ = fs::remove_dir_all(&dest);
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
    fn pax_size_record_governs_the_member_length() {
        // A PAX `size` record overrides the ustar header's (stale)
        // size field; the reader honors the resolved entry size.
        let payload = b"9 size=5
";
        let mut raw = Vec::new();
        raw.extend_from_slice(&raw_header(b"p", b'x', payload.len()));
        raw.extend_from_slice(payload);
        raw.extend_from_slice(&vec![0u8; (512 - payload.len() % 512) % 512]);
        raw.extend_from_slice(&raw_header(b"f.txt", b'0', 0)); // stale size
        raw.extend_from_slice(b"HELLO");
        raw.extend_from_slice(&vec![0u8; 512 - 5]);
        raw.extend_from_slice(&[0u8; 1024]);
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-ps-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        extract_tarball(&gz, &dest, None).unwrap();
        assert_eq!(fs::read(dest.join("f.txt")).unwrap(), b"HELLO");
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn concatenated_tar_after_the_end_marker_is_refused() {
        // Valid tar members after the end-of-archive marker are
        // refused: they could overwrite earlier files.
        let mut raw = Vec::new();
        raw.extend_from_slice(&raw_header(b"f.txt", b'0', 1));
        raw.extend_from_slice(b"A");
        raw.extend_from_slice(&vec![0u8; 511]);
        raw.extend_from_slice(&[0u8; 1024]); // end marker
        raw.extend_from_slice(&raw_header(b"f.txt", b'0', 1));
        raw.extend_from_slice(b"B");
        raw.extend_from_slice(&vec![0u8; 511]);
        raw.extend_from_slice(&[0u8; 1024]);
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-cat-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        assert!(extract_tarball(&gz, &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn zero_padding_after_the_end_marker_is_tolerated() {
        // tar pads past the two end blocks up to its record size; that
        // zero padding is fine, anything non-zero is not.
        let mut raw = Vec::new();
        raw.extend_from_slice(&raw_header(b"a.txt", b'0', 1));
        raw.extend_from_slice(b"x");
        raw.extend_from_slice(&vec![0u8; 511]);
        raw.extend_from_slice(&[0u8; 1024 + 5120]);
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-zp-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        extract_tarball(&gz, &dest, None).unwrap();
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"x");
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn global_pax_headers_are_skipped() {
        // A global PAX header (typeflag 'g') is skipped -- not refused,
        // not applied (record-wise validation removed with the
        // typst-alignment).
        let mut raw = Vec::new();
        raw.extend_from_slice(&raw_header(b"p", b'g', 0));
        raw.extend_from_slice(&tar_file_entry("f.txt", b"x"));
        raw.extend_from_slice(&[0u8; 1024]);
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-gp-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        extract_tarball(&gz, &dest, None).unwrap();
        assert_eq!(fs::read(dest.join("f.txt")).unwrap(), b"x");
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

    // PAX/长名记录的帧解析与严格性由 `tar` crate 内部保证，旧的自写
    // 解码器测试随之删除；crate 对「缺结束块」静默接受的语义已记录。

    #[test]
    fn json_duplicate_keys_are_last_wins() {
        // serde_json object semantics: a repeated key's last value
        // wins. Declared behavior; callers must not rely on first-wins.
        let value =
            serde_json::from_str::<Json>(r#"{"version":"1.0.0","version":"2.0.0"}"#).unwrap();
        assert_eq!(value.get("version").and_then(|v| v.as_str()), Some("2.0.0"));
    }

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
        assert!(serde_json::from_str::<Json>("{\"a\":}").is_err());
        assert!(serde_json::from_str::<Json>("{\"a\":1} trailing").is_err());
        assert!(serde_json::from_str::<Json>("01").is_err());
        assert!(serde_json::from_str::<Json>(r#"\ud83d"#).is_err()); // unpaired surrogate
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
        // accepted by the reader.
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
        // found (documents the limitation).
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
        // directory: the full subpath must resolve.
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

    /// A single plain-file tar entry (header + data + padding), raw.
    fn tar_file_entry(name: &str, contents: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&raw_header(name.as_bytes(), b'0', contents.len()));
        out.extend_from_slice(contents);
        out.extend_from_slice(&vec![0u8; (512 - contents.len() % 512) % 512]);
        out
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
