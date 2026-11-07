//! The named Pack abstraction: parsing, detection and transport of pack
//! sources and destinations.
//!
//! New dependencies are limited to the two classes the proposal allows:
//! TLS (`ureq` with rustls) and compression (`flate2`). The tar container
//! itself is encoded and decoded here with the standard library only
//! (ustar headers, GNU long-name entries and PAX `path` records for
//! reading, end-of-archive blocks for writing), and JSON responses are
//! read with the small built-in parser in [`json`].
//!
//! Safety posture for untrusted archives: member paths are validated (no
//! absolute paths, no `..`, no backslashes, no colons, no Windows device
//! names, no trailing dots or spaces), member names must be UTF-8, the
//! header checksum is verified, the gzip stream must end cleanly and the
//! tar must contain an end-of-archive marker, and resource budgets bound
//! the number of members (including metadata headers) and the total
//! unpacked size. Link and device members are rejected outright.
//!
//! HTTP posture: only transient failures (transport errors, 429 and 5xx)
//! are retried; other 4xx answers are a definitive miss, over-long
//! response bodies are refused rather than truncated, and a non-gzip
//! tarball body is a permanent failure that never triggers another
//! request.

use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Total per-request timeout; a network path must never hang forever.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
/// Attempts per HTTP request for transient failures only (4xx except 429
/// fails immediately).
const RETRIES: usize = 3;
/// Maximum bytes of one HTTP response body we accept.
const MAX_DOWNLOAD: u64 = 512 * 1024 * 1024;
/// Maximum bytes read past the tar end-of-archive marker while checking
/// that only zero padding follows.
const MAX_TRAILER: u64 = 64 * 1024 * 1024;
/// Maximum number of members accepted from one archive; metadata
/// headers (`x`/`L`/`g`/`K`) count against this budget too.
const MAX_ARCHIVE_ENTRIES: usize = 50_000;
/// Maximum total uncompressed bytes accepted from one archive.
const MAX_TOTAL_UNPACKED: u64 = 1024 * 1024 * 1024;
/// Maximum size of a single archive member.
const MAX_MEMBER_SIZE: u64 = 512 * 1024 * 1024;
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
    /// The body exceeds the hard download cap: permanent.
    TooLong,
    /// The connection died mid-body (or another I/O error): the
    /// request is worth retrying.
    Io(std::io::Error),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyError::TooLong => write!(f, "body exceeds the download limit"),
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

/// Read a response body with a hard size cap. The reader is capped at
/// `limit + 1` bytes, so an over-long body is detected by its length
/// alone — no truncation, no second probe read.
fn read_body_capped(reader: impl Read, limit: u64, url: &str) -> Result<Vec<u8>, BodyError> {
    let mut reader = reader.take(limit + 1);
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).map_err(|e| {
        BodyError::Io(std::io::Error::new(
            e.kind(),
            format!("reading body of {url}: {e}"),
        ))
    })?;
    if buf.len() as u64 > limit {
        return Err(BodyError::TooLong);
    }
    Ok(buf)
}

/// GET a URL to bytes, retrying only transient failures. A body read
/// error is transient (the connection may have died mid-body) and is
/// retried in the same loop; an over-long body is permanent.
fn get_bytes(url: &str) -> Result<Vec<u8>, FetchError> {
    let mut last = None;
    for attempt in 0..RETRIES {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(500 * attempt as u64));
        }
        match agent().get(url).call() {
            Ok(resp) => match read_body_capped(resp.into_reader(), MAX_DOWNLOAD, url) {
                Ok(bytes) => return Ok(bytes),
                Err(BodyError::TooLong) => {
                    return Err(FetchError::Fatal(format!(
                        "body of {url} exceeds the {} MiB download limit",
                        MAX_DOWNLOAD / (1024 * 1024)
                    )));
                }
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

/// Collapse `.` and `..` components lexically; a leading `..` at the
/// filesystem root is kept (it cannot go higher).
fn fold_dots(p: &Path) -> PathBuf {
    let mut comps: Vec<Component> = Vec::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                let popped = matches!(
                    comps.last(),
                    Some(Component::Normal(_)) | Some(Component::ParentDir)
                );
                if popped {
                    comps.pop();
                } else {
                    comps.push(c);
                }
            }
            other => comps.push(other),
        }
    }
    comps.into_iter().collect()
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
    let s = fold_dots(&physical(src));
    let d = fold_dots(&physical(dst));
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

/// The per-user Typst packages directory.
fn typst_packages_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("LOCALAPPDATA").map_err(|_| anyhow!("LOCALAPPDATA not set"))?;
        Ok(PathBuf::from(base).join("typst").join("packages"))
    }
    #[cfg(target_os = "macos")]
    {
        let base = match std::env::var("XDG_DATA_HOME") {
            Ok(x) if !x.is_empty() => PathBuf::from(x),
            _ => {
                let home = std::env::var("HOME").map_err(|_| anyhow!("HOME not set"))?;
                PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
            }
        };
        Ok(base.join("typst").join("packages"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let base = match std::env::var("XDG_DATA_HOME") {
            Ok(x) if !x.is_empty() => PathBuf::from(x),
            _ => {
                let home = std::env::var("HOME").map_err(|_| anyhow!("HOME not set"))?;
                PathBuf::from(home).join(".local").join("share")
            }
        };
        Ok(base.join("typst").join("packages"))
    }
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
/// first, then a recursive search as the fallback for archives that
/// nest deeper. This keeps a `repo-HEAD/` wrapper transparent without
/// swallowing the repository's own single-child directories.
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
                .take(MAX_DOWNLOAD + 1)
                .read_to_end(&mut buf)
                .context("reading tarball from stdin")?;
            if buf.len() as u64 > MAX_DOWNLOAD {
                bail!("stdin tarball exceeds the download limit");
            }
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
    let value = json::parse(&text).map_err(|e| anyhow!("invalid JSON from {api}: {e}"))?;
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
fn release_archive_asset(release: &json::Value) -> Option<String> {
    release.get("assets")?.as_arr()?.iter().find_map(|asset| {
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
    let value = json::parse(text).map_err(|e| anyhow!("invalid JSON: {e}"))?;
    let entries = value
        .as_arr()
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

/// Find a directory named `rel` anywhere below `root`.
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
// JSON — a minimal reader, standard library only.
// ---------------------------------------------------------------------------

mod json {
    //! A minimal JSON reader covering objects, arrays, strings (with
    //! `\uXXXX` escapes and surrogate pairs), numbers and the three
    //! literals. Just enough to read GitHub API and registry index
    //! documents correctly; never a text scan.

    /// A parsed JSON value.
    #[allow(dead_code)] // Bool/Num exist for completeness of the reader
    #[derive(Debug, Clone)]
    pub enum Value {
        Null,
        Bool(bool),
        Num(f64),
        Str(String),
        Arr(Vec<Value>),
        Obj(Vec<(String, Value)>),
    }

    impl Value {
        /// The value of `key` in this object, if this is an object.
        pub fn get(&self, key: &str) -> Option<&Value> {
            match self {
                Value::Obj(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }

        /// The string content, if this is a string.
        pub fn as_str(&self) -> Option<&str> {
            match self {
                Value::Str(s) => Some(s),
                _ => None,
            }
        }

        /// The element slice, if this is an array.
        pub fn as_arr(&self) -> Option<&[Value]> {
            match self {
                Value::Arr(a) => Some(a),
                _ => None,
            }
        }

        /// The string value of `key` anywhere below this value,
        /// recursing through objects and arrays.
        #[allow(dead_code)]
        pub fn find_str(&self, key: &str) -> Option<&str> {
            match self {
                Value::Obj(items) => {
                    for (k, v) in items {
                        if k == key {
                            if let Some(s) = v.as_str() {
                                return Some(s);
                            }
                        }
                        if let Some(s) = v.find_str(key) {
                            return Some(s);
                        }
                    }
                    None
                }
                Value::Arr(items) => items.iter().find_map(|v| v.find_str(key)),
                _ => None,
            }
        }
    }

    /// Parse a complete JSON document.
    pub fn parse(text: &str) -> Result<Value, String> {
        let mut p = Parser {
            b: text.as_bytes(),
            i: 0,
            depth: 0,
        };
        p.ws();
        let v = p.value()?;
        p.ws();
        if p.i != p.b.len() {
            return Err("trailing characters after the JSON value".to_string());
        }
        Ok(v)
    }

    struct Parser<'a> {
        b: &'a [u8],
        i: usize,
        depth: usize,
    }

    impl<'a> Parser<'a> {
        fn ws(&mut self) {
            while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
                self.i += 1;
            }
        }

        fn peek(&self) -> Option<u8> {
            self.b.get(self.i).copied()
        }

        fn starts_with(&self, s: &[u8]) -> bool {
            self.b[self.i..].starts_with(s)
        }

        fn value(&mut self) -> Result<Value, String> {
            self.depth += 1;
            if self.depth > 64 {
                return Err("JSON nesting deeper than 64 levels".to_string());
            }
            let v = match self.peek() {
                Some(b'{') => self.object(),
                Some(b'[') => self.array(),
                Some(b'"') => self.string().map(Value::Str),
                Some(b't') if self.starts_with(b"true") => {
                    self.i += 4;
                    Ok(Value::Bool(true))
                }
                Some(b'f') if self.starts_with(b"false") => {
                    self.i += 5;
                    Ok(Value::Bool(false))
                }
                Some(b'n') if self.starts_with(b"null") => {
                    self.i += 4;
                    Ok(Value::Null)
                }
                Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
                _ => Err(format!("unexpected byte at offset {}", self.i)),
            };
            self.depth -= 1;
            v
        }

        fn object(&mut self) -> Result<Value, String> {
            self.i += 1; // '{'
            let mut items = Vec::new();
            self.ws();
            if self.peek() == Some(b'}') {
                self.i += 1;
                return Ok(Value::Obj(items));
            }
            loop {
                self.ws();
                if self.peek() != Some(b'"') {
                    return Err(format!("expected object key at offset {}", self.i));
                }
                let key = self.string()?;
                self.ws();
                if self.peek() != Some(b':') {
                    return Err(format!("expected ':' at offset {}", self.i));
                }
                self.i += 1;
                self.ws();
                let val = self.value()?;
                items.push((key, val));
                self.ws();
                match self.peek() {
                    Some(b',') => self.i += 1,
                    Some(b'}') => {
                        self.i += 1;
                        return Ok(Value::Obj(items));
                    }
                    _ => return Err(format!("expected ',' or '}}' at offset {}", self.i)),
                }
            }
        }

        fn array(&mut self) -> Result<Value, String> {
            self.i += 1; // '['
            let mut items = Vec::new();
            self.ws();
            if self.peek() == Some(b']') {
                self.i += 1;
                return Ok(Value::Arr(items));
            }
            loop {
                self.ws();
                items.push(self.value()?);
                self.ws();
                match self.peek() {
                    Some(b',') => self.i += 1,
                    Some(b']') => {
                        self.i += 1;
                        return Ok(Value::Arr(items));
                    }
                    _ => return Err(format!("expected ',' or ']' at offset {}", self.i)),
                }
            }
        }

        fn string(&mut self) -> Result<String, String> {
            self.i += 1; // '"'
            let mut out: Vec<u8> = Vec::new();
            loop {
                let c = *self
                    .b
                    .get(self.i)
                    .ok_or_else(|| "unterminated string".to_string())?;
                self.i += 1;
                match c {
                    b'"' => return String::from_utf8(out).map_err(|_| "bad UTF-8".to_string()),
                    b'\\' => {
                        let esc = *self
                            .b
                            .get(self.i)
                            .ok_or_else(|| "truncated escape".to_string())?;
                        self.i += 1;
                        match esc {
                            b'"' => out.push(b'"'),
                            b'\\' => out.push(b'\\'),
                            b'/' => out.push(b'/'),
                            b'b' => out.push(0x08),
                            b'f' => out.push(0x0c),
                            b'n' => out.push(b'\n'),
                            b'r' => out.push(b'\r'),
                            b't' => out.push(b'\t'),
                            b'u' => {
                                let mut code = self.hex4()?;
                                if (0xD800..0xDC00).contains(&code) {
                                    // High surrogate: a low surrogate must follow.
                                    if self.peek() == Some(b'\\')
                                        && self.b.get(self.i + 1) == Some(&b'u')
                                    {
                                        self.i += 2;
                                        let low = self.hex4()?;
                                        if !(0xDC00..0xE000).contains(&low) {
                                            return Err("invalid low surrogate".to_string());
                                        }
                                        code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                                    } else {
                                        return Err("unpaired surrogate".to_string());
                                    }
                                } else if (0xDC00..0xE000).contains(&code) {
                                    return Err("unpaired surrogate".to_string());
                                }
                                let ch = char::from_u32(code)
                                    .ok_or_else(|| "invalid codepoint".to_string())?;
                                let mut buf = [0u8; 4];
                                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                            }
                            _ => return Err("unknown escape".to_string()),
                        }
                    }
                    c if c < 0x20 => {
                        return Err("raw control character in string".to_string());
                    }
                    c => out.push(c),
                }
            }
        }

        fn hex4(&mut self) -> Result<u32, String> {
            if self.i + 4 > self.b.len() {
                return Err("truncated \\u escape".to_string());
            }
            let hex = &self.b[self.i..self.i + 4];
            if !hex.iter().all(|b| b.is_ascii_hexdigit()) {
                return Err("bad \\u escape: not four hex digits".to_string());
            }
            // Safe: four ASCII hex digits only (no sign, no whitespace).
            let s = std::str::from_utf8(hex).map_err(|_| "bad \\u escape".to_string())?;
            let v = u32::from_str_radix(s, 16).map_err(|_| "bad \\u escape".to_string())?;
            self.i += 4;
            Ok(v)
        }

        fn number(&mut self) -> Result<Value, String> {
            let start = self.i;
            if self.peek() == Some(b'-') {
                self.i += 1;
            }
            // JSON numbers: `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`
            match self.peek() {
                Some(b'0') => self.i += 1,
                Some(c) if c.is_ascii_digit() => {
                    while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                        self.i += 1;
                    }
                }
                _ => return Err("invalid number".to_string()),
            }
            if self.peek() == Some(b'.') {
                self.i += 1;
                if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    return Err("invalid number: no digit after '.'".to_string());
                }
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            if matches!(self.peek(), Some(b'e' | b'E')) {
                self.i += 1;
                if matches!(self.peek(), Some(b'+' | b'-')) {
                    self.i += 1;
                }
                if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    return Err("invalid number: no digit in exponent".to_string());
                }
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            let text = std::str::from_utf8(&self.b[start..self.i])
                .map_err(|_| "bad number".to_string())?;
            text.parse::<f64>()
                .map(Value::Num)
                .map_err(|_| format!("bad number `{text}`"))
        }
    }
}

// ---------------------------------------------------------------------------
// tar (ustar) codec — standard library only.
// ---------------------------------------------------------------------------

/// Parse an octal field, tolerating trailing NULs and spaces; anything
/// else is an error, never a silent zero.
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

/// Decode archive path bytes: they must be UTF-8. Non-UTF-8 member names
/// are rejected with a clear error rather than round-tripped through a
/// lossy encoding.
fn decode_path(bytes: &[u8]) -> Result<String> {
    let s = std::str::from_utf8(bytes).map_err(|_| {
        anyhow!("archive member name is not valid UTF-8; such archives are rejected")
    })?;
    Ok(s.trim_end_matches('\0').to_string())
}

fn nul_terminated(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(i) => &bytes[..i],
        None => bytes,
    }
}

/// One decoded tar entry.
struct TarEntry {
    /// Path inside the archive.
    path: String,
    /// Whether it is a directory.
    is_dir: bool,
    /// File contents (empty for directories).
    data: Vec<u8>,
}

/// Read the `path` record out of a PAX extended header, if present.
/// Records are parsed strictly by their declared length
/// (`<len> key=value\n`, where `<len>` counts the whole record), the
/// whole record set is validated, and malformed input is an error —
/// never a panic and never a guess.
fn pax_path(data: &[u8]) -> Result<Option<String>> {
    let mut pos = 0usize;
    let mut found: Option<String> = None;
    while pos < data.len() {
        let rel_sp = data[pos..]
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| anyhow!("malformed PAX record: no length separator"))?;
        let len_str = std::str::from_utf8(&data[pos..pos + rel_sp])
            .map_err(|_| anyhow!("malformed PAX record: length is not ASCII"))?;
        // Only plain decimal digits: `usize::parse` would accept a `+`.
        if len_str.is_empty() || !len_str.bytes().all(|b| b.is_ascii_digit()) {
            bail!("malformed PAX record: bad length `{len_str}`");
        }
        let len: usize = len_str
            .parse()
            .map_err(|_| anyhow!("malformed PAX record: bad length `{len_str}`"))?;
        // The declared length covers `<len>` + space + body + newline, so
        // it must be at least large enough for the prefix and terminator.
        // Subtraction instead of `pos + len`: a huge declared length must
        // be an error, never an overflow panic.
        if len < rel_sp + 2 || len > data.len() - pos {
            bail!("malformed PAX record: length {len} out of bounds");
        }
        let record = &data[pos..pos + len];
        if record[len - 1] != b'\n' {
            bail!("malformed PAX record: does not end with a newline");
        }
        // The record body after the `<len> ` prefix is `key=value`.
        let body = &record[rel_sp + 1..len - 1];
        let Some(eq) = body.iter().position(|&b| b == b'=') else {
            bail!("malformed PAX record: no '=' separator");
        };
        if &body[..eq] == b"path" && found.is_none() {
            found = Some(decode_path(&body[eq + 1..])?);
        }
        pos += len;
    }
    Ok(found)
}

/// Resource budgets for decoding one archive, parameterized so tests can
/// exercise the accumulation logic at small scales.
#[derive(Clone, Copy)]
struct TarLimits {
    max_entries: usize,
    max_total: u64,
    max_member: u64,
    max_trailer: u64,
}

/// The production budgets: 50k members, 1 GiB total unpacked, 512 MiB
/// per member, 64 MiB of trailer after the end-of-archive marker.
const PRODUCTION_LIMITS: TarLimits = TarLimits {
    max_entries: MAX_ARCHIVE_ENTRIES,
    max_total: MAX_TOTAL_UNPACKED,
    max_member: MAX_MEMBER_SIZE,
    max_trailer: MAX_TRAILER,
};

/// Decode a gzipped tarball into entries under the production budgets.
fn decode_tar(gz: &[u8]) -> Result<Vec<TarEntry>> {
    decode_tar_with(gz, &PRODUCTION_LIMITS)
}

/// Decode a gzipped tarball into entries. Untrusted input: the gzip
/// stream must decode cleanly (including trailing garbage, which is an
/// error), the header checksum is verified, short reads are errors, the
/// two-block end-of-archive marker is required, resource budgets
/// (including metadata headers) are enforced, and non-regular members
/// are rejected.
fn decode_tar_with(gz: &[u8], limits: &TarLimits) -> Result<Vec<TarEntry>> {
    let mut reader = MultiGzDecoder::new(gz);
    let mut entries = Vec::new();
    let mut total: u64 = 0;
    let mut members_seen: usize = 0;
    let mut pending_long_name: Option<String> = None;
    let mut pending_pax_path: Option<String> = None;
    loop {
        let mut header = [0u8; 512];
        let mut read = 0;
        while read < 512 {
            let n = reader
                .read(&mut header[read..])
                .context("reading tar header")?;
            if n == 0 {
                break;
            }
            read += n;
        }
        if read == 0 {
            // The stream ended without an end-of-archive marker.
            bail!("archive ends without end-of-archive marker");
        }
        if read < 512 {
            bail!("truncated tar header");
        }
        if header.iter().all(|&b| b == 0) {
            // The end-of-archive blocks themselves do not count against
            // the member budget. First end-of-archive block: tar
            // requires a second one, then only zero padding within a
            // bounded read.
            let mut second = [0u8; 512];
            reader
                .read_exact(&mut second)
                .context("truncated end-of-archive marker")?;
            if !second.iter().all(|&b| b == 0) {
                bail!("end-of-archive marker is not followed by a second zero block");
            }
            let mut rest = Vec::new();
            (&mut reader)
                .take(limits.max_trailer + 1)
                .read_to_end(&mut rest)
                .context("reading tar trailer")?;
            if rest.len() as u64 > limits.max_trailer {
                bail!("excessive data after end-of-archive marker");
            }
            if rest.iter().any(|&b| b != 0) {
                bail!("garbage after end-of-archive marker");
            }
            break;
        }
        let stored = octal(&header[148..156])?;
        members_seen += 1;
        if members_seen > limits.max_entries {
            bail!(
                "archive has too many entries (limit {})",
                limits.max_entries
            );
        }
        let mut sum = 0u64;
        for (i, &b) in header.iter().enumerate() {
            sum += if (148..156).contains(&i) {
                b' ' as u64
            } else {
                b as u64
            };
        }
        if sum != stored {
            bail!("tar header checksum mismatch (stored {stored:o}, computed {sum:o})");
        }
        let size = octal(&header[124..136])?;
        if size > limits.max_member {
            bail!(
                "tar member of {size} bytes exceeds the {} MiB member limit",
                limits.max_member / (1024 * 1024)
            );
        }
        // Every member — file, directory or metadata header — counts
        // against the total unpacked budget.
        if total + size > limits.max_total {
            bail!(
                "archive exceeds the total unpacked limit of {} MiB",
                limits.max_total / (1024 * 1024)
            );
        }
        total += size;
        let mut name = {
            // The fallback name in a GNU long-name pair may be a
            // byte-truncated placeholder; when a long name is pending it
            // wins anyway, so tolerate an undecodable header name there.
            let n = match decode_path(nul_terminated(&header[..100])) {
                Ok(n) => Some(n),
                Err(_) if pending_long_name.is_some() => None,
                Err(e) => return Err(e),
            };
            let prefix = decode_path(nul_terminated(&header[345..500]))?;
            match n {
                Some(n) if prefix.is_empty() => n,
                Some(n) => format!("{prefix}/{n}"),
                None => String::new(),
            }
        };
        let mut data = vec![0u8; size as usize];
        reader
            .read_exact(&mut data)
            .with_context(|| format!("truncated tar entry `{name}`"))?;
        let pad = ((512 - (size % 512)) % 512) as usize;
        if pad > 0 {
            let mut skip = vec![0u8; pad];
            reader
                .read_exact(&mut skip)
                .context("truncated tar padding")?;
        }
        let typeflag = header[156];
        match typeflag {
            b'L' => {
                pending_long_name = Some(decode_path(nul_terminated(&data))?);
                continue;
            }
            b'x' => {
                pending_pax_path = pax_path(&data)?;
                continue;
            }
            b'g' => {
                // A global PAX header replaces any pending extended
                // attributes rather than extending them; its records are
                // validated like any other PAX header, then discarded.
                pax_path(&data)?;
                pending_pax_path = None;
                pending_long_name = None;
                continue;
            }
            b'K' => {
                // GNU long-link-name header: the member it names will be
                // rejected as a link anyway.
                continue;
            }
            b'1' | b'2' => {
                bail!("tar member `{name}` is a hard/symlink; link members are not supported")
            }
            b'3' | b'4' | b'6' => {
                bail!("tar member `{name}` is a device or fifo; not supported")
            }
            b'5' => {
                // Both pending overrides are consumed together (GNU long
                // name wins if both are present), so neither can leak
                // into the next member.
                let gn = pending_long_name.take();
                let px = pending_pax_path.take();
                if let Some(override_name) = gn.or(px) {
                    name = override_name;
                }
                entries.push(TarEntry {
                    path: name,
                    is_dir: true,
                    data: Vec::new(),
                });
            }
            b'0' | b'\x00' | b'7' => {
                let gn = pending_long_name.take();
                let px = pending_pax_path.take();
                if let Some(override_name) = gn.or(px) {
                    name = override_name;
                }
                entries.push(TarEntry {
                    path: name,
                    is_dir: false,
                    data,
                });
            }
            other => bail!("unsupported tar typeflag `{other}` for member `{name}`"),
        }
    }
    Ok(entries)
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
    let entries = decode_tar(gz)?;
    for e in entries {
        let mut path = safe_member_path(&e.path)?;
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
            bail!("archive member `{}` escapes the destination", e.path);
        }
        if e.is_dir {
            fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
        } else {
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&out, &e.data).with_context(|| format!("writing {}", out.display()))?;
        }
    }
    Ok(())
}

/// Encode files under `dir` (recursively) as a gzipped tarball.
pub fn pack_tarball(dir: &Path) -> Result<Vec<u8>> {
    let enc = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = TarWriter { out: enc };
    add_tree(&mut tar, dir, "")?;
    tar.write_end_blocks()?;
    tar.out.finish().context("finishing gzip stream")
}

fn add_tree(tar: &mut TarWriter, dir: &Path, rel: &str) -> Result<()> {
    if !rel.is_empty() {
        tar.write_entry(rel, true, &[])?;
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
            add_tree(tar, &path, &child_rel)?;
        } else {
            let data = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            tar.write_entry(&child_rel, false, &data)?;
        }
    }
    Ok(())
}

struct TarWriter {
    out: GzEncoder<Vec<u8>>,
}

/// Split a too-long archive path into a ustar `prefix` + `name` pair,
/// keeping the name (with its trailing slash for directories) at or under
/// 100 bytes and the prefix at or under 155.
fn split_ustar_path(name: &str) -> Option<(String, String)> {
    if name.len() <= 100 {
        return Some((String::new(), name.to_string()));
    }
    let bytes = name.as_bytes();
    let mut best: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'/' && i <= 155 && name.len() - i - 1 <= 100 {
            best = Some(i);
        }
    }
    let i = best?;
    Some((name[..i].to_string(), name[i + 1..].to_string()))
}

impl TarWriter {
    fn write_end_blocks(&mut self) -> Result<()> {
        self.out.write_all(&[0u8; 1024])?;
        Ok(())
    }

    fn write_entry(&mut self, path: &str, is_dir: bool, data: &[u8]) -> Result<()> {
        let mut header = [0u8; 512];
        let name = if is_dir {
            format!("{path}/")
        } else {
            path.to_string()
        };
        match split_ustar_path(&name) {
            Some((prefix, short)) => {
                if !prefix.is_empty() {
                    header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
                }
                header[..short.len()].copy_from_slice(short.as_bytes());
            }
            None => {
                // Not splittable into ustar fields: emit a GNU long-name
                // entry carrying the real name, then the member header.
                // The fallback header name is a placeholder; cut it at a
                // UTF-8 character boundary so the reader (which ignores
                // it in favour of the long name) never sees broken text.
                self.write_long_name(&name)?;
                let nb = name.as_bytes();
                let mut cut = nb.len().min(100);
                while cut > 0 && (nb[cut] & 0xC0) == 0x80 {
                    cut -= 1;
                }
                header[..cut].copy_from_slice(&nb[..cut]);
            }
        }
        self.finish_header(&mut header, if is_dir { b'5' } else { b'0' }, data.len())?;
        if !is_dir {
            self.out.write_all(data)?;
            self.write_padding(data.len())?;
        }
        Ok(())
    }

    /// Emit a GNU long-name (`L`) entry carrying `name`.
    fn write_long_name(&mut self, name: &str) -> Result<()> {
        let mut data = name.as_bytes().to_vec();
        data.push(0);
        let mut header = [0u8; 512];
        header[..2].copy_from_slice(b"./");
        self.finish_header(&mut header, b'L', data.len())?;
        self.out.write_all(&data)?;
        self.write_padding(data.len())?;
        Ok(())
    }

    fn write_padding(&mut self, len: usize) -> Result<()> {
        let pad = ((512 - (len as u64 % 512)) % 512) as usize;
        if pad > 0 {
            self.out.write_all(&vec![0u8; pad])?;
        }
        Ok(())
    }

    /// Fill the fixed fields of a header, compute and store its
    /// checksum, and write it out.
    fn finish_header(&mut self, header: &mut [u8; 512], typeflag: u8, size: usize) -> Result<()> {
        let mode = match typeflag {
            b'5' => b"0000755\x00",
            _ => b"0000644\x00",
        };
        header[100..108].copy_from_slice(mode);
        header[108..116].copy_from_slice(b"0000000\x00"); // uid
        header[116..124].copy_from_slice(b"0000000\x00"); // gid
        let size_field = format!("{size:011o}\x00");
        header[124..136].copy_from_slice(size_field.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\x00"); // mtime
        header[148..156].copy_from_slice(b"        "); // checksum placeholder
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\x00");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|&b| b as u64).sum::<u64>();
        let cs = format!("{checksum:06o}\x00 ");
        header[148..156].copy_from_slice(cs.as_bytes());
        self.out.write_all(header)?;
        Ok(())
    }
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
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
        }
        (Materialized::Dir(dir), Dest::Tarball(path)) => {
            ensure_distinct(&dir, &path)?;
            let bytes = pack_tarball(&dir)?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
        }
        (Materialized::Tarball(bytes), Dest::Dir(path)) => {
            if path.exists() && fs::read_dir(&path)?.next().is_some() {
                bail!("destination `{}` exists and is not empty", path.display());
            }
            let tmp = temp_dir()?;
            extract_tarball(&bytes, &tmp, None)?;
            let inner = find_pack_root(&tmp)?;
            copy_tree(&inner, &path)?;
            let _ = fs::remove_dir_all(&tmp);
        }
        (Materialized::Dir(dir), Dest::Dir(path)) => {
            ensure_distinct(&dir, &path)?;
            if path.exists() && fs::read_dir(&path)?.next().is_some() {
                bail!("destination `{}` exists and is not empty", path.display());
            }
            copy_tree(&dir, &path)?;
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
    let value = json::parse(body).map_err(|e| anyhow!("invalid release JSON: {e}"))?;
    value
        .get("upload_url")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("release for tag `{tag}` has no upload_url"))
}

/// JSON string escape for embedding a value into a JSON document.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    format!("\"{out}\"")
}

/// Percent-encode everything outside the unreserved set.
fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
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
    fn extract_rejects_huge_member_without_oom() {
        // A member claiming 8 GiB must be refused before allocation.
        let mut header = [0u8; 512];
        header[..3].copy_from_slice(b"big");
        let size_field = format!("{:011o}\x00", MAX_MEMBER_SIZE + 1);
        header[124..136].copy_from_slice(size_field.as_bytes());
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        let checksum = header.iter().map(|&b| b as u64).sum::<u64>();
        let cs = format!("{checksum:06o}\x00 ");
        header[148..156].copy_from_slice(cs.as_bytes());
        let gz = gz_of_raw(&header);
        let dest = std::env::temp_dir().join(format!("typship-h-{}", std::process::id()));
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
        // A complete entry without the end-of-archive marker.
        let no_end = {
            let enc = GzEncoder::new(Vec::new(), Compression::default());
            let mut tar = TarWriter { out: enc };
            tar.write_entry("a.txt", false, b"x").unwrap();
            tar.out.finish().unwrap()
        };
        assert!(
            extract_tarball(&no_end, &dest, None).is_err(),
            "no end marker"
        );
        // An empty gzip payload.
        let empty = GzEncoder::new(Vec::new(), Compression::default())
            .finish()
            .unwrap();
        assert!(extract_tarball(&empty, &dest, None).is_err(), "empty gzip");
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
    fn metadata_headers_count_against_the_entry_budget() {
        // MAX_ARCHIVE_ENTRIES + 1 metadata headers must be refused.
        let mut raw = Vec::new();
        for i in 0..(MAX_ARCHIVE_ENTRIES + 1) {
            raw.extend_from_slice(&raw_header(format!("pax{i}").as_bytes(), b'x', 0));
        }
        raw.extend_from_slice(&[0u8; 1024]);
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-mb-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        assert!(extract_tarball(&gz, &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn pax_path_record_is_parsed_by_length() {
        // A well-formed PAX header whose path record carries a slash
        // tag-like value, plus a decoy `n path=evil` text line inside
        // another record that must not win.
        let payload = b"22 path=real/name.typ\n13 y=x path=\n";
        let pad = (512 - (payload.len() % 512)) % 512;
        let gz = gz_of_raw(
            &[
                raw_header(b"PaxHeader", b'x', payload.len()).to_vec(),
                payload.to_vec(),
                vec![0u8; pad],
                raw_header(b"ignored", b'0', 0).to_vec(),
                vec![0u8; 1024],
            ]
            .concat(),
        );
        let entries = decode_tar(&gz).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "real/name.typ");
    }

    #[test]
    fn read_body_capped_refuses_over_long_bodies() {
        assert_eq!(
            read_body_capped(&b"hello"[..], 5, "u").unwrap(),
            b"hello".to_vec()
        );
        assert!(read_body_capped(&b"hello"[..], 4, "u").is_err());
        assert!(read_body_capped(std::io::repeat(b'x'), 1024, "u").is_err());
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
    fn json_parser_reads_nested_objects_and_real_keys() {
        let text =
            r#"{"description":"name","a":{"name":"inner","n":[1,2,{"name":"deep"}]},"name":"top"}"#;
        let v = json::parse(text).unwrap();
        assert_eq!(v.get("name").unwrap().as_str(), Some("top"));
        assert_eq!(v.get("description").unwrap().as_str(), Some("name"));
        assert_eq!(
            v.get("a").unwrap().get("name").unwrap().as_str(),
            Some("inner")
        );
        assert_eq!(v.get("a").unwrap().find_str("name"), Some("inner"));
        // find_str returns the first hit in document order.
        assert_eq!(v.find_str("name"), Some("inner"));
        // Malformed documents are rejected, not scanned.
        assert!(json::parse("{\"a\":}").is_err());
        assert!(json::parse("{\"a\":1} trailing").is_err());
    }

    #[test]
    fn json_parser_handles_escapes_and_surrogate_pairs() {
        let v = json::parse(r#"{"s":"a\"b\\c\n\t😀"}"#).unwrap();
        assert_eq!(v.get("s").unwrap().as_str(), Some("a\"b\\c\n\t😀"));
        assert!(json::parse(r#""\ud83d""#).is_err()); // unpaired surrogate
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
        let v = json::parse(body).unwrap();
        assert_eq!(
            release_archive_asset(&v).as_deref(),
            Some("https://x/p.tar.gz")
        );
        assert_eq!(v.get("tag_name").unwrap().as_str(), Some("v1.2.3"));
        let empty = json::parse(r#"{"tag_name":"v1","assets":[]}"#).unwrap();
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
        // Long enough to take the GNU long-name path, and multi-byte so
        // a byte-truncated fallback header would break decoding.
        let long = format!("{}.typ", "中".repeat(40));
        fs::write(src.join(&long), "long").unwrap();
        let gz = pack_tarball(&src).unwrap();
        let dst = base.join("b");
        extract_tarball(&gz, &dst, None).unwrap();
        assert_eq!(fs::read(dst.join("中文.typ")).unwrap(), b"hello");
        assert_eq!(fs::read(dst.join(&long)).unwrap(), b"long");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn pax_malformed_records_are_errors_not_panics() {
        // A declared length smaller than its own prefix: refused.
        let payload = b"1 path=x\n";
        let gz = gz_of_raw(
            &[
                raw_header(b"p", b'x', payload.len()).to_vec(),
                payload.to_vec(),
                vec![0u8; (512 - (payload.len() % 512)) % 512],
                raw_header(b"m", b'0', 0).to_vec(),
                vec![0u8; 1024],
            ]
            .concat(),
        );
        assert!(decode_tar(&gz).is_err());
        // A valid first record followed by a malformed one: refused (the
        // whole record set is validated).
        let payload = b"15 path=ok.typ\n3 junk\n";
        let gz = gz_of_raw(
            &[
                raw_header(b"p", b'x', payload.len()).to_vec(),
                payload.to_vec(),
                vec![0u8; (512 - (payload.len() % 512)) % 512],
                raw_header(b"m", b'0', 0).to_vec(),
                vec![0u8; 1024],
            ]
            .concat(),
        );
        assert!(decode_tar(&gz).is_err());
        // A record without a newline terminator: refused.
        let payload = b"13 path=no-term";
        let gz = gz_of_raw(
            &[
                raw_header(b"p", b'x', payload.len()).to_vec(),
                payload.to_vec(),
                vec![0u8; (512 - (payload.len() % 512)) % 512],
                raw_header(b"m", b'0', 0).to_vec(),
                vec![0u8; 1024],
            ]
            .concat(),
        );
        assert!(decode_tar(&gz).is_err());
        // Multi-record with the path record second still resolves.
        let payload = b"13 mtime=0.5\n17 path=real.typ\n";
        let gz = gz_of_raw(
            &[
                raw_header(b"p", b'x', payload.len()).to_vec(),
                payload.to_vec(),
                vec![0u8; (512 - (payload.len() % 512)) % 512],
                raw_header(b"m", b'0', 0).to_vec(),
                vec![0u8; 1024],
            ]
            .concat(),
        );
        let entries = decode_tar(&gz).unwrap();
        assert_eq!(entries[0].path, "real.typ");
    }

    #[test]
    fn pending_name_overrides_never_leak_to_the_next_member() {
        // Both a PAX path and a GNU long name pending: the member takes
        // one name (GNU wins) and BOTH are consumed, so the following
        // member keeps its own header name (R4-2 regression).
        let pax_payload = b"14 path=WRONG\n";
        let mut raw = Vec::new();
        raw.extend_from_slice(&raw_header(b"p", b'x', pax_payload.len()));
        raw.extend_from_slice(pax_payload);
        raw.extend_from_slice(&vec![0u8; (512 - (pax_payload.len() % 512)) % 512]);
        // GNU long-name entry for "good.txt".
        let mut ln = b"good.txt".to_vec();
        ln.push(0);
        raw.extend_from_slice(&raw_header(b"ln", b'L', ln.len()));
        raw.extend_from_slice(&ln);
        raw.extend_from_slice(&vec![0u8; (512 - (ln.len() % 512)) % 512]);
        // The member itself: header name is a placeholder.
        raw.extend_from_slice(&raw_header(b"placeholder", b'0', 1));
        raw.extend_from_slice(b"x");
        raw.extend_from_slice(&vec![0u8; 511]);
        // A following member with its own plain name.
        raw.extend_from_slice(&raw_header(b"b.txt", b'0', 1));
        raw.extend_from_slice(b"y");
        raw.extend_from_slice(&vec![0u8; 511]);
        raw.extend_from_slice(&[0u8; 1024]);
        let entries = decode_tar(&gz_of_raw(&raw)).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "good.txt");
        assert_eq!(entries[1].path, "b.txt");
    }

    #[test]
    fn total_unpack_budget_accumulates_regular_files() {
        let limits = TarLimits {
            max_entries: 100,
            max_total: 600,
            max_member: 10_000,
            max_trailer: 1024 * 1024,
        };
        // Three 300-byte files: 900 total, over the 600-byte budget.
        let mut raw = Vec::new();
        for i in 0..3 {
            raw.extend_from_slice(&raw_header(format!("f{i}.txt").as_bytes(), b'0', 300));
            raw.extend_from_slice(&vec![b'a'; 300]);
            raw.extend_from_slice(&vec![0u8; 512 - 300]);
        }
        raw.extend_from_slice(&[0u8; 1024]);
        let gz = gz_of_raw(&raw);
        assert!(decode_tar_with(&gz, &limits).is_err(), "over budget");
        // Two files fit under the budget.
        let mut raw = Vec::new();
        for i in 0..2 {
            raw.extend_from_slice(&raw_header(format!("f{i}.txt").as_bytes(), b'0', 300));
            raw.extend_from_slice(&vec![b'a'; 300]);
            raw.extend_from_slice(&vec![0u8; 512 - 300]);
        }
        raw.extend_from_slice(&[0u8; 1024]);
        let gz = gz_of_raw(&raw);
        assert!(decode_tar_with(&gz, &limits).is_ok(), "within budget");
    }

    #[test]
    fn single_zero_block_is_not_a_complete_end_marker() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&raw_header(b"a.txt", b'0', 1));
        raw.extend_from_slice(b"x");
        raw.extend_from_slice(&vec![0u8; 511]);
        raw.extend_from_slice(&[0u8; 512]); // only one of the two blocks
        let gz = gz_of_raw(&raw);
        let dest = std::env::temp_dir().join(format!("typship-z1-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        assert!(extract_tarball(&gz, &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn http_403_is_permanent_and_never_retried() {
        let (url, count) = mock_server(&[(403, "forbidden")]);
        match get_bytes(&format!("{url}/private")) {
            Err(FetchError::Fatal(_)) => {}
            other => panic!("expected Fatal, got {other:?}"),
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

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
    fn json_lexer_rejects_malformed_numbers_and_escapes() {
        assert!(json::parse("01").is_err(), "leading zero");
        assert!(json::parse("-").is_err());
        assert!(json::parse("1.").is_err());
        assert!(json::parse("1e").is_err());
        assert!(json::parse("\"\\u+041\"").is_err(), "non-hex escape");
        assert!(json::parse("\"\\u04\"").is_err(), "short escape");
    }

    #[test]
    fn json_parser_decodes_escaped_surrogate_pairs() {
        let v = json::parse("{\"e\":\"\\ud83d\\ude00\"}").unwrap();
        assert_eq!(v.get("e").unwrap().as_str(), Some("\u{1F600}"));
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
