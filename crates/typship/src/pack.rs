//! The named Pack abstraction: parsing, detection and transport of pack
//! sources and destinations.
//!
//! New dependencies are limited to the two classes the proposal allows:
//! TLS (`ureq` with rustls) and compression (`flate2`). The tar container
//! itself is encoded and decoded here with the standard library only
//! (ustar headers, GNU long-name entries and PAX `path` records for
//! reading, end-of-archive blocks for writing).
//!
//! Safety posture for untrusted archives: member paths are validated (no
//! absolute paths, no `..`, no backslashes, no drive letters), the header
//! checksum is verified, resource budgets bound the number of members and
//! the total unpacked size, and link/device members are rejected outright.

use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Total per-request timeout; a network path must never hang forever.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
/// Attempts per HTTP request for transient failures only (4xx except 429
/// fails immediately).
const RETRIES: usize = 3;
/// Maximum bytes of one HTTP response body we accept.
const MAX_DOWNLOAD: u64 = 512 * 1024 * 1024;
/// Maximum number of members accepted from one archive.
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

/// Read a response body with a hard size cap; an over-long body is an
/// error, never a silent truncation.
fn read_body_capped(reader: impl Read, url: &str) -> Result<Vec<u8>> {
    let mut reader = reader.take(MAX_DOWNLOAD);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut chunk)
            .with_context(|| format!("reading body of {url}"))?;
        if n == 0 {
            return Ok(buf);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() as u64 >= MAX_DOWNLOAD {
            // The cap was reached and there may be more: refuse, don't
            // truncate.
            let mut probe = [0u8; 1];
            if reader.read(&mut probe).context("reading body of {url}")? > 0 {
                bail!(
                    "body of {url} exceeds the {} MiB download limit",
                    MAX_DOWNLOAD / (1024 * 1024)
                );
            }
            return Ok(buf);
        }
    }
}

/// GET a URL to bytes, retrying only transient failures.
fn get_bytes(url: &str) -> Result<Vec<u8>> {
    let mut last = None;
    for attempt in 0..RETRIES {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(500 * attempt as u64));
        }
        match agent().get(url).call() {
            Ok(resp) => return read_body_capped(resp.into_reader(), url),
            // Permanent client errors are not worth retrying; 429 and 5xx are.
            Err(ureq::Error::Status(code, _)) if (400..500).contains(&code) && code != 429 => {
                bail!("GET {url} failed: HTTP {code}");
            }
            Err(e) => last = Some(e),
        }
    }
    Err(anyhow!(
        "GET {url} failed after {RETRIES} attempts: {}",
        last.unwrap()
    ))
}

/// GET a URL that must yield a gzipped tarball. A single request; a
/// non-gzip body is an error, never a reason to re-request.
fn get_tarball(url: &str) -> Result<Vec<u8>> {
    let bytes = get_bytes(url)?;
    if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
        bail!("body of {url} is not a gzipped tarball");
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
    /// is the fallback.
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

/// Parse `@namespace/name[:version]`.
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
        if part.contains('/') || part.contains('\\') || part == ".." {
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
                    .ok_or_else(|| anyhow!("invalid GitHub URL `{s}`"))?,
                it.next()
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
                    let tag = segs
                        .get(5)
                        .copied()
                        .ok_or_else(|| anyhow!("invalid GitHub release URL `{s}`"))?;
                    if tag == "latest" {
                        return Ok(Source::GithubRelease {
                            repo: format!("{owner}/{repo}"),
                            tag: None,
                        });
                    }
                    return Ok(Source::GithubRelease {
                        repo: format!("{owner}/{repo}"),
                        tag: Some(tag.to_string()),
                    });
                }
                Some("latest") => {
                    return Ok(Source::GithubRelease {
                        repo: format!("{owner}/{repo}"),
                        tag: None,
                    });
                }
                Some(tag) => {
                    return Ok(Source::GithubRelease {
                        repo: format!("{owner}/{repo}"),
                        tag: Some(tag.to_string()),
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
                    .get(5)
                    .copied()
                    .ok_or_else(|| anyhow!("invalid GitHub release URL `{s}`"))?,
                "download" => bail!("`{s}` is an asset URL, not an upload target"),
                other => other,
            };
            return Ok(Dest::Release {
                repo: format!("{}/{}", segs[1], segs[2]),
                tag: tag.to_string(),
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

/// Strip `\\?\` / `\\?\UNC\` verbatim prefixes (Windows only).
#[cfg(target_os = "windows")]
fn strip_verbatim(text: String) -> String {
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!("\\{rest}")
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

/// Refuse a copy whose destination is the source or sits inside it (or
/// vice versa); otherwise `copy_tree` recurses into itself. Best-effort
/// alias resolution through canonicalize is included for the side of the
/// pair that already exists.
fn ensure_distinct(src: &Path, dst: &Path) -> Result<()> {
    let s = normalize_absolute(src);
    let d = normalize_absolute(dst);
    if s == d {
        bail!(
            "source and destination are the same directory `{}`",
            src.display()
        );
    }
    if d.starts_with(&s) {
        bail!(
            "destination `{}` is inside source `{}`",
            dst.display(),
            src.display()
        );
    }
    if s.starts_with(&d) {
        bail!(
            "source `{}` is inside destination `{}`",
            src.display(),
            dst.display()
        );
    }
    // Alias check when both ends resolve on disk.
    if let (Ok(sc), Ok(dc)) = (src.canonicalize(), dst.canonicalize()) {
        if sc == dc {
            bail!(
                "source and destination are the same directory `{}`",
                src.display()
            );
        }
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
                .take(MAX_DOWNLOAD)
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
            let found =
                find_dir(&tmp, subpath.as_deref().unwrap_or_default()).ok_or_else(|| {
                    anyhow!(
                        "subpath `{}` not found in archive",
                        subpath.as_deref().unwrap_or_default()
                    )
                })?;
            Ok(Materialized::Dir(found))
        }
        Source::GithubTree { owner, repo, rest } => materialize_github_tree(owner, repo, rest),
        Source::GithubRelease { repo, tag } => materialize_github_release(repo, tag.as_deref()),
    }
}

/// Resolve a GitHub tree URL: the ref may contain slashes, so try
/// interpretations from the longest ref to the shortest one; the first
/// interpretation that yields a gzip archive wins (the requested subpath
/// is then located inside it).
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
                if let Err(e) = extract_tarball(&bytes, &tmp, None) {
                    last_err = Some(e);
                    continue;
                }
                return match find_dir(&tmp, subpath.as_deref().unwrap_or_default()) {
                    Some(dir) => Ok(Materialized::Dir(dir)),
                    None => Err(anyhow!(
                        "subpath `{}` not found in archive of `{}`",
                        subpath.unwrap_or_default(),
                        url
                    )),
                };
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("could not resolve GitHub tree URL")))
}

/// Resolve a GitHub release URL through the API: prefer a `.tar.gz`/`.tgz`
/// asset, fall back to the source archive of the resolved tag.
fn materialize_github_release(repo: &str, tag: Option<&str>) -> Result<Materialized> {
    let api = match tag {
        Some(t) => format!("https://api.github.com/repos/{repo}/releases/tags/{t}"),
        None => format!("https://api.github.com/repos/{repo}/releases/latest"),
    };
    let body = get_bytes(&api)?;
    let text = String::from_utf8_lossy(&body);
    let mut from = 0;
    while let Some(rel) = text[from..].find("\"browser_download_url\"") {
        let abs = from + rel;
        if let Some(url) = json_object_string_field(&text[abs..], "browser_download_url") {
            let lower = url.to_ascii_lowercase();
            if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
                return Ok(Materialized::Tarball(get_tarball(&url)?));
            }
        }
        from = abs + "\"browser_download_url\"".len();
    }
    // No archive asset: fall back to the source archive of the tag.
    let tag_name = json_object_string_field(&text, "tag_name")
        .ok_or_else(|| anyhow!("release lookup for `{repo}` returned no tag_name"))?;
    Ok(Materialized::Tarball(get_tarball(&format!(
        "https://codeload.github.com/{repo}/tar.gz/refs/tags/{tag_name}"
    ))?))
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
        Some(url) if url.contains("github.com") => {
            // A GitHub repository acting as a packages registry, using the
            // standard Typst layout `packages/{namespace}/{name}/{version}`
            // (a legacy flat `packages/{name}` layout is also accepted).
            let rest = url
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .strip_prefix("github.com/")
                .ok_or_else(|| anyhow!("invalid GitHub registry `{url}`"))?;
            let mut it = rest.splitn(2, '/');
            let (owner, repo) = (
                it.next()
                    .ok_or_else(|| anyhow!("invalid GitHub registry `{url}`"))?,
                it.next().unwrap_or_default().trim_end_matches('/'),
            );
            let bytes = get_tarball(&format!(
                "https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD"
            ))?;
            let tmp = temp_dir()?;
            extract_tarball(&bytes, &tmp, None)?;
            let pkg_base = find_dir(&tmp, &format!("packages/{namespace}/{name}"))
                .or_else(|| find_dir(&tmp, &format!("packages/{name}")))
                .ok_or_else(|| {
                    anyhow!("package `{namespace}/{name}` not found in registry `{url}`")
                })?;
            let version = match version {
                Some(v) => v.to_string(),
                None => latest_version_dir(&pkg_base)?
                    .ok_or_else(|| anyhow!("no version of `{name}` in registry `{url}`"))?,
            };
            Ok(Materialized::Dir(pkg_base.join(version)))
        }
        Some(url) => {
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

/// Latest version of a package from `{base}/index.json`. The scan is
/// tolerant of whitespace and of field order: the body is split into
/// object chunks and each chunk is searched for `name` and `version`.
fn latest_index_version(base: &str, name: &str) -> Result<String> {
    let body = get_bytes(&format!("{}/index.json", base.trim_end_matches('/')))?;
    let text = String::from_utf8_lossy(&body);
    let mut best: Option<(Vec<u64>, String)> = None;
    for chunk in text.split('}') {
        if json_object_string_field(chunk, "name").as_deref() != Some(name) {
            continue;
        }
        if let Some(v) = json_object_string_field(chunk, "version") {
            let nums: Vec<u64> = v
                .split('.')
                .map(|p| p.parse::<u64>().unwrap_or(0))
                .collect();
            if best.as_ref().is_none_or(|(b, _)| nums > *b) {
                best = Some((nums, v));
            }
        }
    }
    best.map(|(_, v)| v)
        .ok_or_else(|| anyhow!("package `{name}` not found in registry index at {base}/index.json"))
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

/// Decode archive path bytes: UTF-8 when valid, latin-1 as the fallback
/// so every byte survives the round trip.
fn decode_path(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    }
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
fn pax_path(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if let Some(eq) = line.find(" path=") {
            let digits = &line[..eq];
            if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
                return Some(line[eq + " path=".len()..].to_string());
            }
        }
    }
    None
}

/// Decode a gzipped tarball into entries. Untrusted input: the header
/// checksum is verified, short reads are errors, resource budgets are
/// enforced, and non-regular members are rejected.
fn decode_tar(gz: &[u8]) -> Result<Vec<TarEntry>> {
    let mut reader = GzDecoder::new(gz);
    let mut entries = Vec::new();
    let mut total: u64 = 0;
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
            // Clean end of stream.
            break;
        }
        if read < 512 {
            bail!("truncated tar header");
        }
        if header.iter().all(|&b| b == 0) {
            // End-of-archive marker: what follows must be zero padding
            // only, and the gzip stream must be intact.
            let mut rest = Vec::new();
            reader
                .read_to_end(&mut rest)
                .context("reading tar trailer")?;
            if rest.iter().any(|&b| b != 0) {
                bail!("garbage after end-of-archive marker");
            }
            break;
        }
        let stored = octal(&header[148..156])?;
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
        if size > MAX_MEMBER_SIZE {
            bail!(
                "tar member of {size} bytes exceeds the {} MiB member limit",
                MAX_MEMBER_SIZE / (1024 * 1024)
            );
        }
        if total + size > MAX_TOTAL_UNPACKED {
            bail!(
                "archive exceeds the total unpacked limit of {} MiB",
                MAX_TOTAL_UNPACKED / (1024 * 1024)
            );
        }
        let mut name = {
            let n = decode_path(nul_terminated(&header[..100]));
            let prefix = decode_path(nul_terminated(&header[345..500]));
            if prefix.is_empty() {
                n
            } else {
                format!("{prefix}/{n}")
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
                pending_long_name = Some(decode_path(nul_terminated(&data)));
                continue;
            }
            b'x' => {
                pending_pax_path = pax_path(&data);
                continue;
            }
            b'g' | b'K' => continue,
            b'1' | b'2' => {
                bail!("tar member `{name}` is a hard/symlink; link members are not supported")
            }
            b'3' | b'4' | b'6' => {
                bail!("tar member `{name}` is a device or fifo; not supported")
            }
            b'5' => {
                if let Some(ln) = pending_long_name.take() {
                    name = ln;
                } else if let Some(px) = pending_pax_path.take() {
                    name = px;
                }
                if entries.len() >= MAX_ARCHIVE_ENTRIES {
                    bail!("archive has too many entries (limit {MAX_ARCHIVE_ENTRIES})");
                }
                total += size;
                entries.push(TarEntry {
                    path: name,
                    is_dir: true,
                    data: Vec::new(),
                });
            }
            b'0' | b'\0' | b'7' => {
                if let Some(ln) = pending_long_name.take() {
                    name = ln;
                } else if let Some(px) = pending_pax_path.take() {
                    name = px;
                }
                if entries.len() >= MAX_ARCHIVE_ENTRIES {
                    bail!("archive has too many entries (limit {MAX_ARCHIVE_ENTRIES})");
                }
                total += size;
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

/// Validate an archive member path: it must be relative, slash-separated
/// and stay inside the destination.
fn safe_member_path(path: &str) -> Result<String> {
    if path.is_empty() {
        bail!("empty archive member path");
    }
    if path.starts_with('/') {
        bail!("absolute path `{path}` in archive");
    }
    if path.contains('\\') {
        bail!("backslash in archive path `{path}`");
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        bail!("windows drive letter in archive path `{path}`");
    }
    for comp in path.split('/') {
        if comp == ".." {
            bail!("parent directory component in archive path `{path}`");
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
                self.write_long_name(&name)?;
                let nb = name.as_bytes();
                header[..nb.len().min(100)].copy_from_slice(&nb[..nb.len().min(100)]);
            }
        }
        let mode = if is_dir { b"0000755\0" } else { b"0000644\0" };
        header[100..108].copy_from_slice(mode);
        header[108..116].copy_from_slice(b"0000000\0"); // uid
        header[116..124].copy_from_slice(b"0000000\0"); // gid
        let size_field = format!("{:011o}\0", if is_dir { 0 } else { data.len() });
        header[124..136].copy_from_slice(size_field.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0"); // mtime
        header[148..156].copy_from_slice(b"        "); // checksum placeholder
        header[156] = if is_dir { b'5' } else { b'0' };
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|&b| b as u64).sum::<u64>();
        let cs = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(cs.as_bytes());
        self.out.write_all(&header)?;
        if !is_dir {
            self.out.write_all(data)?;
            let pad = ((512 - (data.len() as u64 % 512)) % 512) as usize;
            if pad > 0 {
                self.out.write_all(&vec![0u8; pad])?;
            }
        }
        Ok(())
    }

    /// Emit a GNU long-name (`L`) entry carrying `name`.
    fn write_long_name(&mut self, name: &str) -> Result<()> {
        let mut data = name.as_bytes().to_vec();
        data.push(0);
        let mut header = [0u8; 512];
        header[..2].copy_from_slice(b"./");
        let size_field = format!("{:011o}\0", data.len());
        header[124..136].copy_from_slice(size_field.as_bytes());
        header[148..156].copy_from_slice(b"        "); // checksum placeholder
        header[156] = b'L';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|&b| b as u64).sum::<u64>();
        let cs = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(cs.as_bytes());
        self.out.write_all(&header)?;
        self.out.write_all(&data)?;
        let pad = ((512 - (data.len() as u64 % 512)) % 512) as usize;
        if pad > 0 {
            self.out.write_all(&vec![0u8; pad])?;
        }
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
        .get(&format!("{api}/tags/{tag}"))
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    let upload_url = match existing {
        Ok(resp) => {
            let body = resp.into_string().context("reading release response")?;
            json_object_string_field(&body, "upload_url")
                .ok_or_else(|| anyhow!("release for tag `{tag}` has no upload_url"))?
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
            json_object_string_field(&text, "upload_url")
                .ok_or_else(|| anyhow!("created release has no upload_url"))?
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

/// Pull the string value of `key` out of a JSON object without a JSON
/// dependency (not allowed by the proposal). Tolerates whitespace around
/// the colon and unescapes the value; returns `None` when the key is
/// absent or its value is not a string.
fn json_object_string_field(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let mut from = 0;
    loop {
        let pos = body[from..].find(&pat)?;
        let rest = body[from + pos + pat.len()..].trim_start();
        let rest = rest.strip_prefix(':')?.trim_start();
        if !rest.starts_with('"') {
            // A non-string value under this key: keep scanning.
            from += pos + pat.len();
            continue;
        }
        let val = &rest[1..];
        let mut out = String::new();
        let mut chars = val.char_indices();
        while let Some((_, c)) = chars.next() {
            match c {
                '"' => return Some(out),
                '\\' => {
                    let (_, esc) = chars.next()?;
                    match esc {
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        'u' => {
                            let hex: String = (0..4)
                                .filter_map(|_| chars.next().map(|(_, c)| c))
                                .collect();
                            let code = u32::from_str_radix(&hex, 16).ok()?;
                            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        }
                        other => out.push(other),
                    }
                }
                c => out.push(c),
            }
        }
        return None;
    }
}

/// Link a named pack from `src` to `dst` instead of copying.
///
/// Both ends must be linkable: a filesystem or local-namespace directory.
/// Any other shape is rejected with a clear error.
pub fn link(src: &str, dst: &str, registry: Option<&str>) -> Result<()> {
    let source = parse_source(src)?;
    let dest = parse_dest(dst)?;
    let src_dir = match &source {
        Source::Fs(p) => {
            if !p.is_dir() {
                bail!("fs pack `{}` is not a directory", p.display());
            }
            p.clone()
        }
        Source::Tarball(_) => {
            bail!("a tarball pack cannot be linked; use `copy` instead")
        }
        Source::Registry {
            namespace,
            name,
            version,
        } if namespace == "local" => {
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
        Source::Registry { namespace, .. } => bail!(
            "cannot link registry pack in namespace `{namespace}`: only fs and @local packs are linkable, use copy instead"
        ),
        Source::Stdin => {
            bail!("cannot link stdin: only fs and @local packs are linkable, use copy instead")
        }
        Source::Url { .. } | Source::GithubTree { .. } | Source::GithubRelease { .. } => bail!(
            "cannot link a remote pack: only fs and @local packs are linkable, use copy instead"
        ),
    };
    let dst_path = match dest {
        Dest::Dir(p) => p,
        Dest::Tarball(_) => {
            bail!("cannot link into a tarball: only directories are linkable, use copy instead")
        }
        Dest::Release { .. } => bail!("cannot link into a GitHub release: use copy instead"),
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
    fn extract_rejects_huge_member_without_oom() {
        // A member claiming 8 GiB must be refused before allocation.
        let mut header = [0u8; 512];
        header[..3].copy_from_slice(b"big");
        let size_field = format!("{:011o}\0", MAX_MEMBER_SIZE + 1);
        header[124..136].copy_from_slice(size_field.as_bytes());
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        let checksum = header.iter().map(|&b| b as u64).sum::<u64>();
        let cs = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(cs.as_bytes());
        let mut raw = Vec::new();
        raw.extend_from_slice(&header);
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&raw).unwrap();
        let gz = enc.finish().unwrap();
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
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&raw).unwrap();
        let gz = enc.finish().unwrap();
        let dest = std::env::temp_dir().join(format!("typship-c-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        assert!(extract_tarball(&gz, &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
        // A symlink member is rejected outright.
        let mut header = [0u8; 512];
        header[..4].copy_from_slice(b"link");
        header[156] = b'2';
        header[148..156].copy_from_slice(b"        ");
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|&b| b as u64).sum::<u64>();
        let cs = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(cs.as_bytes());
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&header).unwrap();
        let gz = enc.finish().unwrap();
        fs::create_dir_all(&dest).unwrap();
        assert!(extract_tarball(&gz, &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
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

        // 3. A single-file directory survives as that file.
        let src = base.join("d");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("main.typ"), "y").unwrap();
        let gz = pack_tarball(&src).unwrap();
        let dst = base.join("b3");
        extract_tarball(&gz, &base.join("t3"), None).unwrap();
        let root = find_pack_root(&base.join("t3")).unwrap();
        copy_tree(&root, &dst).unwrap();
        assert!(dst.join("main.typ").is_file());

        // 4. A wrapper archive: the manifest marks the pack root.
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
        let long = format!("{}.typ", "l".repeat(150));
        fs::write(src.join(&long), "long").unwrap();
        let gz = pack_tarball(&src).unwrap();
        let dst = base.join("b");
        extract_tarball(&gz, &dst, None).unwrap();
        assert_eq!(fs::read(dst.join("中文.typ")).unwrap(), b"hello");
        assert_eq!(fs::read(dst.join(&long)).unwrap(), b"long");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn truncated_and_ungzipped_bodies_are_errors() {
        let gz = gz_of(&[("a.txt", &[0u8; 600])]);
        // Cut the archive short: the entry data cannot be fully read.
        let cut = &gz[..gz.len() - 40];
        let dest = std::env::temp_dir().join(format!("typship-t-{}", std::process::id()));
        fs::create_dir_all(&dest).unwrap();
        assert!(extract_tarball(cut, &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
        // Not gzip at all.
        assert!(extract_tarball(b"plain text", &dest, None).is_err());
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn json_field_extraction_tolerates_spaces_and_escapes() {
        let body = r#"{"upload_url": "https://u/?name=x", "quote": "a\"b", "n": 5}"#;
        assert_eq!(
            json_object_string_field(body, "upload_url").unwrap(),
            "https://u/?name=x"
        );
        assert_eq!(json_object_string_field(body, "quote").unwrap(), "a\"b");
        assert!(json_object_string_field(body, "missing").is_none());
    }

    #[test]
    fn index_scan_is_order_and_space_tolerant() {
        let body = r#"[ {"version": "0.2.0", "name": "foo"} ,{"name":"foo","version":"0.10.0"},{"name":"bar","version":"9.9.9"} ]"#;
        assert_eq!(latest_index_scan(body, "foo").unwrap(), "0.10.0");
        assert!(latest_index_scan(body, "nope").is_err());
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
        // same
        assert!(ensure_distinct(&src, &src).is_err());
        // unrelated: fine
        assert!(ensure_distinct(&src, &base.join("b")).is_ok());
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

    /// Build a gzipped tar from (path, data) pairs through the writer.
    fn gz_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let enc = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = TarWriter { out: enc };
        for (path, data) in entries {
            tar.write_entry(path, false, data).unwrap();
        }
        tar.write_end_blocks().unwrap();
        tar.out.finish().unwrap()
    }

    /// A trimmed re-implementation of the index scan used by tests.
    fn latest_index_scan(body: &str, name: &str) -> Result<String> {
        let mut best: Option<(Vec<u64>, String)> = None;
        for chunk in body.split('}') {
            if json_object_string_field(chunk, "name").as_deref() != Some(name) {
                continue;
            }
            if let Some(v) = json_object_string_field(chunk, "version") {
                let nums: Vec<u64> = v
                    .split('.')
                    .map(|p| p.parse::<u64>().unwrap_or(0))
                    .collect();
                if best.as_ref().is_none_or(|(b, _)| nums > *b) {
                    best = Some((nums, v));
                }
            }
        }
        best.map(|(_, v)| v).ok_or_else(|| anyhow!("not found"))
    }
}
