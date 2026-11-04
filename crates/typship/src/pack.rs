//! The named Pack abstraction: parsing, detection and transport of pack
//! sources and destinations.
//!
//! New dependencies are limited to the two classes the proposal allows:
//! TLS (`ureq` with rustls) and compression (`flate2`). The tar container
//! itself is encoded and decoded here with the standard library only
//! (ustar headers, plus GNU long-name entries for reading).

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Total per-request timeout; a network path must never hang forever.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
const RETRIES: usize = 5;

/// An HTTP agent with connection and total timeouts.
fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .user_agent("typship")
        .build()
}

/// GET a URL to bytes, retrying transient failures up to [`RETRIES`] times.
fn get_bytes(url: &str) -> Result<Vec<u8>> {
    let mut last = None;
    for _ in 0..RETRIES {
        match agent().get(url).call() {
            Ok(resp) => {
                let mut buf = Vec::new();
                resp.into_reader()
                    .take(512 * 1024 * 1024)
                    .read_to_end(&mut buf)
                    .with_context(|| format!("reading body of {url}"))?;
                return Ok(buf);
            }
            // Permanent client errors are not worth retrying.
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
    /// A URL that resolves to a gzipped tarball (http, git, GitHub,
    /// GitHub release all normalize to this) plus an optional in-archive
    /// subpath (e.g. a GitHub `tree` URL pointing inside the repo).
    Url {
        /// Tarball URL to download.
        url: String,
        /// Subdirectory inside the archive to use, if any.
        subpath: Option<String>,
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
    if is_fs_path(s) {
        // A `*.tar.gz`/`*.tgz` file is transported as a tarball, not a directory.
        let lower = s.to_ascii_lowercase();
        if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
            if !std::path::Path::new(s).is_file() {
                bail!("fs tarball `{s}` is not a file");
            }
            let bytes = fs::read(s).with_context(|| format!("reading tarball {s}"))?;
            return Ok(Source::Tarball(bytes));
        }
        return Ok(Source::Fs(PathBuf::from(s)));
    }
    if let Some(rest) = s.strip_prefix('@') {
        let _ = rest;
        return parse_at(s);
    }
    if !is_http(s) {
        bail!("`{s}` is neither a valid pack (fs path, `-`, `@ns/name`) nor an http(s) URL");
    }
    // git pack: `.../repo.git`
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
        let repo = base.rsplit('/').next().unwrap_or("repo");
        return Ok(Source::Url {
            url: format!("{base}/archive/HEAD/{repo}.tar.gz"),
            subpath: None,
        });
    }
    let host_and_path = s
        .strip_prefix("https://")
        .unwrap_or_else(|| s.strip_prefix("http://").unwrap_or(s));
    let segs: Vec<&str> = host_and_path.split('/').collect();
    // GitHub release pack: github.com/{o}/{r}/releases/[tag|download|tag]/{x}
    if segs.len() >= 4 && segs[0] == "github.com" && segs[3] == "releases" {
        let tag = match segs.get(4).copied().unwrap_or("HEAD") {
            "tag" | "download" => segs.get(5).copied().unwrap_or("HEAD"),
            other => other,
        };
        if tag == "latest" || tag == "HEAD" {
            return Ok(Source::Url {
                url: format!(
                    "https://codeload.github.com/{}/{}/tar.gz/HEAD",
                    segs[1], segs[2]
                ),
                subpath: None,
            });
        }
        return Ok(Source::Url {
            url: format!(
                "https://github.com/{}/{}/archive/refs/tags/{}.tar.gz",
                segs[1], segs[2], tag
            ),
            subpath: None,
        });
    }
    // GitHub directory pack: github.com/{o}/{r}[/tree/{branch}[/subpath]]
    if segs.len() >= 3 && segs[0] == "github.com" {
        let (owner, repo) = (segs[1], segs[2]);
        if segs.len() >= 5 && segs[3] == "tree" {
            let branch = segs[4];
            let subpath = if segs.len() > 5 {
                Some(segs[5..].join("/"))
            } else {
                None
            };
            return Ok(Source::Url {
                url: format!("https://codeload.github.com/{owner}/{repo}/tar.gz/{branch}"),
                subpath,
            });
        }
        return Ok(Source::Url {
            url: format!("https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD"),
            subpath: None,
        });
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
        // to release: github.com/{o}/{r}/releases/{tag}
        if segs.len() >= 5 && segs[0] == "github.com" && segs[3] == "releases" {
            let tag = match segs[4] {
                "tag" | "download" => segs.get(5).copied().unwrap_or("HEAD"),
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

/// Normalize a path: resolve `.` components so external tools
/// (e.g. `mklink`) do not misparse segments like `./name`.
fn dunce_like_absolute(p: &Path) -> PathBuf {
    let text = p.to_string_lossy().to_string();
    let text = if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!("\\{rest}")
    } else if let Some(rest) = text.strip_prefix("\\?\\") {
        rest.to_string()
    } else {
        text
    };
    Path::new(&text)
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect::<PathBuf>()
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
        let home = std::env::var("HOME").map_err(|_| anyhow!("HOME not set"))?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("typst")
            .join("packages"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let home = std::env::var("HOME").map_err(|_| anyhow!("HOME not set"))?;
        Ok(PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("typst")
            .join("packages"))
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

/// GET a URL that must yield a gzipped tarball, retrying when the body
/// is not gzip (truncated or an error page slipped through).
fn get_tarball(url: &str) -> Result<Vec<u8>> {
    let mut last = None;
    for _ in 0..RETRIES {
        match get_bytes(url) {
            Ok(bytes) if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b => {
                return Ok(bytes);
            }
            Ok(_) => last = Some(anyhow!("body of {url} is not gzip")),
            Err(e) => last = Some(e),
        }
    }
    Err(anyhow!(
        "GET {url} failed after {RETRIES} attempts: {}",
        last.unwrap()
    ))
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
            let tmp = temp_dir();
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
    }
}

/// Resolve a registry pack to a tarball download.
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
            // A GitHub repository acting as a packages registry
            // (typst/packages layout: packages/{name}/{version}).
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
            let tmp = temp_dir();
            extract_tarball(&bytes, &tmp, None)?;
            let pkg_base = find_dir(&tmp, &format!("packages/{name}"))
                .ok_or_else(|| anyhow!("package `{name}` not found in registry `{url}`"))?;
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

/// Latest version of a package from `{base}/index.json`.
fn latest_index_version(base: &str, name: &str) -> Result<String> {
    let body = get_bytes(&format!("{}/index.json", base.trim_end_matches('/')))?;
    let text = String::from_utf8_lossy(&body);
    // Minimal scan of the JSON index: find every {"name":"<name>","version":"<v>"}
    // without pulling in a JSON dependency (not allowed by the proposal).
    let needle_name = format!("\"name\":\"{name}\"");
    let mut best: Option<(Vec<u64>, String)> = None;
    let mut from = 0;
    while let Some(pos) = text[from..].find(&needle_name) {
        let abs = from + pos;
        let rest = &text[abs..];
        if let Some(vpos) = rest.find("\"version\":\"") {
            let vstart = abs + vpos + "\"version\":\"".len();
            if let Some(vend_rel) = text[vstart..].find('"') {
                let v = text[vstart..vstart + vend_rel].to_string();
                let nums: Vec<u64> = v
                    .split('.')
                    .map(|p| p.parse::<u64>().unwrap_or(0))
                    .collect();
                if best.as_ref().is_none_or(|(b, _)| nums > *b) {
                    best = Some((nums, v));
                }
            }
        }
        from = abs + needle_name.len();
    }
    best.map(|(_, v)| v)
        .ok_or_else(|| anyhow!("package `{name}` not found in registry index at {base}/index.json"))
}

/// Find a directory named `rel` anywhere below `root` (one level of archive
/// root dir is always present).
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

/// A fresh temporary directory for this process.
fn temp_dir() -> PathBuf {
    let base = std::env::temp_dir();
    let dir = base.join(format!(
        "typship-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    let _ = fs::create_dir_all(&dir);
    dir
}

// ---------------------------------------------------------------------------
// tar (ustar) codec — standard library only.
// ---------------------------------------------------------------------------

/// Parse an octal field, tolerating trailing NULs and spaces.
fn octal(field: &[u8]) -> u64 {
    let s: String = field
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect();
    let s = s.trim();
    let s2 = s.trim_start_matches('0');
    u64::from_str_radix(if s2.is_empty() { "0" } else { s2 }, 8).unwrap_or(0)
}

/// One decoded tar entry.
struct TarEntry {
    /// Path inside the archive (no leading components stripped).
    path: String,
    /// Whether it is a directory.
    is_dir: bool,
    /// File contents (empty for directories).
    data: Vec<u8>,
}

/// Decode a gzipped tarball into entries, handling GNU long names (`L`).
fn decode_tar(gz: &[u8]) -> Result<Vec<TarEntry>> {
    let mut reader = GzDecoder::new(gz);
    let mut entries = Vec::new();
    let mut pending_long_name: Option<String> = None;
    loop {
        let mut header = [0u8; 512];
        let mut read = 0;
        while read < 512 {
            let n = reader.read(&mut header[read..])?;
            if n == 0 {
                break;
            }
            read += n;
        }
        if read < 512 || header.iter().all(|&b| b == 0) {
            break;
        }
        let size = octal(&header[124..136]);
        let typeflag = header[156];
        let mut name = {
            let n: String = header[..100]
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as char)
                .collect();
            let prefix: String = header[345..500]
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as char)
                .collect();
            if prefix.is_empty() {
                n
            } else {
                format!("{prefix}/{n}")
            }
        };
        let mut data = vec![0u8; size as usize];
        reader
            .read_exact(&mut data)
            .context("truncated tar entry")?;
        // Pad to 512 boundary.
        let pad = ((512 - (size % 512)) % 512) as usize;
        if pad > 0 {
            let mut skip = vec![0u8; pad];
            reader.read_exact(&mut skip)?;
        }
        match typeflag {
            b'L' => {
                pending_long_name = Some(
                    data.iter()
                        .take_while(|&&b| b != 0)
                        .map(|&b| b as char)
                        .collect::<String>(),
                );
                continue;
            }
            b'x' | b'g' | b'K' => continue, // pax / long-link metadata: skip
            b'5' => {
                if let Some(ln) = pending_long_name.take() {
                    name = ln;
                }
                entries.push(TarEntry {
                    path: name,
                    is_dir: true,
                    data: Vec::new(),
                });
            }
            _ => {
                if let Some(ln) = pending_long_name.take() {
                    name = ln;
                }
                entries.push(TarEntry {
                    path: name,
                    is_dir: false,
                    data,
                });
            }
        }
    }
    Ok(entries)
}

/// Extract a gzipped tarball into `dest`, keeping only entries under the
/// optional `subpath` (relative to the archive's single root directory).
pub fn extract_tarball(gz: &[u8], dest: &Path, subpath: Option<&str>) -> Result<()> {
    let entries = decode_tar(gz)?;
    // Detect a single common root directory and strip it.
    let roots: Vec<&str> = entries
        .iter()
        .filter_map(|e| e.path.split('/').next())
        .collect();
    let strip_root = match roots.first() {
        Some(r) if !r.is_empty() && roots.iter().all(|x: &&str| x == r) => Some(format!("{r}/")),
        _ => None,
    };
    for e in entries {
        let mut path = e.path.clone();
        if let Some(root) = &strip_root {
            if !path.starts_with(root.as_str()) {
                continue;
            }
            path = path[root.len()..].to_string();
        }
        if path.is_empty() {
            continue;
        }
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

impl TarWriter {
    fn write_entry(&mut self, path: &str, is_dir: bool, data: &[u8]) -> Result<()> {
        let mut header = [0u8; 512];
        let name = if is_dir {
            format!("{path}/")
        } else {
            path.to_string()
        };
        let name_bytes = name.as_bytes();
        if name_bytes.len() > 100 {
            bail!("tar path too long: {path}");
        }
        header[..name_bytes.len()].copy_from_slice(name_bytes);
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
            let tmp = temp_dir();
            extract_tarball(&bytes, &tmp, None)?;
            let inner = find_pack_root(&tmp)?;
            copy_tree(&inner, &path)?;
            let _ = fs::remove_dir_all(&tmp);
        }
        (Materialized::Dir(dir), Dest::Dir(path)) => {
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

/// After extraction, the pack root (strips a single archive root directory).
fn find_pack_root(tmp: &Path) -> Result<PathBuf> {
    let mut entries: Vec<_> = fs::read_dir(tmp)?.collect::<std::io::Result<_>>()?;
    if entries.len() == 1 && entries[0].file_type()?.is_dir() {
        return Ok(entries.remove(0).path());
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
    // Find existing release by tag.
    let existing = agent()
        .get(&format!("{api}/tags/{tag}"))
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    let upload_url = match existing {
        Ok(resp) => {
            let body = resp.into_string().context("reading release response")?;
            extract_json_string(&body, "upload_url")
                .ok_or_else(|| anyhow!("release for tag `{tag}` has no upload_url"))?
        }
        Err(_) => {
            let body = format!(r#"{{"tag_name":"{tag}","name":"{tag}"}}"#);
            let resp = agent()
                .post(&api)
                .set("Authorization", &format!("Bearer {token}"))
                .set("Content-Type", "application/json")
                .send_string(&body)
                .map_err(|e| anyhow!("creating release {tag} on {repo}: {e}"))?;
            let text = resp.into_string().context("reading release response")?;
            extract_json_string(&text, "upload_url")
                .ok_or_else(|| anyhow!("created release has no upload_url"))?
        }
    };
    let upload_url = upload_url.replace("{?name,label}", "");
    agent()
        .post(&format!("{upload_url}?name={asset_name}"))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/gzip")
        .send_bytes(bytes)
        .map_err(|e| anyhow!("uploading asset {asset_name}: {e}"))?;
    Ok(())
}

/// Pull the string value of `key` out of a JSON object without a JSON
/// dependency (not allowed by the proposal).
fn extract_json_string(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let pos = body.find(&needle)?;
    let rest = &body[pos + needle.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
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
        Source::Url { .. } => bail!(
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
    if dst_path.exists() {
        bail!("destination `{}` already exists", dst_path.display());
    }
    if let Some(parent) = dst_path.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(target_os = "windows")]
    {
        if std::os::windows::fs::symlink_dir(&src_dir, &dst_path).is_err() {
            // Without the symlink privilege, fall back to a junction.
            let dst_abs = dst_path.canonicalize().unwrap_or(dst_path.clone());
            let dst_abs = if dst_abs.is_absolute() {
                dunce_like_absolute(&dst_abs)
            } else {
                std::env::current_dir()
                    .map(|c| dunce_like_absolute(&c.join(&dst_abs)))
                    .unwrap_or(dst_abs)
            };
            let src_abs = src_dir
                .canonicalize()
                .map(|p| dunce_like_absolute(&p))
                .unwrap_or_else(|_| src_dir.clone());
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
        std::os::unix::fs::symlink(&src_dir, &dst_path).map_err(|e| {
            anyhow!(
                "symlink {} -> {} failed: {e}",
                dst_path.display(),
                src_dir.display()
            )
        })?;
    }
    Ok(())
}
