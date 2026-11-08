//! Transports: resolve a [`crate::source::Source`] to bytes or a
//! directory (`materialize`), git cloning with a hard timeout, archive
//! extraction/packing with typst-aligned unpack rules, and the atomic
//! temp-dir/rename placement primitives.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use walkdir::WalkDir;
use serde_json::Value as Json;

use std::path::Component;

use crate::fs::{typst_packages_dir, latest_version_dir};
use crate::http::{fetch_bytes, get_tarball};

/// The manifest that marks the pack root inside an archive.
pub const PACK_MANIFEST: &str = "typst.toml";
use crate::source::{Source, OFFICIAL_REGISTRY};
use crate::github::percent_encode;

/// A source resolved to concrete bytes or a filesystem location.
pub enum Materialized {
    /// A directory on disk: an existing local pack, or a clone in a
    /// temporary directory that removes itself when the transport is
    /// done.
    Dir {
        /// The directory path (inside the guard's temporary directory
        /// when the source was cloned or extracted).
        path: PathBuf,
        /// Owns the self-removing temporary directory, when one backs
        /// `path`.
        #[allow(dead_code)]
        guard: Option<TempDir>,
    },
    /// A gzipped tarball held in memory, with an optional in-archive
    /// subpath to locate when unpacking at the destination.
    Tarball {
        /// The full tarball bytes.
        bytes: Vec<u8>,
        /// Subdirectory inside the archive to use, if any.
        subpath: Option<String>,
    },
}

/// The chain of candidate roots inside an extracted archive: the
/// extraction directory itself plus each directory along a chain of
/// single subdirectories (up to three levels, the GitHub `repo-ref/`
/// wrapper and the repository's own single-child prefixes).
pub fn archive_chain(tmp: &Path) -> Vec<PathBuf> {
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
pub fn locate_subdir(tmp: &Path, sub: &str) -> Option<PathBuf> {
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
pub fn find_in_chain(tmp: &Path, rel: &str) -> Option<PathBuf> {
    archive_chain(tmp)
        .iter()
        .find_map(|root| find_dir(root, rel))
}

/// Resolve a [`Source`] into bytes or a directory.
pub fn materialize(src: &Source, registry: Option<&str>) -> Result<Materialized> {
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
pub fn materialize_github_tree(owner: &str, repo: &str, rest: &[String]) -> Result<Materialized> {
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
pub fn materialize_github_repo(owner: &str, repo: &str) -> Result<Materialized> {
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
pub fn run_git(args: &[String]) -> Result<()> {
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
pub fn git_clone_shallow(url: &str, git_ref: Option<&str>, dest: &Path) -> Result<()> {
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

/// Fetch a GitHub release: resolve the release document through the
/// API, then download its packaged `.tar.gz`/`.tgz` asset.
pub fn materialize_github_release(repo: &str, tag: Option<&str>) -> Result<Materialized> {
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
pub fn release_archive_asset(release: &Json) -> Option<String> {
    release.get("assets")?.as_array()?.iter().find_map(|asset| {
        let url = asset.get("browser_download_url")?.as_str()?;
        let lower = url.to_ascii_lowercase();
        (lower.ends_with(".tar.gz") || lower.ends_with(".tgz")).then(|| url.to_string())
    })
}

/// Resolve a registry pack to a tarball download or a local directory.
pub fn materialize_registry(
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
pub fn latest_official_version(name: &str) -> Result<String> {
    latest_index_version(OFFICIAL_REGISTRY, name)
}

/// Latest version of a package from `{base}/index.json`: fetch the
/// index and hand the text to [`latest_from_index_json`].
pub fn latest_index_version(base: &str, name: &str) -> Result<String> {
    let body = fetch_bytes(&format!("{}/index.json", base.trim_end_matches('/')))?;
    let text = String::from_utf8(body)
        .map_err(|_| anyhow!("registry index at {base}/index.json is not UTF-8"))?;
    latest_from_index_json(&text, name)
        .map_err(|e| anyhow!("reading registry index at {base}/index.json: {e:#}"))
}

/// The greatest version among the entries of a registry index whose
/// `name` matches, parsed as real JSON (the index is an array of
/// objects). Pure so tests exercise the production function directly.
pub fn latest_from_index_json(text: &str, name: &str) -> Result<String> {
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
pub fn find_dir(root: &Path, rel: &str) -> Option<PathBuf> {
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
pub fn temp_suffix() -> String {
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
pub struct TempDir(PathBuf);

impl TempDir {
    /// A temp dir next to `path`'s parent, on the same mount point as
    /// the final destination.
    pub fn next_to(path: &Path, label: &str) -> Result<Self> {
        let dir = path.with_file_name(format!(".typship-tmp-{label}-{}", temp_suffix()));
        fs::create_dir(&dir).with_context(|| format!("creating temp dir {}", dir.display()))?;
        Ok(Self(dir))
    }

    /// A temp dir under the system temporary directory.
    pub fn system(label: &str) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!(".typship-tmp-{label}-{}", temp_suffix()));
        fs::create_dir(&dir).with_context(|| format!("creating temp dir {}", dir.display()))?;
        Ok(Self(dir))
    }

    /// The temporary directory's path.
    pub fn path(&self) -> &Path {
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
pub fn write_tarball_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
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
pub fn move_dir_atomic(from: &Path, to: &Path) -> Result<()> {
    if to.exists() {
        if fs::read_dir(to)?.next().is_some() {
            bail!("destination `{}` exists and is not empty", to.display());
        }
        fs::remove_dir(to).with_context(|| format!("removing empty {}", to.display()))?;
    }
    fs::rename(from, to).with_context(|| format!("moving {} to {}", from.display(), to.display()))
}

/// Recursively copy a directory tree.
pub fn copy_tree(from: &Path, to: &Path) -> Result<()> {
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

/// Locate the pack root inside an extracted archive: the first directory
/// along the chain of single subdirectories (up to three levels) that
/// contains a `typst.toml` manifest. Without a manifest the extracted
/// tree is used as-is, preserving its structure exactly.
pub fn find_pack_root(tmp: &Path) -> Result<PathBuf> {
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
pub fn octal(field: &[u8]) -> Result<u64> {
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

/// Encode the files under `dir` into `builder` (recursively, sorted).
pub fn add_tree(builder: &mut tar::Builder<GzEncoder<Vec<u8>>>, dir: &Path) -> Result<()> {
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
pub fn append_entry(
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
