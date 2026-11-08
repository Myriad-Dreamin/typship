//! The `copy` and `link` transports: parse both ends, materialize the
//! source, and place it at the destination — atomically for directories,
//! via upload for GitHub releases, and by symlink (junction fallback on
//! Windows) when both ends of a link are linkable.

use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use dunce;

use crate::fs::{typst_packages_dir, latest_version_dir, ensure_distinct, absolute_lexical};
use crate::source::{parse_source, Source};
use crate::dest::{parse_dest, Dest};
use crate::transport::{materialize, Materialized, pack_tarball, write_tarball_atomic, copy_tree, extract_tarball, find_pack_root, locate_subdir, TempDir, move_dir_atomic};
use crate::github::upload_release_asset;

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
