//! Path helpers shared by the pack sources and destinations: shape
//! detection (`is_http` / `is_fs_path`), lexically-clean absolutes,
//! physical resolution through existing ancestors, component-wise path
//! comparison, the source/destination distinctness contract, and the
//! per-user Typst packages directory with its version picking.

use std::borrow::Cow;
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

/// Whether `s` is an http(s) URL by prefix.
pub fn is_http(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Whether `s` names a filesystem path by shape: a `.`/`..` prefix, an
/// absolute (or Windows-rooted) path, or a drive-letter path.
pub fn is_fs_path(s: &str) -> bool {
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

/// Make `p` absolute (against the current directory when needed) and
/// lexically cleaned, via the path-clean crate.
pub fn absolute_lexical(p: &Path) -> PathBuf {
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
pub fn physical(p: &Path) -> PathBuf {
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
pub fn comp_key(c: Component<'_>) -> Cow<'_, str> {
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

/// Component-wise path equality; case-insensitive on Windows.
pub fn same_path(a: &Path, b: &Path) -> bool {
    a.components()
        .map(comp_key)
        .eq(b.components().map(comp_key))
}

/// Whether `child` equals `parent` or sits below it, component-wise.
pub fn is_prefix(child: &Path, parent: &Path) -> bool {
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
pub fn ensure_distinct(src: &Path, dst: &Path) -> Result<()> {
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
pub fn typst_packages_dir() -> Result<PathBuf> {
    let base =
        dirs::data_dir().ok_or_else(|| anyhow!("cannot determine the per-user data directory"))?;
    Ok(base.join("typst").join("packages"))
}

/// Pick the greatest version-like directory name under `dir`.
pub fn latest_version_dir(dir: &Path) -> Result<Option<String>> {
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
