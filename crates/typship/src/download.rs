//! The `typship download` command: fetch a package from a registry into
//! the local cache.
//!
//! The network layer ([`crate::net`]) enforces mandatory timeouts; a
//! network path must fail fast, never hang.

use std::path::PathBuf;

use anyhow::{Context, Result};

/// The official Typst package registry base URL.
pub const OFFICIAL_REGISTRY: &str = "https://packages.typst.org/preview";

/// A parsed `download` invocation.
#[derive(Debug)]
pub struct Download {
    /// Package spec: `name` or `name:version`.
    pub spec: String,
    /// Registry base URL overriding the official one.
    pub registry: Option<String>,
}

/// Runs the download command.
pub fn run(download: &Download) -> Result<()> {
    let (name, version) = parse_spec(&download.spec)?;
    let mut registry = download
        .registry
        .clone()
        .unwrap_or_else(|| OFFICIAL_REGISTRY.to_string());
    while registry.ends_with('/') {
        registry.pop();
    }
    if !registry.starts_with("http://") && !registry.starts_with("https://") {
        anyhow::bail!("registry URL must start with http:// or https://, got {registry:?}");
    }
    let version = match version {
        Some(version) => version,
        None => resolve_latest(&registry, &name)?,
    };
    let url = format!("{registry}/{name}-{version}.tar.gz");
    eprintln!("Downloading {name}:{version} from {url}");
    let payload = crate::net::get(&url)?;
    let data = if payload.starts_with(&[0x1F, 0x8B]) {
        crate::net::gunzip(&payload)?
    } else {
        payload
    };
    let dest = cache_dir().join(format!("{name}@{version}"));
    if dest.exists() {
        eprintln!("Overwriting existing {}", dest.display());
        std::fs::remove_dir_all(&dest)
            .with_context(|| format!("failed to remove {}", dest.display()))?;
    }
    crate::net::unpack_tar(&data, &dest)?;
    println!("Downloaded {name}:{version} to {}", dest.display());
    Ok(())
}

/// Splits `name:version` or `name` and validates both parts.
fn parse_spec(spec: &str) -> Result<(String, Option<String>)> {
    let name = spec.strip_suffix(':').unwrap_or(spec);
    let (name, version) = match name.split_once(':') {
        Some((name, version)) => (name, Some(version)),
        None => (spec, None),
    };
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        anyhow::bail!("invalid package name {name:?}: expected lowercase letters, digits and '-'");
    }
    if let Some(version) = version {
        let ok = !version.is_empty()
            && version.split('.').all(|segment| {
                !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit() || c == '-')
            });
        if !ok {
            anyhow::bail!("invalid version {version:?} in package spec");
        }
    }
    Ok((name.to_string(), version.map(str::to_string)))
}

/// Fetches the registry index and returns the latest version of `name`.
fn resolve_latest(registry: &str, name: &str) -> Result<String> {
    let index_url = format!("{registry}/index.json");
    let index = crate::net::get(&index_url)?;
    let pairs = crate::net::registry_versions(&index);
    let best = pairs
        .iter()
        .filter(|(entry, _)| entry == name)
        .map(|(_, version)| version.clone())
        .max_by(|a, b| {
            if version_ge(a, b) {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            }
        })
        .ok_or_else(|| {
            anyhow::anyhow!("package {name:?} not found in registry index {index_url}")
        })?;
    Ok(best)
}

/// Returns `true` when `a` compares greater than or equal to `b` numerically.
fn version_ge(a: &str, b: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.split(['.', '-'])
            .map(|segment| segment.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (va, vb) = (parse(a), parse(b));
    for i in 0..va.len().max(vb.len()) {
        let sa = va.get(i).copied().unwrap_or(0);
        let sb = vb.get(i).copied().unwrap_or(0);
        if sa != sb {
            return sa > sb;
        }
    }
    true
}

/// Resolves the package cache directory.
fn cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("TYPSHIP_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Application Support"))
        .unwrap_or_else(|| PathBuf::from("."));
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".local/share"))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("typship").join("packages")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_spec_accepts_name_and_version() {
        assert_eq!(
            parse_spec("example:0.1.0").unwrap(),
            ("example".to_string(), Some("0.1.0".to_string()))
        );
        assert_eq!(
            parse_spec("example").unwrap(),
            ("example".to_string(), None)
        );
    }

    #[test]
    fn parse_spec_rejects_bad_names_and_versions() {
        assert!(parse_spec("Bad_Name").is_err());
        assert!(parse_spec("example:abc").is_err());
        assert!(parse_spec("example:").is_err());
    }

    #[test]
    fn version_ge_compares_numerically() {
        assert!(version_ge("0.10.0", "0.9.1"));
        assert!(!version_ge("0.9.1", "0.10.0"));
        assert!(version_ge("1.0", "1.0"));
    }
}
