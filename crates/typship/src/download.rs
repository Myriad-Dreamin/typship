//! The `typship download` command: fetch a package from a registry into
//! the local cache.
//!
//! Transport, unpacking and placement are entirely the named Pack
//! implementation ([`typship_pack`]): download is `copy` of a
//! `@preview/...` pack into the cache directory. That inherits the
//! network red-line (10 s connect / 120 s total per request, never
//! hangs) and the typst-style atomic placement (unpack into a temp dir
//! next to the destination, then `rename` into place) — no local HTTP,
//! gunzip or tar code remains.

use std::path::PathBuf;

use anyhow::{Context, Result};

use typship_pack::copy as pack;

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
    let (name, version) = split_spec(&download.spec)?;
    let cache = cache_dir()?;
    let dest = pack::download(
        &name,
        version.as_deref(),
        download.registry.as_deref(),
        &cache,
    )?;
    println!("Downloaded {name} to {}", dest.display());
    Ok(())
}

/// Splits `name:version` or `name` (a trailing `:` means no version);
/// name and version are validated by the pack layer ([`pack::download`]).
fn split_spec(spec: &str) -> Result<(String, Option<String>)> {
    let (name, version) = match spec.strip_suffix(':') {
        Some(name) => (name, None),
        None => match spec.split_once(':') {
            Some((name, version)) => (name, Some(version)),
            None => (spec, None),
        },
    };
    if name.is_empty() {
        anyhow::bail!("invalid package spec `{spec}`: empty name");
    }
    Ok((name.to_string(), version.map(str::to_string)))
}

/// Resolves the package cache directory: `TYPSHIP_CACHE_DIR` wins,
/// otherwise the user data directory (`dirs::data_dir()`, i.e.
/// `%APPDATA%` on Windows — the same data-vs-cache distinction the
/// official typst packages dir uses).
fn cache_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("TYPSHIP_CACHE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let base = dirs::data_dir().context("could not determine the user data directory")?;
    Ok(base.join("typship").join("packages"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(spec: &str) -> (String, Option<String>) {
        split_spec(spec).unwrap()
    }

    #[test]
    fn split_spec_accepts_name_and_version() {
        assert_eq!(
            split("example:0.1.0"),
            ("example".into(), Some("0.1.0".into()))
        );
        assert_eq!(split("example"), ("example".into(), None));
        assert_eq!(split("example:"), ("example".into(), None));
    }

    #[test]
    fn cache_dir_honors_the_override() {
        let dir = std::env::temp_dir().join("typship-cache-override-test");
        // Safety: test-only env mutation, no other threads read this
        // variable during the test binary run.
        unsafe {
            std::env::set_var("TYPSHIP_CACHE_DIR", &dir);
            assert_eq!(cache_dir().unwrap(), dir);
            std::env::remove_var("TYPSHIP_CACHE_DIR");
        }
    }
}
