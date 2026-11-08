//! The typst package manifest (`typst.toml`) and the package skeleton.
//!
//! Manifest output is formatted by hand with the standard library only — no
//! external dependencies beyond the `anyhow` already shipped with the skeleton.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// The file name of the typst package manifest.
const MANIFEST_FILE: &str = "typst.toml";

/// The default package version assigned to a newly initialized package.
const DEFAULT_VERSION: &str = "0.1.0";

/// The package entrypoint generated into the skeleton.
const ENTRYPOINT: &str = "lib.typ";

/// Initializes the current working directory as a typship package.
///
/// The package name defaults to the directory name and the version to
/// [`DEFAULT_VERSION`]. Refuses to touch a directory that is not empty.
pub fn init_current_dir() -> Result<()> {
    let cwd = std::env::current_dir().context("failed to read the current directory")?;
    let name = cwd
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "untitled".to_string());
    init_dir(&cwd, &name)
}

/// Initializes `dir` as a typship package named `name`.
fn init_dir(dir: &Path, name: &str) -> Result<()> {
    if fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?
        .next()
        .is_some()
    {
        bail!("refusing to initialize: {} is not empty", dir.display());
    }

    let manifest = dir.join(MANIFEST_FILE);
    fs::write(&manifest, manifest_toml(name, DEFAULT_VERSION))
        .with_context(|| format!("failed to write {}", manifest.display()))?;

    fs::write(dir.join(ENTRYPOINT), entrypoint_source(name))
        .with_context(|| format!("failed to write {}", dir.join(ENTRYPOINT).display()))?;

    let src = dir.join("src");
    fs::create_dir(&src).with_context(|| format!("failed to create {}", src.display()))?;
    fs::write(src.join(ENTRYPOINT), "")
        .with_context(|| format!("failed to write {}", src.join(ENTRYPOINT).display()))?;

    println!("initialized typship package `{name}` in {}", dir.display());
    println!("  {MANIFEST_FILE}");
    println!("  {ENTRYPOINT}");
    println!("  src/{ENTRYPOINT}");
    Ok(())
}

/// The `[package]` table of a generated `typst.toml` manifest; string
/// escaping is delegated to the `toml` crate during serialization.
#[derive(serde::Serialize)]
struct PackageManifest<'a> {
    name: &'a str,
    version: &'a str,
    entrypoints: [&'a str; 1],
}

/// The whole generated `typst.toml` document.
#[derive(serde::Serialize)]
struct ManifestDocument<'a> {
    package: PackageManifest<'a>,
}

/// Formats the manifest TOML for a package with the given name and version.
fn manifest_toml(name: &str, version: &str) -> String {
    toml::to_string(&ManifestDocument {
        package: PackageManifest {
            name,
            version,
            entrypoints: [ENTRYPOINT],
        },
    })
    .expect("manifest serialization cannot fail")
}

/// Formats the content of the generated root entrypoint.
fn entrypoint_source(name: &str) -> String {
    format!("// {name}\n#import \"src/lib.typ\"\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_contains_expected_fields() {
        let doc = manifest_toml("example", "0.1.0");
        assert_eq!(
            doc,
            "[package]\nname = \"example\"\nversion = \"0.1.0\"\nentrypoints = [\"lib.typ\"]\n"
        );
    }

    #[test]
    fn manifest_escapes_special_characters() {
        let doc = manifest_toml("ex\"a\\mple", "0.1.0");
        // Round-trip through the crate parser: the name must come back
        // verbatim whatever escape style the serializer picked.
        let parsed: toml::Table = toml::from_str(&doc).unwrap();
        assert_eq!(parsed["package"]["name"].as_str(), Some("ex\"a\\mple"));
    }

    #[test]
    fn manifest_escapes_control_characters() {
        let doc = manifest_toml("ex\ra\x07mple", "0.1.0");
        // Control characters must be escaped, never emitted raw (the old
        // hand-written escaper let raw CR through, producing invalid TOML).
        assert!(!doc.bytes().any(|b| b == b'\r' || b == 0x07));
        let parsed: toml::Table = toml::from_str(&doc).unwrap();
        assert_eq!(parsed["package"]["name"].as_str(), Some("ex\ra\x07mple"));
    }
}
