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

/// Formats the manifest TOML for a package with the given name and version.
fn manifest_toml(name: &str, version: &str) -> String {
    format!(
        "[package]\nname = \"{}\"\nversion = \"{version}\"\nentrypoints = [\"{ENTRYPOINT}\"]\n",
        escape_toml_string(name),
    )
}

/// Escapes a string for use inside a basic TOML string literal.
fn escape_toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
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
        let toml = manifest_toml("example", "0.1.0");
        assert_eq!(
            toml,
            "[package]\nname = \"example\"\nversion = \"0.1.0\"\nentrypoints = [\"lib.typ\"]\n"
        );
    }

    #[test]
    fn manifest_escapes_special_characters() {
        let toml = manifest_toml("ex\"a\\mple", "0.1.0");
        assert!(toml.contains("name = \"ex\\\"a\\\\mple\""));
    }
}
