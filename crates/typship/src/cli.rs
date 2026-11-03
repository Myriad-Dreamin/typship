//! Command line parsing for typship.

use std::fmt::Write as _;

/// The official Typst package registry base URL.
pub const OFFICIAL_REGISTRY: &str = "https://packages.typst.org/preview";

/// A parsed command line invocation.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// Print help text.
    Help,
    /// Print the version.
    Version,
    /// Download a package into the local cache.
    Download(Download),
}

/// Arguments of the `download` command.
#[derive(Debug, Clone, PartialEq)]
pub struct Download {
    /// Package spec: `name` or `name:version`.
    pub spec: String,
    /// Registry base URL overriding the official one.
    pub registry: Option<String>,
}

/// Parses command line arguments, returning a usage error message on failure.
pub fn parse(args: &[String]) -> Result<Command, String> {
    let mut iter = args.iter();
    let Some(first) = iter.next() else {
        return Ok(Command::Help);
    };
    match first.as_str() {
        "-h" | "--help" | "help" => return Ok(Command::Help),
        "-V" | "--version" | "version" => return Ok(Command::Version),
        "download" => {}
        other => return Err(format!("unknown command {other:?}")),
    }
    let mut download = Download {
        spec: String::new(),
        registry: None,
    };
    let mut positional = 0;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--registry" => {
                let Some(url) = iter.next() else {
                    return Err("--registry requires a URL argument".to_string());
                };
                download.registry = Some(url.clone());
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option {other:?}"));
            }
            other => {
                positional += 1;
                if positional > 1 {
                    return Err("download takes exactly one package spec".to_string());
                }
                download.spec = other.to_string();
            }
        }
    }
    if positional != 1 {
        return Err("download takes exactly one package spec".to_string());
    }
    Ok(Command::Download(download))
}

/// The `-h` / `help` output.
pub const HELP: &str = "typship - a Typst package CLI tool

USAGE:
    typship <COMMAND> [OPTIONS]

COMMANDS:
    download <name[:version]>    Download a package into the local cache
    help                         Print this help text
    version                      Print the version

OPTIONS (download):
    --registry <url>             Use a custom registry base URL instead of
                                 the official Typst package registry

DOWNLOAD:
    The package spec is either `name` (resolves the latest version via the
    registry index) or `name:version` for an exact version.

    Packages are fetched from <registry>/{name}-{version}.tar.gz and unpacked
    into the cache directory as <cache>/{name}@{version}. Re-downloading an
    already cached version overwrites the existing directory.

    The cache directory defaults to:
      Windows:  %LOCALAPPDATA%\\typship\\packages
      Linux:    ~/.local/share/typship/packages
      macOS:    ~/Library/Application Support/typship/packages
    and can be overridden with the TYPSHIP_CACHE_DIR environment variable.

    Every network request has a 10 second connect timeout and a 60 second
    total timeout. Failures exit with a non-zero status and print the URL
    and the reason.";

/// Renders the `version` output.
pub fn version_text() -> String {
    let mut text = String::new();
    let _ = write!(text, "typship {}", env!("CARGO_PKG_VERSION"));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_download_with_registry() {
        let cmd = parse(&args(&["download", "example:0.1.0", "--registry", "http://x"])).unwrap();
        assert_eq!(
            cmd,
            Command::Download(Download {
                spec: "example:0.1.0".to_string(),
                registry: Some("http://x".to_string()),
            })
        );
    }

    #[test]
    fn rejects_missing_spec() {
        assert!(parse(&args(&["download"])).is_err());
    }

    #[test]
    fn help_and_version_flags() {
        assert_eq!(parse(&args(&[])), Ok(Command::Help));
        assert_eq!(parse(&args(&["-h"])), Ok(Command::Help));
        assert_eq!(parse(&args(&["--version"])), Ok(Command::Version));
        assert!(parse(&args(&["frobnicate"])).is_err());
    }
}
