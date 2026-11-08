//! Command-line interface for typship.
//!
//! Declarative argument parsing and subcommand dispatch via [`palc`].
//! Help text (`-h`/`--help` and the `help` subcommand) is rendered by
//! `palc` itself; only `--version` is handled manually, since `palc`
//! does not implement the `version` attribute yet.

use std::ffi::OsString;

use anyhow::Result;
use palc::Parser;

use crate::{manifest, pack};

/// A simple package manager for Typst.
#[derive(Debug, palc::Parser)]
struct Cli {
    /// Print version.
    #[arg(short = 'V', long)]
    version: bool,

    /// The subcommand to run.
    #[command(subcommand)]
    command: Option<Command>,
}

/// A parsed subcommand.
#[derive(Debug, palc::Subcommand)]
enum Command {
    /// Initialize the current directory as a typship package.
    Init,
    Copy(CopyArgs),
    Link(LinkArgs),
    /// Print the help message.
    Help,
}

/// Copy a named pack from a source to a destination.
#[derive(Debug, palc::Args)]
#[command(long_about = "Copy a named pack from a source to a destination.")]
struct CopyArgs {
    /// The source pack.
    src: String,
    /// The destination pack.
    dst: String,
    /// Base URL of a custom registry.
    #[arg(long)]
    registry: Option<String>,
}

/// Link a source pack to a destination instead of copying.
#[derive(Debug, palc::Args)]
#[command(long_about = "Link a source pack to a destination instead of copying.")]
struct LinkArgs {
    /// The source pack.
    src: String,
    /// The destination pack.
    dst: String,
    /// Base URL of a custom registry.
    #[arg(long)]
    registry: Option<String>,
}

/// Renders the top-level help message via `palc`.
fn render_help() -> String {
    Cli::render_long_help("typship")
}

/// Parses the given arguments and dispatches to the matching subcommand.
pub fn dispatch(args: impl Iterator<Item = OsString>) -> Result<()> {
    match Cli::try_parse_from(args) {
        Ok(cli) if cli.version => {
            println!("typship {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Ok(cli) => match cli.command {
            Some(Command::Init) => manifest::init_current_dir(),
            Some(Command::Copy(args)) => pack::copy(&args.src, &args.dst, args.registry.as_deref()),
            Some(Command::Link(args)) => pack::link(&args.src, &args.dst, args.registry.as_deref()),
            Some(Command::Help) | None => {
                println!("{}", render_help());
                Ok(())
            }
        },
        Err(err) => match err.try_into_help() {
            Ok(help) => {
                println!("{help}");
                Ok(())
            }
            Err(err) => Err(err.into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dispatch_str(args: &[&str]) -> Result<()> {
        dispatch(args.iter().map(OsString::from))
    }

    #[test]
    fn no_arguments_prints_help() {
        assert!(dispatch_str(&["typship"]).is_ok());
    }

    #[test]
    fn help_and_version_are_ok() {
        for arg in ["help", "--help", "-h", "--version", "-V"] {
            assert!(dispatch_str(&["typship", arg]).is_ok(), "failed for {arg}");
        }
    }

    #[test]
    fn help_is_rendered_by_palc() {
        let help = render_help();
        assert!(help.contains("Usage: typship"), "{help}");
        assert!(help.contains("init"), "{help}");
        assert!(help.contains("--version"), "{help}");
    }

    #[test]
    fn unknown_command_is_rejected() {
        let err = Cli::try_parse_from(["typship", "frobnicate"]).unwrap_err();
        assert!(err.to_string().contains("frobnicate"), "{err}");
        assert!(dispatch_str(&["typship", "frobnicate"]).is_err());
    }

    #[test]
    fn init_rejects_extra_arguments() {
        assert!(dispatch_str(&["typship", "init", "extra"]).is_err());
    }
}
