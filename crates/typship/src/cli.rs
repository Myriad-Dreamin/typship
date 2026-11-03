//! Command-line interface for typship.
//!
//! Declarative argument parsing and subcommand dispatch via [`palc`].

use std::ffi::OsString;

use anyhow::Result;
use palc::Parser;

use crate::manifest;

/// The usage information printed when no or an unknown command is given.
const USAGE: &str = "typship - A simple package manager for Typst

Usage: typship <COMMAND>

Commands:
  init  Initialize the current directory as a typship package
  help  Print this message

Options:
  -h, --help     Print help
  -V, --version  Print version";

/// The typship command-line interface.
#[derive(Debug, palc::Parser)]
struct Cli {
    /// Print help.
    #[arg(short, long)]
    help: bool,

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
    /// Print the usage message.
    Help,
}

/// Parses the given arguments into a top-level [`Cli`].
fn parse(args: impl Iterator<Item = OsString>) -> palc::Result<Cli> {
    Cli::try_parse_from(args)
}

/// Parses the given arguments and dispatches to the matching subcommand.
pub fn dispatch(args: impl Iterator<Item = OsString>) -> Result<()> {
    match parse(args) {
        Ok(cli) if cli.version => {
            println!("typship {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Ok(cli) if cli.help => {
            println!("{USAGE}");
            Ok(())
        }
        Ok(cli) => match cli.command {
            Some(Command::Init) => manifest::init_current_dir(),
            Some(Command::Help) | None => {
                println!("{USAGE}");
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

    fn parse_str(args: &[&str]) -> palc::Result<Cli> {
        parse(args.iter().map(OsString::from))
    }

    fn dispatch_str(args: &[&str]) -> Result<()> {
        dispatch(args.iter().map(OsString::from))
    }

    // --- Subcommand routing ---

    #[test]
    fn no_arguments_yields_no_subcommand() {
        let cli = parse_str(&["typship"]).unwrap();
        assert!(!cli.help && !cli.version);
        assert!(cli.command.is_none());
    }

    #[test]
    fn routes_to_init() {
        let cli = parse_str(&["typship", "init"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Init)));
        assert!(!cli.help && !cli.version);
    }

    #[test]
    fn routes_to_help_subcommand() {
        let cli = parse_str(&["typship", "help"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Help)));
    }

    // --- Optional flags ---

    #[test]
    fn long_version_flag_is_set() {
        let cli = parse_str(&["typship", "--version"]).unwrap();
        assert!(cli.version);
        assert!(cli.command.is_none());
    }

    #[test]
    fn short_version_flag_is_set() {
        let cli = parse_str(&["typship", "-V"]).unwrap();
        assert!(cli.version);
    }

    #[test]
    fn long_help_flag_is_set() {
        let cli = parse_str(&["typship", "--help"]).unwrap();
        assert!(cli.help);
        assert!(!cli.version);
    }

    #[test]
    fn short_help_flag_is_set() {
        let cli = parse_str(&["typship", "-h"]).unwrap();
        assert!(cli.help);
    }

    #[test]
    fn flags_before_subcommand_are_accepted() {
        let cli = parse_str(&["typship", "--help", "init"]).unwrap();
        assert!(cli.help);
        assert!(matches!(cli.command, Some(Command::Init)));
    }

    // --- Error inputs ---

    #[test]
    fn unknown_command_is_rejected() {
        let err = parse_str(&["typship", "frobnicate"]).unwrap_err();
        assert!(err.to_string().contains("frobnicate"), "{err}");
    }

    #[test]
    fn init_rejects_extra_arguments() {
        let err = parse_str(&["typship", "init", "extra"]).unwrap_err();
        assert!(err.to_string().contains("unexpected argument"), "{err}");
    }

    #[test]
    fn init_rejects_trailing_flags() {
        assert!(parse_str(&["typship", "init", "--version"]).is_err());
    }

    #[test]
    fn help_flag_renders_palc_help() {
        // `--help` after a subcommand falls through to palc's help rendering.
        let err = parse_str(&["typship", "init", "--help"]).unwrap_err();
        let help = err.try_into_help().expect("should be a help error");
        assert!(help.contains("init"), "{help}");
    }

    // --- Dispatch behavior (exit paths) ---

    #[test]
    fn dispatch_no_arguments_prints_usage() {
        assert!(dispatch_str(&["typship"]).is_ok());
    }

    #[test]
    fn dispatch_help_and_version_are_ok() {
        for arg in ["help", "--help", "-h", "--version", "-V"] {
            assert!(dispatch_str(&["typship", arg]).is_ok(), "failed for {arg}");
        }
    }

    #[test]
    fn dispatch_unknown_command_is_rejected() {
        assert!(dispatch_str(&["typship", "frobnicate"]).is_err());
    }

    #[test]
    fn dispatch_init_rejects_extra_arguments() {
        assert!(dispatch_str(&["typship", "init", "extra"]).is_err());
    }
}
