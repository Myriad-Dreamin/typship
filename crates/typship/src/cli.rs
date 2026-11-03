//! Hand-rolled, zero-dependency command-line parsing and subcommand dispatch.

use std::ffi::OsString;

use anyhow::{bail, Result};

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

/// Parses the given arguments and dispatches to the matching subcommand.
pub fn dispatch(args: impl Iterator<Item = OsString>) -> Result<()> {
    let mut args = args;
    let _program = args.next();
    let Some(arg) = args.next() else {
        println!("{USAGE}");
        return Ok(());
    };

    match arg.to_string_lossy().as_ref() {
        "init" => {
            if let Some(extra) = args.next() {
                bail!(
                    "unexpected argument `{}` for the init command\n\nUsage: typship init",
                    extra.to_string_lossy()
                );
            }
            manifest::init_current_dir()
        }
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        "--version" | "-V" => {
            println!("typship {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => bail!(
            "unrecognized command `{other}`\n\nrun `typship help` for usage information"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dispatch_str(args: &[&str]) -> Result<()> {
        dispatch(args.iter().map(OsString::from))
    }

    #[test]
    fn no_arguments_prints_usage() {
        assert!(dispatch_str(&["typship"]).is_ok());
    }

    #[test]
    fn help_and_version_are_ok() {
        for arg in ["help", "--help", "-h", "--version", "-V"] {
            assert!(dispatch_str(&["typship", arg]).is_ok(), "failed for {arg}");
        }
    }

    #[test]
    fn unknown_command_is_rejected() {
        assert!(dispatch_str(&["typship", "frobnicate"]).is_err());
    }

    #[test]
    fn init_rejects_extra_arguments() {
        assert!(dispatch_str(&["typship", "init", "extra"]).is_err());
    }
}
