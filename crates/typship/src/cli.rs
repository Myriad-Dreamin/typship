//! Command-line interface for typship.
//!
//! Hand-rolled argument parsing: the proposal limits new dependencies to
//! TLS and compression, so no clap.

use anyhow::{anyhow, bail};

/// A parsed subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `typship copy X Y`: copy a named pack from X to Y.
    Copy {
        /// Source pack.
        src: String,
        /// Destination pack.
        dst: String,
        /// Custom registry base URL, `--registry <url>`.
        registry: Option<String>,
    },
    /// `typship link X Y`: link X to Y instead of copying.
    Link {
        /// Source pack.
        src: String,
        /// Destination pack.
        dst: String,
        /// Custom registry base URL, `--registry <url>`.
        registry: Option<String>,
    },
}

const HELP: &str = "\
typship - a package manager CLI for Typst

USAGE:
    typship copy <SRC> <DST> [--registry <URL>]
    typship link <SRC> <DST> [--registry <URL>]

SRC/DST (named Pack, auto detected by shape):
    ./a, /path/to/a            filesystem pack
    -                          tarball read from stdin
    @local/name[:ver]          local namespace pack
    @preview/name[:ver]        official registry pack
    https://...                tarball / git / GitHub / GitHub release pack

DST may also be:
    ./b.tar.gz                 write a tarball
    https://github.com/o/r/releases/x
                               upload a tarball to a GitHub release
";

/// Parse command-line arguments into a [`Command`].
pub fn parse<I: Iterator<Item = String>>(args: I) -> anyhow::Result<Command> {
    let args: Vec<String> = args.collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{HELP}");
        std::process::exit(0);
    }
    let mut registry = None;
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--registry" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| anyhow!("--registry needs a URL"))?;
                registry = Some(v.clone());
            }
            _ => positional.push(args[i].clone()),
        }
        i += 1;
    }
    let (cmd, rest) = positional.split_first().ok_or_else(|| {
        anyhow!("no subcommand given\n{HELP}")
    })?;
    if rest.len() != 2 {
        bail!("{cmd} needs exactly two arguments: <SRC> <DST>\n{HELP}");
    }
    match cmd.as_str() {
        "copy" => Ok(Command::Copy {
            src: rest[0].clone(),
            dst: rest[1].clone(),
            registry,
        }),
        "link" => Ok(Command::Link {
            src: rest[0].clone(),
            dst: rest[1].clone(),
            registry,
        }),
        other => bail!("unknown subcommand `{other}`\n{HELP}"),
    }
}
