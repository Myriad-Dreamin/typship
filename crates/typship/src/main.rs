//! # typship
//!
//! A package manager CLI for Typst.

mod cli;
mod pack;

use anyhow::Result;
use cli::Command;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match cli::parse(std::env::args().skip(1))? {
        Command::Copy { src, dst, registry } => pack::copy(&src, &dst, registry.as_deref()),
        Command::Link { src, dst, registry } => pack::link(&src, &dst, registry.as_deref()),
    }
}
