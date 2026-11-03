//! # typship
//!
//! A simple package manager for Typst.

mod cli;
mod manifest;

use anyhow::Result;

fn main() -> Result<()> {
    cli::dispatch(std::env::args_os())
}
