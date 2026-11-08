//! # typship
//!
//! A simple package manager for Typst.

mod cli;
mod download;
mod manifest;
mod pack;

use anyhow::Result;

fn main() -> Result<()> {
    cli::dispatch(std::env::args_os())
}
