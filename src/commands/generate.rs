use std::path::Path;

use anyhow::Context;
use clap::Parser;

const LONG_ABOUT: &str = "Generate CI that triggers typship to publish the package automatically.";

#[derive(Parser)]
#[command(long_about = LONG_ABOUT)]
/// Publish the package to a certain registry
pub struct GenerateArgs {
    #[arg(long)]
    /// The forked repository from typst/packages.
    pub source: Option<String>,
    #[arg(long)]
    /// The path to install the package in the source repository
    pub destination: Option<String>,
}

pub fn generate(_current_dir: &Path, args: &GenerateArgs) -> anyhow::Result<()> {
    let source = args.source.as_deref().unwrap_or("Myriad-Dreamin/packages");
    let destination = args.destination.as_deref().unwrap_or("packages/preview");

    // .github/workflows/Release.yml
    // This function will handle the generation of the project files.
    println!("Generating project files...");
    std::fs::create_dir_all(".github/workflows").context("Failed to create directory")?;
    std::fs::write(
        ".github/workflows/releast-typst.yml",
        include_str!("generate.yml")
            .replace("\"<<source>>\"", &format!("{source:?}"))
            .replace("\"<<destination>>\"", &format!("{destination:?}")),
    )
    .context("Failed to write Release.yml")?;

    Ok(())
}
