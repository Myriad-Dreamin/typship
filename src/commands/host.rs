use std::io::BufWriter;
use std::path::Path;

use anyhow::Context;
use clap::Parser;
use ecow::EcoString;
use serde::{Deserialize, Serialize};

const LONG_ABOUT: &str = "Host the package in a GitHub repository.";

#[derive(Parser)]
#[command(long_about = LONG_ABOUT)]
/// Host the package in a GitHub repository
pub struct HostArgs {
    #[arg(long)]
    /// The packages to host.
    /// Space-separated list of packages to host.
    pub packages: Option<String>,
    #[arg(long)]
    /// The forked repository from typst/packages.
    pub source: Option<String>,
    #[arg(long)]
    /// The path to install the package in the source repository
    pub destination: Option<String>,
}

// if: ${{ fromJson(needs.plan.outputs.val).ci.github.artifacts_matrix.include
// != null && (needs.plan.outputs.publishing == 'true' ||
// fromJson(needs.plan.outputs.val).ci.github.pr_run_mode == 'upload') }}

// runs-on: ${{ matrix.runner }}
// container: ${{ matrix.container && matrix.container.image || null }}
// mkdir -p typst-packages/${{ inputs.destination }}/${{ matrix.package.name }}
// mv ${{ matrix.package.source }} typst-packages/${{ inputs.destination }}/${{
// matrix.package.name }}/${{ matrix.package.version }} name: preview-${{
// matrix.package.name }}-${{ matrix.package.version }} path: typst-packages/${{
// inputs.destination }}/${{ matrix.package.name }}/${{ matrix.package.version
// }} title: "@preview/{{ matrix.package.name }} {{ matrix.package.version }}"

#[derive(Debug, Deserialize, Serialize)]
struct Output {
    ci: Ci,
}

#[derive(Debug, Deserialize, Serialize)]
struct Ci {
    github: CiGitHub,
}

#[derive(Debug, Deserialize, Serialize)]
struct CiGitHub {
    artifacts_matrix: Option<Vec<ArtifactsMatrix>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ArtifactsMatrix {
    runner: String,
    container: Option<Container>,
    package: Package,
}

#[derive(Debug, Deserialize, Serialize)]
struct Container {
    image: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Package {
    source: String,
    name: EcoString,
    version: String,
}

pub fn host(_current_dir: &Path, _args: &HostArgs) -> anyhow::Result<()> {
    let packages = _args.packages.as_deref().unwrap_or("all");
    let mut packages = packages.split_whitespace().collect::<Vec<_>>();
    if packages == ["all"] {
        packages = vec![];
    }

    // find packages in workspace
    let package_dirs = ignore::WalkBuilder::new(".")
        .standard_filters(true)
        .add_custom_ignore_filename(".typstignore")
        .build()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            (entry.path().file_name()? == "typst.toml").then_some(entry)
        })
        .collect::<Vec<_>>();

    let mut tasks = vec![];

    for package in package_dirs {
        // package.path().parent().ok_or_else()
        let package_dir = package.path().parent().ok_or_else(|| {
            anyhow::anyhow!("Package directory not found: {}", package.path().display())
        })?;
        let manifest = crate::utils::read_manifest(package_dir).with_context(|| {
            format!(
                "failed to read the package manifest file: {}",
                package_dir.display()
            )
        })?;
        if !packages.is_empty() && !packages.contains(&manifest.package.name.as_str()) {
            continue;
        }

        tasks.push(ArtifactsMatrix {
            runner: "ubuntu-24.04".to_string(),
            container: None,
            package: Package {
                source: package_dir.display().to_string(),
                name: manifest.package.name,
                version: manifest.package.version.to_string(),
            },
        });
    }

    let output = Output {
        ci: Ci {
            github: CiGitHub {
                artifacts_matrix: Some(tasks),
            },
        },
    };

    let stdout = std::io::stdout().lock();
    let mut writer = BufWriter::new(stdout);
    serde_json::to_writer_pretty(&mut writer, &output)?;

    Ok(())
}
