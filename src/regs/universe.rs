/// Typst Official Package Registry: Universeuse anyhow::anyhow;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{LazyLock, OnceLock};

use anyhow::{anyhow, bail, Result};
use clap::ValueEnum;
use crossterm::style::Stylize;
use dialoguer::{Confirm, Input};
use futures_util::TryStreamExt;
use log::{info, warn};
use octocrab::models::pulls::PullRequest;
use octocrab::models::repos::{ContentItems, Object};
use octocrab::{params, Octocrab, Page};
use regex::Regex;
use secrecy::SecretString;
use std::process::Command;
use tempfile::TempDir;
use typst_syntax::package::{PackageManifest, PackageVersion};

use crate::config::CONFIG;
use crate::utils::walkers::walker_publish;
use crate::utils::{config_file, save_config};

// pub const UNIVERSE_REPO_ID: RepositoryId =
// RepositoryId::from("R_kgDOJ0PIWA");
pub const UNIVERSE_REPO_NAME: &str = "packages";
pub const UNIVERSE_REPO_OWNER: &str = "typst";

/// Unauthorized client for public access
pub static PUBLIC_CLIENT: LazyLock<Octocrab> =
    LazyLock::new(|| Octocrab::builder().build().unwrap());

pub static AUTH_CLIENT: OnceLock<Octocrab> = OnceLock::new();

pub fn get_authenticated_client() -> Result<&'static Octocrab> {
    // TODO: better secret management
    // TODO: Lock retry?
    let token = CONFIG
        .try_lock()?
        .tokens
        .universe
        .clone()
        .ok_or(anyhow::anyhow!(
            "You need to set up the token first. Run `typship login universe`."
        ))?;
    let token = SecretString::from(token);
    Ok(AUTH_CLIENT.get_or_init(|| Octocrab::builder().personal_token(token).build().unwrap()))
}

/// Get the list of package names under `packages/preview` directory in the
/// official Universe (GitHub) registry.
pub async fn packages() -> Result<ContentItems> {
    Ok(PUBLIC_CLIENT
        .repos(UNIVERSE_REPO_OWNER, UNIVERSE_REPO_NAME)
        .get_content()
        .path("packages/preview")
        .r#ref("main")
        .send()
        .await?)
}

/// Get the list of package versions under `packages/preview/{package_name}`
/// directory in the official Universe (GitHub) registry.
pub async fn package_versions(package_name: &str) -> Result<ContentItems> {
    Ok(PUBLIC_CLIENT
        .repos(UNIVERSE_REPO_OWNER, UNIVERSE_REPO_NAME)
        .get_content()
        .path(format!("packages/preview/{package_name}"))
        .r#ref("main")
        .send()
        .await?)
}

/// Get the list of *OPEN* pull requests in the official Universe (GitHub)
/// registry.
pub async fn pending_list() -> Result<Page<PullRequest>> {
    Ok(PUBLIC_CLIENT
        .pulls(UNIVERSE_REPO_OWNER, UNIVERSE_REPO_NAME)
        .list()
        .state(octocrab::params::State::Open)
        .send()
        .await?)
}

pub fn login() -> Result<()> {
    let overwrite = if CONFIG.try_lock()?.tokens.universe.is_some() {
        info!("Already logged in to the Universe registry");
        dialoguer::Confirm::new()
            .with_prompt("Do you want to overwrite the existing token?")
            .default(false)
            .interact()?
    } else {
        true
    };
    if !overwrite {
        return Ok(());
    }
    let token = dialoguer::Password::new()
        .with_prompt(r#"
Please create and get a `fine-grained token` from https://github.com/settings/personal-access-tokens/new.
You must grant the "Contents", "Workflows", and "Pull requests" permission of the typst/packages forks to the token.
Enter your GitHub personal access token
"#.trim())
        .interact()?;
    CONFIG.try_lock()?.tokens.universe = Some(token);
    if let Ok(cfg) = CONFIG.try_lock() {
        save_config(&cfg)?;
    } else {
        anyhow::bail!("Failed to save the configuration file");
    }
    info!("Your token has been saved to {}", config_file().display());
    Ok(())
}

pub async fn publish(manifest: &PackageManifest, package_dir: &Path, dry_run: bool) -> Result<()> {
    // 1. create PR
    // 2. watch PR state.

    todo!()
}
