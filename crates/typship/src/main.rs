//! # typship
//!
//! A Typst package CLI tool.

mod cli;
mod net;

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(run(&args));
}

fn run(args: &[String]) -> i32 {
    let command = match cli::parse(args) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("error: {message}\n\n{}", cli::HELP);
            return 2;
        }
    };
    match command {
        cli::Command::Help => {
            println!("{}", cli::HELP);
            0
        }
        cli::Command::Version => {
            println!("{}", cli::version_text());
            0
        }
        cli::Command::Download(download) => match download_inner(&download) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        },
    }
}

fn download_inner(download: &cli::Download) -> Result<(), String> {
    let (name, version) = parse_spec(&download.spec)?;
    let mut registry = download
        .registry
        .clone()
        .unwrap_or_else(|| cli::OFFICIAL_REGISTRY.to_string());
    while registry.ends_with('/') {
        registry.pop();
    }
    if !registry.starts_with("http://") && !registry.starts_with("https://") {
        return Err(format!(
            "registry URL must start with http:// or https://, got {registry:?}"
        ));
    }
    let version = match version {
        Some(version) => version,
        None => resolve_latest(&registry, &name)?,
    };
    let url = format!("{registry}/{name}-{version}.tar.gz");
    eprintln!("Downloading {name}:{version} from {url}");
    let payload = net::get(&url).map_err(|e| e.to_string())?;
    let data = if payload.starts_with(&[0x1F, 0x8B]) {
        net::gunzip(&payload).map_err(|e| e.to_string())?
    } else {
        payload
    };
    let dest = cache_dir().join(format!("{name}@{version}"));
    if dest.exists() {
        eprintln!("Overwriting existing {}", dest.display());
        std::fs::remove_dir_all(&dest)
            .map_err(|e| format!("failed to remove {}: {e}", dest.display()))?;
    }
    net::unpack_tar(&data, &dest).map_err(|e| e.to_string())?;
    println!("Downloaded {name}:{version} to {}", dest.display());
    Ok(())
}

/// Splits `name:version` or `name` and validates both parts.
fn parse_spec(spec: &str) -> Result<(String, Option<String>), String> {
    let name = spec.strip_suffix(':').unwrap_or(spec);
    let (name, version) = match name.split_once(':') {
        Some((name, version)) => (name, Some(version)),
        None => (spec, None),
    };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "invalid package name {name:?}: expected lowercase letters, digits and '-'"
        ));
    }
    if let Some(version) = version {
        let ok = !version.is_empty()
            && version.split('.').all(|segment| {
                !segment.is_empty()
                    && segment
                        .chars()
                        .all(|c| c.is_ascii_digit() || c == '-')
            });
        if !ok {
            return Err(format!("invalid version {version:?} in package spec"));
        }
    }
    Ok((name.to_string(), version.map(str::to_string)))
}

/// Fetches the registry index and returns the latest version of `name`.
fn resolve_latest(registry: &str, name: &str) -> Result<String, String> {
    let index_url = format!("{registry}/index.json");
    let index = net::get(&index_url).map_err(|e| e.to_string())?;
    let pairs = net::registry_versions(&index);
    let best = pairs
        .iter()
        .filter(|(entry, _)| entry == name)
        .map(|(_, version)| version.clone())
        .max_by(|a, b| {
            if version_ge(a, b) {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            }
        })
        .ok_or_else(|| {
            format!("package {name:?} not found in registry index {index_url}")
        })?;
    Ok(best)
}

/// Returns `true` when `a` compares greater than or equal to `b` numerically.
fn version_ge(a: &str, b: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.split(|c: char| c == '.' || c == '-')
            .map(|segment| segment.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (va, vb) = (parse(a), parse(b));
    for i in 0..va.len().max(vb.len()) {
        let sa = va.get(i).copied().unwrap_or(0);
        let sb = vb.get(i).copied().unwrap_or(0);
        if sa != sb {
            return sa > sb;
        }
    }
    true
}

/// Resolves the package cache directory.
fn cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("TYPSHIP_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Application Support"))
        .unwrap_or_else(|| PathBuf::from("."));
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".local/share"))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("typship").join("packages")
}
