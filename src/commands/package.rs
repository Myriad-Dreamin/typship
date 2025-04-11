use std::io::Write;
use std::{os::unix::ffi::OsStrExt, str::FromStr};

use clap::{Parser, Subcommand};
use typst_syntax::package::PackageSpec;

use crate::utils::typst_local_dir;

#[derive(Subcommand, Clone)]
pub enum PackageCommands {
    /// Lists packages
    #[command(name = "list", alias = "ls")]
    List(PackageListArgs),
    /// Gets directory to a package location
    #[command(name = "path")]
    Path(PackagePathArgs),
}

#[derive(Parser, Clone)]
/// List packages
pub struct PackageListArgs {
    /// Filter by namespace
    #[clap(short, long, default_value = "preview")]
    pub namespace: String,
    /// Name Pattern
    #[clap(default_value = "")]
    pub name: String,
    /// Only prints the package ID
    #[clap(long)]
    pub id: bool,
    /// Only prints first line
    #[clap(long)]
    pub first: bool,
}

pub fn package_main(commands: PackageCommands) -> anyhow::Result<()> {
    match commands {
        PackageCommands::List(args) => package_list(args),
        PackageCommands::Path(args) => package_cd(args),
    }
}

pub fn package_list(args: PackageListArgs) -> anyhow::Result<()> {
    let mut results = Vec::new();

    let namespace = args.namespace;
    let name = args.name;

    for ns in typst_local_dir().read_dir()? {
        let ns = ns?;
        if !ns.file_type()?.is_dir() || ns.file_name().as_bytes().starts_with(b".") {
            continue;
        }
        let pkg_ns = ns.file_name();
        let pkg_ns = pkg_ns.to_string_lossy();
        if !namespace.is_empty() && pkg_ns != namespace {
            continue;
        }

        for pkg in ns.path().read_dir()? {
            let pkg = pkg?;
            if !pkg.file_type()?.is_dir() || pkg.file_name().as_bytes().starts_with(b".") {
                continue;
            }

            let pkg_name = pkg.file_name();
            let pkg_name = pkg_name.to_string_lossy();
            if !name.is_empty() && !pkg_name.contains(&name) {
                continue;
            }

            for version in pkg.path().read_dir()? {
                let version = version?;
                if !version.file_type()?.is_dir()
                    || version.file_name().as_bytes().starts_with(b".")
                {
                    continue;
                }

                let spec = format!(
                    "@{pkg_ns}/{}:{}",
                    pkg.file_name().to_string_lossy(),
                    version.file_name().to_string_lossy()
                );

                let Ok(res) = PackageSpec::from_str(&spec) else {
                    continue;
                };

                results.push((res, version.metadata().and_then(|m| m.created())));
            }
        }
    }

    results.sort_by(|(a, _), (b, _)| {
        a.namespace
            .cmp(&b.namespace)
            .then(a.name.cmp(&b.name))
            .then(a.version.cmp(&b.version).reverse())
    });

    if args.first {
        results = results.into_iter().take(1).collect();
    }

    if args.id {
        let result = results
            .iter()
            .map(|(res, _)| res.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        writeln!(std::io::stdout().lock(), "{result}")?;
        return Ok(());
    }

    let mut table = vec![];

    table.push("Package\tNamespace\tCreated".to_owned());
    for (res, time) in results {
        let ago = time.map(time_ago).unwrap_or_else(|_| "unknown".to_string());
        let PackageSpec {
            name,
            version,
            namespace,
        } = res;
        table.push(format!("{name}:{version}\t@{namespace}\t{ago}"));
    }

    let table = table
        .iter()
        .map(|s| s.split('\t').collect::<Vec<_>>())
        .collect::<Vec<_>>();

    check_table(&table, table[0].len())?;

    let mut max_width = vec![0; table[0].len()];
    for row in table.iter() {
        for (i, s) in row.iter().enumerate() {
            max_width[i] = max_width[i].max(s.len());
        }
    }

    let table = table
        .iter()
        .map(|row| {
            row.iter()
                .enumerate()
                .map(|(i, s)| format!("{s: <width$}", width = max_width[i]))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n");

    writeln!(std::io::stdout().lock(), "{table}")?;

    Ok(())
}

/// Gets directory to a package location
#[derive(Parser, Clone)]
pub struct PackagePathArgs {
    // todo: cache/data directory (default to the first hit directory)
    /// The namespace to change to
    /// ## Example
    /// ```example
    /// cd "$(typship pkg path @preview)"
    /// cd "$(typship pkg path @preview/example)"
    /// cd "$(typship pkg path @preview/example:0.1.0)"
    /// cd "$(typship pkg path (typship pkg ls book --id --first))"
    /// ```
    #[clap(action = clap::ArgAction::Append)]
    pub spec: Vec<String>,
}

fn package_cd(args: PackagePathArgs) -> anyhow::Result<()> {
    if args.spec.len() > 1 {
        return Err(anyhow::anyhow!("Multiple package specs provided"));
    }
    let spec = args
        .spec
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No package spec provided"))?;

    let spec = spec.trim();
    if spec.is_empty() {
        return Err(anyhow::anyhow!("Empty package spec"));
    }

    let has_colon = spec.contains(':');
    let has_slash = spec.contains('/');

    if has_colon && !has_slash {
        return Err(anyhow::anyhow!(
            "invalid package spec: {spec}. Please use `@namespace/package:version`"
        ));
    }

    let path = match (has_colon, has_slash) {
        (true, true) => {
            let (ns, pkg) = spec.split_once('/').unwrap();
            let (pkg, version) = pkg.split_once(':').unwrap();
            let path = typst_local_dir().join(human_ns(ns)).join(pkg).join(version);
            path
        }
        (false, true) => {
            let (ns, pkg) = spec.split_once('/').unwrap();
            let path = typst_local_dir().join(human_ns(ns)).join(pkg);
            path
        }
        (true, false) => {
            return Err(anyhow::anyhow!(
                "invalid package spec: {spec}. Please use `@namespace/package:version` or `@namespace/package` or `@namespace` or `namespace`"
            ));
        }
        (false, false) => typst_local_dir().join(human_ns(spec)),
    };

    if !path.exists() {
        return Err(anyhow::anyhow!(
            "directory to go not found: {}",
            path.to_string_lossy()
        ));
    }

    writeln!(std::io::stdout().lock(), "{}", path.to_string_lossy())?;

    Ok(())
}

fn human_ns(ns: &str) -> &str {
    ns.strip_prefix('@').unwrap_or(ns)
}

fn check_table(rows: &[Vec<&str>], cols: usize) -> anyhow::Result<()> {
    if rows.is_empty() {
        return Ok(());
    }

    for row in rows.iter() {
        if row.len() != cols {
            return Err(anyhow::anyhow!(
                "Invalid table format: expected {} columns, got {}",
                cols,
                row.len()
            ));
        }
    }

    Ok(())
}

fn time_ago(time: std::time::SystemTime) -> String {
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(time).unwrap_or_default();
    let seconds = duration.as_secs();

    // if less than 1 hour, show in min and sec
    if seconds < 3600 {
        let minutes = seconds / 60;
        let seconds = seconds % 60;
        return format!("{minutes}m{seconds}s");
    }

    // if less than 48 hours, show in hours
    if seconds < 172800 {
        let hours = seconds / 3600;
        return format!("{hours} hours ago");
    }

    // if more than 48 hours, show in days
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    if days < 7 {
        return format!("{days} days {hours} hours ago");
    }

    format!("{days} days ago")
}
