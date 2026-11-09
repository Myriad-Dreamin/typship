//! Pack sources: shape auto-detection ([`parse_source`]) over registry
//! specs, GitHub repos/trees/releases, plain tarball URLs and local
//! filesystem paths.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};

use crate::fs::{is_fs_path, is_http};

/// The official Typst preview registry base.
pub const OFFICIAL_REGISTRY: &str = "https://packages.typst.org/preview";

/// A detected pack source.
#[derive(Debug, Clone)]
pub enum Source {
    /// A directory on the local filesystem.
    Fs(PathBuf),
    /// A local tarball file read directly.
    Tarball(Vec<u8>),
    /// A gzipped tarball read from stdin.
    Stdin,
    /// A registry pack: `@namespace/name[:version]`.
    Registry {
        /// Namespace, e.g. `preview` or `local`.
        namespace: String,
        /// Package name.
        name: String,
        /// Optional exact version; latest is picked when absent.
        version: Option<String>,
    },
    /// A GitHub repository root or `.git` URL: the default branch,
    /// cloned with git.
    GithubRepo {
        /// Repository owner.
        owner: String,
        /// Repository name (without a `.git` suffix).
        repo: String,
    },
    /// A URL that resolves to a gzipped tarball, plus an optional
    /// in-archive subpath.
    Url {
        /// Tarball URL to download.
        url: String,
        /// Subdirectory inside the archive to use, if any.
        subpath: Option<String>,
    },
    /// A GitHub repository tree URL `github.com/{owner}/{repo}/tree/...`;
    /// the ref may contain slashes, so the ref/subpath split is resolved
    /// by trying interpretations from the longest ref down at transport
    /// time.
    GithubTree {
        /// Repository owner.
        owner: String,
        /// Repository name.
        repo: String,
        /// Path segments after `tree/` (ref segments and subpath).
        rest: Vec<String>,
    },
    /// A GitHub release URL (`releases/latest`, `releases/tag/{tag}` or
    /// `releases/{tag}`). Resolved through the GitHub API: a `.tar.gz`/
    /// `.tgz` asset is preferred, the source archive of the resolved tag
    /// is the fallback. `releases/tag/latest` names the literal tag
    /// `latest`, not the latest release.
    GithubRelease {
        /// `owner/repo`.
        repo: String,
        /// Release tag; `None` means the latest release.
        tag: Option<String>,
    },
}

/// Parse `@namespace/name[:version]`. Every component must be a single
/// path-safe, dot-free segment: `.` and `..` are rejected, and colons
/// are not allowed (they are the version separator and an NTFS stream
/// marker).
pub fn parse_at(s: &str) -> Result<Source> {
    let body = &s[1..];
    let (ns_name, version) = match body.split_once(':') {
        Some((a, b)) => (a, Some(b.to_string())),
        None => (body, None),
    };
    let (namespace, name) = ns_name
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid pack spec `{s}`, expected @namespace/name[:version]"))?;
    if namespace.is_empty() || name.is_empty() {
        bail!("invalid pack spec `{s}`, expected @namespace/name[:version]");
    }
    for part in [namespace, name, version.as_deref().unwrap_or_default()] {
        if part.is_empty() {
            continue;
        }
        if part.contains('/')
            || part.contains('\\')
            || part.contains(':')
            || part == "."
            || part == ".."
        {
            bail!(
                "invalid pack spec `{s}`: namespace, name and version must be single path-safe components"
            );
        }
    }
    if version.as_deref() == Some("") {
        bail!("invalid pack spec `{s}`: empty version");
    }
    Ok(Source::Registry {
        namespace: namespace.to_string(),
        name: name.to_string(),
        version,
    })
}

/// Auto-detect a source pack by shape.
pub fn parse_source(s: &str) -> Result<Source> {
    if s == "-" {
        return Ok(Source::Stdin);
    }
    // A `*.tar.gz`/`*.tgz` file is transported as a tarball, not a
    // directory; a bare file name is accepted as long as it exists.
    let lower = s.to_ascii_lowercase();
    if (lower.ends_with(".tar.gz") || lower.ends_with(".tgz")) && std::path::Path::new(s).is_file()
    {
        let bytes = fs::read(s).with_context(|| format!("reading tarball {s}"))?;
        return Ok(Source::Tarball(bytes));
    }
    if is_fs_path(s) {
        return Ok(Source::Fs(PathBuf::from(s)));
    }
    if s.starts_with('@') {
        return parse_at(s);
    }
    if !is_http(s) {
        bail!("`{s}` is neither a valid pack (fs path, `-`, `@ns/name`) nor an http(s) URL");
    }
    // git pack: `.../repo.git` -- no ref is expressible, so the default
    // branch is cloned. Generic git hosts use different layouts; failing
    // clearly beats downloading the wrong thing.
    if s.ends_with(".git") {
        let url = url::Url::parse(s).map_err(|e| anyhow!("invalid URL `{s}`: {e}"))?;
        if url.host_str().map(|h| h.eq_ignore_ascii_case("github.com")) != Some(true) {
            bail!(
                "git pack support is limited to github.com URLs; for other hosts pass a direct archive URL"
            );
        }
        let segs: Vec<&str> = url
            .path_segments()
            .map(|segs| segs.filter(|p| !p.is_empty()).collect())
            .unwrap_or_default();
        if segs.len() != 2 {
            bail!("invalid GitHub URL `{s}`");
        }
        return Ok(Source::GithubRepo {
            owner: segs[0].to_string(),
            repo: segs[1].trim_end_matches(".git").to_string(),
        });
    }
    let url = url::Url::parse(s).map_err(|e| anyhow!("invalid URL `{s}`: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("`{s}` is neither a valid pack (fs path, `-`, `@ns/name`) nor an http(s) URL");
    }
    let segs: Vec<&str> = url
        .path_segments()
        .map(|segs| segs.filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();
    if url.host_str().map(|h| h.eq_ignore_ascii_case("github.com")) != Some(true) {
        // Any other http(s) URL: a tarball.
        return Ok(Source::Url {
            url: s.to_string(),
            subpath: None,
        });
    }
    if segs.len() < 2 {
        bail!("invalid GitHub URL `{s}`");
    }
    let (owner, repo) = (segs[0], segs[1]);
    // `.../archive/...` is already an archive URL: pass it through
    // untouched so the requested ref is preserved.
    if segs.len() >= 4 && segs[2] == "archive" {
        return Ok(Source::Url {
            url: s.to_string(),
            subpath: None,
        });
    }
    // GitHub release pack: releases/latest | releases/tag/{t} |
    // releases/{t} | releases/download/{t}/{asset}.
    if segs.len() >= 4 && segs[2] == "releases" {
        match segs.get(3).copied() {
            Some("download") => {
                // An asset download URL: use it exactly as given.
                if segs.len() < 5 {
                    bail!("invalid GitHub release asset URL `{s}`");
                }
                return Ok(Source::Url {
                    url: s.to_string(),
                    subpath: None,
                });
            }
            Some("tag") => {
                // The tag may contain slashes: everything after
                // `tag/` is the literal tag, including a tag that
                // happens to be named `latest`.
                let tag = segs.get(4..).filter(|t| !t.is_empty()).map(|t| t.join("/"));
                return Ok(Source::GithubRelease {
                    repo: format!("{owner}/{repo}"),
                    tag,
                });
            }
            Some("latest") => {
                return Ok(Source::GithubRelease {
                    repo: format!("{owner}/{repo}"),
                    tag: None,
                });
            }
            Some(_tag) => {
                return Ok(Source::GithubRelease {
                    repo: format!("{owner}/{repo}"),
                    tag: Some(segs[3..].join("/")),
                });
            }
            None => bail!("invalid GitHub release URL `{s}`"),
        }
    }
    // GitHub directory pack: tree/{ref-with-possible-slashes[/subpath]}.
    if segs.len() >= 4 && segs[2] == "tree" {
        return Ok(Source::GithubTree {
            owner: owner.to_string(),
            repo: repo.to_string(),
            rest: segs[3..].iter().map(|s| s.to_string()).collect(),
        });
    }
    if segs.len() == 2 {
        // A plain repository URL: the default branch, cloned with git.
        return Ok(Source::GithubRepo {
            owner: owner.to_string(),
            repo: repo.to_string(),
        });
    }
    bail!(
        "`{s}` is not a pack source (expected a repository root, tree, archive, release or .git URL)"
    )
}
