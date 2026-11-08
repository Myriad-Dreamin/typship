//! Pack destinations: shape auto-detection ([`parse_dest`]) over local
//! directories, `.tar.gz` files and GitHub release upload targets.

use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};

use crate::fs::{is_fs_path, is_http};

/// A detected pack destination.
#[derive(Debug, Clone)]
pub enum Dest {
    /// A directory to fill with the pack contents.
    Dir(PathBuf),
    /// A `.tar.gz` file to write.
    Tarball(PathBuf),
    /// A GitHub release to upload the tarball to.
    Release {
        /// `owner/repo`.
        repo: String,
        /// Release tag.
        tag: String,
    },
}

/// Auto-detect a destination pack by shape.
pub fn parse_dest(s: &str) -> Result<Dest> {
    if is_fs_path(s) {
        let lower = s.to_ascii_lowercase();
        if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
            return Ok(Dest::Tarball(PathBuf::from(s)));
        }
        return Ok(Dest::Dir(PathBuf::from(s)));
    }
    if is_http(s) {
        let host_and_path = s
            .strip_prefix("https://")
            .unwrap_or_else(|| s.strip_prefix("http://").unwrap_or(s));
        let segs: Vec<&str> = host_and_path.split('/').collect();
        // to release: github.com/{o}/{r}/releases/{tag} (or releases/tag/{tag})
        if segs.len() >= 5 && segs[0] == "github.com" && segs[3] == "releases" {
            let tag = match segs[4] {
                "tag" => segs
                    .get(5..)
                    .filter(|t| !t.is_empty())
                    .map(|t| t.join("/"))
                    .ok_or_else(|| anyhow!("invalid GitHub release URL `{s}`"))?,
                "download" => bail!("`{s}` is an asset URL, not an upload target"),
                _ => segs[4..].join("/"),
            };
            return Ok(Dest::Release {
                repo: format!("{}/{}", segs[1], segs[2]),
                tag,
            });
        }
    }
    bail!("`{s}` is neither a valid destination (fs dir, `*.tar.gz`, GitHub release URL)");
}
