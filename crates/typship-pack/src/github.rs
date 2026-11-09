//! GitHub release upload, plus the URL-escaping helpers shared by the
//! registry and GitHub transports.

use anyhow::{Context, Result, anyhow, bail};

use crate::http::agent;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value as Json;

/// Create (if missing) a GitHub release and upload `bytes` as an asset.
/// Requires a token in `GITHUB_TOKEN` (or `TYPSHIP_TOKEN`).
pub fn upload_release_asset(repo: &str, tag: &str, asset_name: &str, bytes: &[u8]) -> Result<()> {
    let token = std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("TYPSHIP_TOKEN"))
        .map_err(|_| {
            anyhow!(
                "uploading to a GitHub release requires a token in the GITHUB_TOKEN environment variable"
            )
        })?;
    let api = format!("https://api.github.com/repos/{repo}/releases");
    // Find an existing release by tag; only a 404 leads to creating one.
    let existing = agent()
        .get(&format!("{api}/tags/{}", percent_encode(tag)))
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    let upload_url = match existing {
        Ok(resp) => {
            let body = resp.into_string().context("reading release response")?;
            release_upload_url(&body, tag)?
        }
        Err(ureq::Error::Status(404, _)) => {
            let body = format!(
                r#"{{"tag_name":{},"name":{}}}"#,
                json_escape(tag),
                json_escape(tag)
            );
            let resp = agent()
                .post(&api)
                .set("Authorization", &format!("Bearer {token}"))
                .set("Content-Type", "application/json")
                .send_string(&body)
                .map_err(|e| anyhow!("creating release {tag} on {repo}: {e}"))?;
            let text = resp.into_string().context("reading release response")?;
            release_upload_url(&text, tag)?
        }
        Err(e) => return Err(anyhow!("looking up release {tag} on {repo} failed: {e}")),
    };
    let upload_url = upload_url.replace("{?name,label}", "");
    if !upload_url.starts_with("https://uploads.github.com/") {
        bail!("release upload URL is not an uploads.github.com endpoint");
    }
    agent()
        .post(&format!("{upload_url}?name={}", percent_encode(asset_name)))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/gzip")
        .send_bytes(bytes)
        .map_err(|e| anyhow!("uploading asset {asset_name}: {e}"))?;
    Ok(())
}

/// Extract `upload_url` from a parsed release document.
pub fn release_upload_url(body: &str, tag: &str) -> Result<String> {
    let value: Json =
        serde_json::from_str(body).map_err(|e| anyhow!("invalid JSON in release document: {e}"))?;
    value
        .get("upload_url")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("release for tag `{tag}` has no upload_url"))
}

/// JSON string escape for embedding a value into a JSON document;
/// delegated to `serde_json` so the escaping rules live in one place.
pub fn json_escape(s: &str) -> String {
    serde_json::to_string(s).expect("string serialization cannot fail")
}

/// The RFC 3986 unreserved set: everything else is percent-encoded.
pub const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Percent-encode everything outside the unreserved set.
pub fn percent_encode(s: &str) -> String {
    utf8_percent_encode(s, UNRESERVED).to_string()
}
