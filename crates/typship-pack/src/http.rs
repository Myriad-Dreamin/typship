//! The HTTP layer: a shared user-agent with connection/total timeouts,
//! the retry policy (transient failures only), and the gzipped-tarball
//! fetch used by registry and GitHub transports.

use std::io::Read;
use std::time::Duration;

use anyhow::{anyhow, Result};

/// Connect phase timeout; the total request budget is separate.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Total per-request timeout; a network path must never hang forever.
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
/// Attempts per HTTP request for transient failures only (4xx except 429
/// fails immediately).
pub const RETRIES: usize = 3;
/// The manifest that marks the pack root inside an archive.
pub const PACK_MANIFEST: &str = "typst.toml";

/// An HTTP agent with connection and total timeouts.
pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .user_agent("typship")
        .build()
}

/// Why a fetch failed, classified so callers know whether to retry, to
/// fall back to the next candidate, or to stop.
#[derive(Debug)]
pub enum FetchError {
    /// The resource definitively does not exist (HTTP 404): retrying
    /// the same URL never helps, but a caller may fall back to another
    /// candidate (e.g. the next ref interpretation of a tree URL).
    NotFound(String),
    /// A permanent problem (other 4xx such as 401/403, a body over the
    /// download cap, a non-gzip tarball): no retry and no fallback can
    /// fix it.
    Fatal(String),
    /// A transport error, a 429 or a 5xx: worth retrying.
    Transient(String),
}

/// Why reading a response body failed.
#[derive(Debug)]
pub enum BodyError {
    /// The connection died mid-body (or another I/O error): the
    /// request is worth retrying.
    Io(std::io::Error),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::NotFound(m) | FetchError::Fatal(m) | FetchError::Transient(m) => {
                write!(f, "{m}")
            }
        }
    }
}

impl From<FetchError> for anyhow::Error {
    fn from(e: FetchError) -> Self {
        anyhow!("{e}")
    }
}

/// Read a response body in full. A connection death mid-body is an I/O
/// error, which the retry loop treats as transient.
pub fn read_body(mut reader: impl Read, url: &str) -> Result<Vec<u8>, BodyError> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).map_err(|e| {
        BodyError::Io(std::io::Error::new(
            e.kind(),
            format!("reading body of {url}: {e}"),
        ))
    })?;
    Ok(buf)
}

/// GET a URL to bytes, retrying only transient failures. A body read
/// error is transient (the connection may have died mid-body).
pub fn get_bytes(url: &str) -> Result<Vec<u8>, FetchError> {
    let mut last = None;
    for attempt in 0..RETRIES {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(500 * attempt as u64));
        }
        match agent().get(url).call() {
            Ok(resp) => match read_body(resp.into_reader(), url) {
                Ok(bytes) => return Ok(bytes),
                Err(BodyError::Io(e)) => {
                    last = Some(FetchError::Transient(format!("GET {url}: body read: {e}")));
                }
            },
            // A definitive miss: the one status that may trigger a
            // fallback to another candidate.
            Err(ureq::Error::Status(404, _)) => {
                return Err(FetchError::NotFound(format!("GET {url} failed: HTTP 404")));
            }
            // Other client errors (401/403/…) are permanent: no retry,
            // no fallback.
            Err(ureq::Error::Status(code, _)) if (400..500).contains(&code) && code != 429 => {
                return Err(FetchError::Fatal(format!("GET {url} failed: HTTP {code}")));
            }
            Err(e) => {
                last = Some(FetchError::Transient(format!("GET {url}: {e}")));
            }
        }
    }
    Err(last.unwrap())
}

/// [`get_bytes`] with the error flattened into `anyhow` for callers that
/// do not branch on the classification.
pub fn fetch_bytes(url: &str) -> Result<Vec<u8>> {
    get_bytes(url).map_err(anyhow::Error::from)
}

/// GET a URL that must yield a gzipped tarball. A non-gzip body is a
/// permanent failure, never a reason to re-request.
pub fn get_tarball(url: &str) -> Result<Vec<u8>, FetchError> {
    let bytes = get_bytes(url)?;
    if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
        return Err(FetchError::Fatal(format!(
            "body of {url} is not a gzipped tarball"
        )));
    }
    Ok(bytes)
}
