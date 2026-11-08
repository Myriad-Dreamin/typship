//! The named Pack abstraction: parsing, detection and transport of pack
//! sources and destinations, split by concern —
//!
//! - [`fs`]: path helpers (shape detection, physical resolution,
//!   distinctness contract, per-user packages dir)
//! - [`source`]: source shape auto-detection
//! - [`dest`]: destination shape auto-detection
//! - [`transport`]: materialization, git clone, tar extract/pack, atomic IO
//! - [`github`]: release upload and URL escaping
//! - [`copy`]: the `copy` / `link` commands over the above
//!
//! Standard formats are handled by standard crates: JSON with
//! `serde_json`, the tar container with `tar`, gzip with `flate2`,
//! percent-encoding with `percent-encoding`, and TOML manifest writing
//! with `toml`. No hand-written parsers or encoders for standard formats.
//!
//! Safety posture for untrusted archives, aligned with typst's own
//! unpacking rules: member paths are validated (no absolute paths, no
//! `..` components), member names must be UTF-8, and member types are
//! restricted to plain files and directories — link and device members
//! are rejected outright. Resource budgets were removed per admin
//! direction 2026-11-08 ("不要做没必要的限制"): an archive is as large
//! as it is.
//!
//! HTTP posture: only transient failures (transport errors, 429 and 5xx)
//! are retried; other 4xx answers are a definitive miss, and a non-gzip
//! tarball body is a permanent failure that never triggers another
//! request. Response bodies are read in full — no download cap.

pub mod copy;
pub mod http;
pub mod dest;
pub mod fs;
pub mod github;
pub mod source;
pub mod transport;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

