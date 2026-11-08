//! The `typship download` command: fetch a package from a registry into
//! the local cache.
//!
//! Transport, unpacking and placement are entirely the named Pack
//! implementation ([`crate::pack`]): download is `copy` of a
//! `@preview/...` pack into the cache directory. That inherits the
//! network red-line (10 s connect / 120 s total per request, never
//! hangs) and the typst-style atomic placement (unpack into a temp dir
//! next to the destination, then `rename` into place) — no local HTTP,
//! gunzip or tar code remains.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::pack;

/// A parsed `download` invocation.
#[derive(Debug)]
pub struct Download {
    /// Package spec: `name` or `name:version`.
    pub spec: String,
    /// Registry base URL overriding the official one.
    pub registry: Option<String>,
}

/// Runs the download command.
pub fn run(download: &Download) -> Result<()> {
    let (name, version) = split_spec(&download.spec)?;
    let cache = cache_dir()?;
    let dest = pack::download(
        &name,
        version.as_deref(),
        download.registry.as_deref(),
        &cache,
    )?;
    println!("Downloaded {name} to {}", dest.display());
    Ok(())
}

/// Splits `name:version` or `name` (a trailing `:` means no version);
/// name and version are validated by the pack layer ([`pack::download`]).
fn split_spec(spec: &str) -> Result<(String, Option<String>)> {
    let (name, version) = match spec.strip_suffix(':') {
        Some(name) => (name, None),
        None => match spec.split_once(':') {
            Some((name, version)) => (name, Some(version)),
            None => (spec, None),
        },
    };
    if name.is_empty() {
        anyhow::bail!("invalid package spec `{spec}`: empty name");
    }
    Ok((name.to_string(), version.map(str::to_string)))
}

/// Resolves the package cache directory: `TYPSHIP_CACHE_DIR` wins,
/// otherwise the user data directory (`dirs::data_dir()`, i.e.
/// `%APPDATA%` on Windows — the same data-vs-cache distinction the
/// official typst packages dir uses).
fn cache_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("TYPSHIP_CACHE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let base = dirs::data_dir().context("could not determine the user data directory")?;
    Ok(base.join("typship").join("packages"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn split(spec: &str) -> (String, Option<String>) {
        split_spec(spec).unwrap()
    }

    #[test]
    fn split_spec_accepts_name_and_version() {
        assert_eq!(
            split("example:0.1.0"),
            ("example".into(), Some("0.1.0".into()))
        );
        assert_eq!(split("example"), ("example".into(), None));
        assert_eq!(split("example:"), ("example".into(), None));
    }

    #[test]
    fn cache_dir_honors_the_override() {
        let dir = std::env::temp_dir().join("typship-cache-override-test");
        // Safety: test-only env mutation, no other threads read this
        // variable during the test binary run.
        unsafe {
            std::env::set_var("TYPSHIP_CACHE_DIR", &dir);
            assert_eq!(cache_dir().unwrap(), dir);
            std::env::remove_var("TYPSHIP_CACHE_DIR");
        }
    }

    /// Minimal HTTP server answering each connection with a canned
    /// response (cycled by request order).
    fn mock_raw_server(responses: &[Vec<u8>]) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responses: Vec<_> = responses.to_vec();
        std::thread::spawn(move || {
            for response in responses.iter().cycle().take(16) {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let mut buf = [0u8; 1024];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                let _ = std::io::Write::write_all(&mut stream, response);
            }
        });
        format!("http://{addr}")
    }

    fn http_response(body: &[u8]) -> Vec<u8> {
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    /// A gzipped tarball whose root contains the given entries.
    fn gz_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        let tarball = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tarball).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn download_resolves_latest_and_places_atomically() {
        let index = br#"[{"name":"demo","version":"0.1.0"},{"name":"demo","version":"0.2.0"}]"#;
        let tarball = gz_of(&[("typst.toml", b"[package]\nname = \"demo\"\n".as_slice())]);
        let url = mock_raw_server(&[http_response(index), http_response(&tarball)]);
        let cache = std::env::temp_dir().join(format!("typship-dl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache);
        let dest = pack::download("demo", None, Some(&url), &cache).unwrap();
        assert_eq!(dest, cache.join("demo@0.2.0"));
        assert!(dest.join("typst.toml").is_file());
        // A second download into the same cache: the non-empty
        // destination is an error, never a silent merge.
        assert!(pack::download("demo", None, Some(&url), &cache).is_err());
        let _ = std::fs::remove_dir_all(&cache);
    }

    #[test]
    fn download_rejects_path_unsafe_names() {
        let cache = std::env::temp_dir().join(format!("typship-dl2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache);
        // `..` and slash components are rejected by the pack layer
        // before any network traffic happens.
        assert!(pack::download("../evil", None, None, &cache).is_err());
        assert!(pack::download("a/b", None, None, &cache).is_err());
        let _ = std::fs::remove_dir_all(&cache);
    }
}
