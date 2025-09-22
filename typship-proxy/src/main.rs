//! A proxy for typst universe (https://packages.typst.org)

use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::Path as PathParam;

use axum::response::{IntoResponse, Response};
use axum::{Router, extract::Request, http::StatusCode, routing::get};
use clap::Parser;
use tokio::net::TcpListener;
use tower::ServiceExt;
use tower_http::services::ServeFile;

/// Arguments for the proxy
#[derive(Parser)]
struct Args {
    /// Registry to use
    #[clap(long, default_value = "https://packages.typst.org")]
    registry: String,
    /// The cache directory to use. Defaults to `$XDG_CACHE_HOME`
    #[clap(long)]
    cache_dir: Option<PathBuf>,
    /// Address to bind to. Defaults to `127.0.0.1:11980`
    #[clap(long)]
    bind: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();

    let cache_dir = match args.cache_dir {
        Some(dir) => dir,
        None => dirs::cache_dir()
            .context("Failed to get the cache directory")?
            .join("typship/proxy"),
    };

    let cache_dir: Arc<Path> = cache_dir.into();
    let registry: Arc<str> = args.registry.into();

    // ns/spec-version.tar.gz
    let routes = Router::new().route(
        "/preview/{file_name}",
        get(
            async move |PathParam(file_name): PathParam<String>, request: Request| {
                // file_name can only contain letters, numbers, and hyphens and ends with
                // .tar.gz
                if !file_name.ends_with(".tar.gz") {
                    return Err(TypshipError::InvalidFileName(file_name));
                }
                if !file_name
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '.')
                {
                    return Err(TypshipError::InvalidFileName(file_name));
                }

                let cache_dest = cache_dir.clone().join("preview").join(&file_name);
                if cache_dest.exists() {
                    let service = ServeFile::new(cache_dest);
                    log::info!("Serving from cache: @preview/{file_name}");
                    return Ok(service.oneshot(request).await.unwrap());
                }

                let url = format!("{registry}/preview/{file_name}");
                let cache_dest = tokio::task::spawn_blocking(move || -> Result<_, TypshipError> {
                    let tmp_file = tempfile::NamedTempFile::new().unwrap();
                    let mut tmp_file = std::io::BufWriter::new(tmp_file);

                    let mut req = reqwest::blocking::get(url).unwrap();
                    std::io::copy(&mut req, &mut tmp_file).log()?;

                    tmp_file.flush().log()?;
                    let tmp_file = tmp_file.into_inner().log()?;

                    std::fs::create_dir_all(cache_dest.parent().with_log("cache no parent dir")?)
                        .log()?;

                    tmp_file.persist(&cache_dest).log()?;

                    Ok(cache_dest)
                })
                .await
                .log()??;

                let service = ServeFile::new(cache_dest);
                log::info!("Serving from remote: @preview/{file_name}");
                Ok(service.oneshot(request).await.unwrap())
            },
        ),
    );

    log::info!(
        "Serving on {}",
        args.bind.as_deref().unwrap_or("127.0.0.1:11980")
    );
    axum::serve(
        TcpListener::bind(args.bind.as_deref().unwrap_or("127.0.0.1:11980")).await?,
        routes,
    )
    .await?;

    Ok(())
}

trait LogError<T> {
    fn log(self) -> Result<T, TypshipError>;
}

impl<T, E: std::error::Error> LogError<T> for Result<T, E> {
    fn log(self) -> Result<T, TypshipError> {
        self.map_err(|e| {
            log::error!("Failed to get response: {e}");
            TypshipError::Internal
        })
    }
}

trait WithLog<T> {
    fn with_log(self, msg: &str) -> Result<T, TypshipError>;
}

impl<T> WithLog<T> for Option<T> {
    fn with_log(self, msg: &str) -> Result<T, TypshipError> {
        self.ok_or_else(|| {
            log::error!("{}", msg);
            TypshipError::Internal
        })
    }
}

pub enum TypshipError {
    InvalidFileName(String),
    Io(std::io::Error),
    Internal,
}

impl From<std::io::Error> for TypshipError {
    fn from(e: std::io::Error) -> Self {
        TypshipError::Io(e)
    }
}

impl From<String> for TypshipError {
    fn from(e: String) -> Self {
        TypshipError::InvalidFileName(e)
    }
}

impl IntoResponse for TypshipError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            TypshipError::InvalidFileName(e) => (StatusCode::BAD_REQUEST, e),
            TypshipError::Io(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            TypshipError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            ),
        };
        (status, error_message).into_response()
    }
}
