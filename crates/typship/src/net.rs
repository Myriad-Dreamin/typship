//! Minimal networking for `typship download`.
//!
//! A handwritten HTTP/1.1 GET over [`std::net`] with mandatory connect and
//! total timeouts (it never hangs), optional TLS via `rustls` for `https`
//! URLs, and system-proxy support through the `HTTPS_PROXY` / `HTTP_PROXY`
//! environment variables (honoring `NO_PROXY`; loopback hosts never go
//! through a proxy). The module also carries the registry payload decoders:
//! gzip (DEFLATE), tar unpacking, and the registry index scan.

use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant};

/// Connection-establishment timeout (includes DNS resolution).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Overall deadline for one [`get`] call, across redirects and body reads.
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum number of HTTP redirects followed by [`get`].
const MAX_REDIRECTS: usize = 5;
/// Maximum size of a response header line before failing.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// A network-layer failure. The message always names the URL and the reason.
#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// Result alias for the network layer.
pub type Result<T> = std::result::Result<T, Error>;

fn fail<T>(url: &str, reason: impl fmt::Display) -> Result<T> {
    Err(Error::new(format!("GET {url} failed: {reason}")))
}

fn map_io(url: &str, e: std::io::Error) -> Error {
    if matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) {
        Error::new(format!("GET {url} failed: timed out"))
    } else {
        Error::new(format!("GET {url} failed: {e}"))
    }
}

/// Parsed absolute `http` / `https` URL.
#[derive(Debug, Clone)]
pub struct Url {
    /// Lowercase scheme, `http` or `https`.
    pub scheme: String,
    /// Host name or IP literal (without brackets for IPv6).
    pub host: String,
    /// Port, defaulted to 80 / 443 per scheme when absent.
    pub port: u16,
    /// Request path, always starting with `/`.
    pub path: String,
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let default_port = if self.scheme == "https" { 443 } else { 80 };
        write!(f, "{}://", self.scheme)?;
        if self.host.contains(':') {
            write!(f, "[{}]", self.host)?;
        } else {
            write!(f, "{}", self.host)?;
        }
        if self.port != default_port {
            write!(f, ":{}", self.port)?;
        }
        write!(f, "{}", self.path)
    }
}

fn parse_authority(authority: &str, scheme: &str, input: &str) -> Result<(String, u16)> {
    let default_port = if scheme == "https" { 443 } else { 80 };
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return Err(Error::new(format!(
                "URL {input:?} has an unterminated IPv6 literal"
            )));
        };
        let port = match after.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| Error::new(format!("URL {input:?} has an invalid port")))?,
            None => default_port,
        };
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, p)) => {
            let port = p
                .parse()
                .map_err(|_| Error::new(format!("URL {input:?} has an invalid port")))?;
            Ok((host.to_string(), port))
        }
        None => Ok((authority.to_string(), default_port)),
    }
}

/// Parses an absolute `http` or `https` URL.
pub fn parse_url(input: &str) -> Result<Url> {
    let Some((scheme, rest)) = input.split_once("://") else {
        return Err(Error::new(format!(
            "URL {input:?} has no scheme (expected http:// or https://)"
        )));
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(Error::new(format!(
            "URL {input:?} uses unsupported scheme {scheme:?} (only http and https)"
        )));
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(Error::new(format!("URL {input:?} has an empty host")));
    }
    if authority.contains('@') {
        return Err(Error::new(format!(
            "URL {input:?} contains userinfo, which is not supported"
        )));
    }
    let (host, port) = parse_authority(authority, &scheme, input)?;
    Ok(Url {
        scheme,
        host,
        port,
        path: path.to_string(),
    })
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

fn no_proxy_matches(host: &str) -> bool {
    let list = match std::env::var("NO_PROXY").or_else(|_| std::env::var("no_proxy")) {
        Ok(list) => list,
        Err(_) => return false,
    };
    list.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .any(|entry| {
            let entry = entry.trim_start_matches('.');
            entry == "*"
                || host.eq_ignore_ascii_case(entry)
                || host
                    .to_ascii_lowercase()
                    .ends_with(&format!(".{}", entry.to_ascii_lowercase()))
        })
}

/// Returns the proxy URL to use for `url`, if the environment specifies one.
fn proxy_for(url: &Url) -> Option<Url> {
    if is_loopback(&url.host) || no_proxy_matches(&url.host) {
        return None;
    }
    let vars: &[&str] = if url.scheme == "https" {
        &["HTTPS_PROXY", "https_proxy"]
    } else {
        &["HTTP_PROXY", "http_proxy"]
    };
    for var in vars {
        if let Ok(proxy) = std::env::var(var) {
            let proxy = proxy.trim();
            if proxy.is_empty() {
                continue;
            }
            if let Ok(parsed) = parse_url(proxy) {
                return Some(parsed);
            }
        }
    }
    None
}

/// Resolves and connects, bounded by both [`CONNECT_TIMEOUT`] and the overall
/// deadline. DNS resolution happens on a helper thread so an unresponsive
/// resolver cannot hang past the deadline either.
fn connect(url: &Url, proxy: Option<&Url>, deadline: Instant) -> Result<TcpStream> {
    let (host, port) = match proxy {
        Some(proxy) => (&proxy.host, proxy.port),
        None => (&url.host, url.port),
    };
    let target = format!("{host}:{port}");
    let (tx, rx) = std::sync::mpsc::channel();
    let connect_budget = CONNECT_TIMEOUT;
    std::thread::spawn(move || {
        let attempt = || -> std::io::Result<TcpStream> {
            let mut last: Option<std::io::Error> = None;
            for addr in target.to_socket_addrs()? {
                match TcpStream::connect_timeout(&addr, connect_budget) {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        return Ok(stream);
                    }
                    Err(e) => last = Some(e),
                }
            }
            Err(last.unwrap_or_else(|| std::io::Error::other("host resolved to no addresses")))
        };
        let _ = tx.send(attempt());
    });
    let remaining = deadline.saturating_duration_since(Instant::now());
    let wait = remaining.min(connect_budget);
    match rx.recv_timeout(wait) {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => fail(
            &url.to_string(),
            format!("connect to {host}:{port} failed: {e}"),
        ),
        Err(_) => fail(
            &url.to_string(),
            format!(
                "connect to {host}:{port} timed out after {}s (connect timeout)",
                connect_budget.as_secs()
            ),
        ),
    }
}

/// Applies the remaining time until `deadline` as the socket read/write
/// timeouts, failing once the deadline has passed.
fn apply_deadline(sock: &TcpStream, url: &str, deadline: Instant) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Error::new(format!(
            "GET {url} failed: total timeout of {}s exceeded",
            TOTAL_TIMEOUT.as_secs()
        )));
    }
    let _ = sock.set_read_timeout(Some(remaining));
    let _ = sock.set_write_timeout(Some(remaining));
    Ok(())
}

/// The established connection: a plain TCP stream or a TLS-wrapped one.
enum Stream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Stream {
    fn as_tcp(&self) -> &TcpStream {
        match self {
            Stream::Plain(tcp) => tcp,
            Stream::Tls(tls) => &tls.sock,
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(tcp) => tcp.read(buf),
            Stream::Tls(tls) => tls.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(tcp) => tcp.write(buf),
            Stream::Tls(tls) => tls.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(tcp) => tcp.flush(),
            Stream::Tls(tls) => tls.flush(),
        }
    }
}

/// Wraps an established TCP stream in TLS, completing the handshake under the
/// deadline.
fn tls_connect(url: &Url, tcp: TcpStream, deadline: Instant) -> Result<Stream> {
    let url_string = url.to_string();
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(url.host.clone())
        .map_err(|_| Error::new(format!("GET {url_string} failed: invalid TLS server name")))?;
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(config), server_name)
        .map_err(|e| Error::new(format!("GET {url_string} failed: TLS setup failed: {e}")))?;
    let mut stream = Stream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)));
    let Stream::Tls(tls) = &mut stream else {
        return Ok(stream);
    };
    loop {
        if !tls.conn.is_handshaking() {
            break;
        }
        apply_deadline(&tls.sock, &url_string, deadline)?;
        let result = tls.conn.complete_io(&mut tls.sock);
        if let Err(e) = result {
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) {
                continue;
            }
            return fail(&url_string, format!("TLS handshake failed: {e}"));
        }
    }
    Ok(stream)
}

/// Buffered reader over the connection that enforces the total deadline.
struct DeadlineReader {
    stream: Stream,
    buf: Vec<u8>,
    url: String,
    deadline: Instant,
    eof: bool,
}

impl DeadlineReader {
    fn new(stream: Stream, url: String, deadline: Instant) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            url,
            deadline,
            eof: false,
        }
    }

    /// Reads more bytes from the socket. Returns `false` on clean EOF.
    fn fill(&mut self) -> Result<bool> {
        if self.eof {
            return Ok(false);
        }
        apply_deadline(self.stream.as_tcp(), &self.url, self.deadline)?;
        let mut chunk = [0u8; 16 * 1024];
        let n = self
            .stream
            .read(&mut chunk)
            .map_err(|e| map_io(&self.url, e))?;
        if n == 0 {
            self.eof = true;
            return Ok(false);
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(true)
    }

    /// Reads one CRLF-terminated line (returned without the terminator).
    fn read_line(&mut self, max: usize) -> Result<String> {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line = String::from_utf8_lossy(&self.buf[..i]).into_owned();
                self.buf.drain(..i + 2);
                return Ok(line);
            }
            if self.buf.len() > max {
                return fail(&self.url, "response header line too long");
            }
            if !self.fill()? {
                return fail(&self.url, "connection closed mid-response");
            }
        }
    }

    /// Reads exactly `n` more bytes into `out`.
    fn read_exact_n(&mut self, out: &mut Vec<u8>, mut n: usize) -> Result<()> {
        while n > 0 {
            let take = n.min(self.buf.len());
            if take > 0 {
                out.extend_from_slice(&self.buf[..take]);
                self.buf.drain(..take);
                n -= take;
            }
            if n > 0 && !self.fill()? {
                return fail(&self.url, "connection closed mid-response");
            }
        }
        Ok(())
    }

    /// Reads everything until the connection is closed by the server.
    fn read_to_end(&mut self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.buf);
        self.buf.clear();
        while self.fill()? {
            let n = self.buf.len();
            out.extend_from_slice(&self.buf[..n]);
            self.buf.clear();
        }
        Ok(())
    }
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn read_headers(reader: &mut DeadlineReader) -> Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    loop {
        let line = reader.read_line(MAX_LINE_BYTES)?;
        if line.is_empty() {
            return Ok(headers);
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
}

fn parse_status(line: &str, url: &str) -> Result<u16> {
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return fail(url, format!("malformed status line {line:?}"));
    }
    parts
        .next()
        .unwrap_or("")
        .parse::<u16>()
        .map_err(|_| Error::new(format!("GET {url} failed: malformed status line {line:?}")))
}

fn resolve_redirect(base: &Url, location: &str) -> Result<Url> {
    if location.contains("://") {
        parse_url(location)
    } else if let Some(rest) = location.strip_prefix('/') {
        let mut url = base.clone();
        url.path = rest.to_string();
        Ok(url)
    } else {
        let cut = base.path.rfind('/').map_or(0, |i| i + 1);
        let mut url = base.clone();
        url.path = format!("{}{location}", &base.path[..cut]);
        Ok(url)
    }
}

fn read_chunked(reader: &mut DeadlineReader, out: &mut Vec<u8>) -> Result<()> {
    loop {
        let line = reader.read_line(1024)?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| {
            Error::new(format!(
                "GET {} failed: invalid chunk size {size_text:?}",
                reader.url
            ))
        })?;
        if size == 0 {
            loop {
                if reader.read_line(1024)?.is_empty() {
                    break;
                }
            }
            return Ok(());
        }
        reader.read_exact_n(out, size)?;
        if !reader.read_line(16)?.is_empty() {
            return fail(&reader.url, "missing CRLF after a chunk");
        }
    }
}

fn read_body(
    reader: &mut DeadlineReader,
    headers: &[(String, String)],
    out: &mut Vec<u8>,
) -> Result<()> {
    let chunked = find_header(headers, "transfer-encoding")
        .map(|value| value.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    if chunked {
        read_chunked(reader, out)
    } else if let Some(len) =
        find_header(headers, "content-length").and_then(|value| value.trim().parse::<usize>().ok())
    {
        reader.read_exact_n(out, len)
    } else {
        reader.read_to_end(out)
    }
}

/// Sends the CONNECT request for an https tunnel through `proxy`.
fn proxy_tunnel(tcp: &mut TcpStream, url: &Url, proxy: &Url, deadline: Instant) -> Result<()> {
    let authority = format!("{}:{}", url.host, url.port);
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    apply_deadline(tcp, &url.to_string(), deadline)?;
    tcp.write_all(request.as_bytes())
        .map_err(|e| map_io(&url.to_string(), e))?;
    tcp.flush().map_err(|e| map_io(&url.to_string(), e))?;
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        apply_deadline(tcp, &url.to_string(), deadline)?;
        let n = tcp
            .read(&mut byte)
            .map_err(|e| map_io(&url.to_string(), e))?;
        if n == 0 {
            return fail(&url.to_string(), "proxy closed the CONNECT tunnel");
        }
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
        if response.len() > 16 * 1024 {
            return fail(&url.to_string(), "proxy CONNECT response too large");
        }
    }
    let head = String::from_utf8_lossy(&response);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 200 {
        return fail(
            &url.to_string(),
            format!("proxy {proxy} refused CONNECT with HTTP {status}"),
        );
    }
    Ok(())
}

fn send_request(
    stream: &mut Stream,
    request_target: &str,
    host_header: &str,
    url: &str,
    deadline: Instant,
) -> Result<()> {
    apply_deadline(stream.as_tcp(), url, deadline)?;
    let request = format!(
        "GET {request_target} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: typship/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| map_io(url, e))?;
    stream.flush().map_err(|e| map_io(url, e))?;
    Ok(())
}

/// Performs an HTTP GET against `url` and returns the response body.
///
/// Follows up to [`MAX_REDIRECTS`] redirects. Connection setup is bounded by
/// [`CONNECT_TIMEOUT`] and the whole exchange by [`TOTAL_TIMEOUT`]; timeouts,
/// unreachable hosts and HTTP error statuses are reported as [`Error`]s that
/// name the URL and the reason.
pub fn get(url: &str) -> Result<Vec<u8>> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let mut current = parse_url(url)?;
    let mut redirects = 0;
    loop {
        let proxy = proxy_for(&current);
        let mut tcp = connect(&current, proxy.as_ref(), deadline)?;
        if current.scheme == "https" {
            if let Some(proxy) = &proxy {
                proxy_tunnel(&mut tcp, &current, proxy, deadline)?;
            }
        }
        let mut stream = if current.scheme == "https" {
            tls_connect(&current, tcp, deadline)?
        } else {
            Stream::Plain(tcp)
        };
        let request_target = if current.scheme == "http" && proxy.is_some() {
            current.to_string()
        } else {
            current.path.clone()
        };
        let default_port = if current.scheme == "https" { 443 } else { 80 };
        let host_header = if current.port == default_port {
            current.host.clone()
        } else {
            format!("{}:{}", current.host, current.port)
        };
        send_request(
            &mut stream,
            &request_target,
            &host_header,
            &current.to_string(),
            deadline,
        )?;
        let mut reader = DeadlineReader::new(stream, current.to_string(), deadline);
        let status = loop {
            let code = parse_status(&reader.read_line(8192)?, &reader.url)?;
            if code / 100 == 1 {
                continue;
            }
            break code;
        };
        let headers = read_headers(&mut reader)?;
        if (300..400).contains(&status) {
            if let Some(location) = find_header(&headers, "location") {
                if redirects >= MAX_REDIRECTS {
                    return fail(&current.to_string(), "too many redirects");
                }
                redirects += 1;
                current = resolve_redirect(&current, location)?;
                continue;
            }
            return fail(
                &current.to_string(),
                format!("HTTP {status} redirect without Location header"),
            );
        }
        if status >= 400 {
            return fail(&current.to_string(), format!("HTTP {status}"));
        }
        if status / 100 != 2 {
            return fail(
                &current.to_string(),
                format!("unexpected HTTP status {status}"),
            );
        }
        let mut body = Vec::new();
        read_body(&mut reader, &headers, &mut body)?;
        return Ok(body);
    }
}

fn skip_cstr(data: &[u8], mut pos: usize, field: &str) -> Result<usize> {
    while pos < data.len() && data[pos] != 0 {
        pos += 1;
    }
    if pos >= data.len() {
        return Err(Error::new(format!("truncated gzip header ({field})")));
    }
    Ok(pos + 1)
}

/// Computes the CRC-32 checksum (IEEE, as used by gzip).
pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, entry) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *entry = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc = table[((crc ^ u32::from(byte)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// A bit-level reader (LSB first) over a DEFLATE stream.
struct BitReader<'a> {
    data: &'a [u8],
    byte: usize,
    bit: u32,
}

impl BitReader<'_> {
    fn bits(&mut self, count: u32) -> Result<u32> {
        let mut out = 0u32;
        for i in 0..count {
            if self.byte >= self.data.len() {
                return Err(Error::new("DEFLATE stream truncated"));
            }
            let bit = (self.data[self.byte] >> self.bit) & 1;
            out |= u32::from(bit) << i;
            self.bit += 1;
            if self.bit == 8 {
                self.bit = 0;
                self.byte += 1;
            }
        }
        Ok(out)
    }

    fn align(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.byte += 1;
        }
    }
}

/// A canonical Huffman decoding table (RFC 1951).
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Self {
        let mut counts = [0u16; 16];
        for &len in lengths {
            counts[len as usize] += 1;
        }
        counts[0] = 0;
        let mut offsets = [0u16; 16];
        for i in 1..16 {
            offsets[i] = offsets[i - 1] + counts[i - 1];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (sym, &len) in lengths.iter().enumerate() {
            if len != 0 {
                symbols[offsets[len as usize] as usize] = sym as u16;
                offsets[len as usize] += 1;
            }
        }
        Self { counts, symbols }
    }

    fn decode(&self, reader: &mut BitReader) -> Result<u16> {
        let mut code = 0i32;
        let mut first = 0i32;
        let mut index = 0i32;
        for len in 1..16 {
            code |= reader.bits(1)? as i32;
            let count = i32::from(self.counts[len]);
            if code - count < first {
                return self
                    .symbols
                    .get((index + (code - first)) as usize)
                    .copied()
                    .ok_or_else(|| Error::new("invalid DEFLATE code"));
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(Error::new("invalid DEFLATE code (ran out of codes)"))
    }
}

const LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXT: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DEXT: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

fn fixed_tables() -> (Huffman, Huffman) {
    let mut lengths = [0u8; 288];
    for (i, len) in lengths.iter_mut().enumerate() {
        *len = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    (Huffman::new(&lengths), Huffman::new(&[5u8; 30]))
}

fn dynamic_tables(reader: &mut BitReader) -> Result<(Huffman, Huffman)> {
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let hlit = reader.bits(5)? as usize + 257;
    let hdist = reader.bits(5)? as usize + 1;
    let hclen = reader.bits(4)? as usize + 4;
    let mut code_lengths = [0u8; 19];
    for &slot in ORDER.iter().take(hclen) {
        code_lengths[slot] = reader.bits(3)? as u8;
    }
    let code_huffman = Huffman::new(&code_lengths);
    let mut lengths = vec![0u8; hlit + hdist];
    let mut i = 0usize;
    while i < lengths.len() {
        match code_huffman.decode(reader)? {
            sym @ 0..=15 => {
                lengths[i] = sym as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return Err(Error::new("invalid DEFLATE code length repeat"));
                }
                let prev = lengths[i - 1];
                let count = 3 + reader.bits(2)? as usize;
                if i + count > lengths.len() {
                    return Err(Error::new("DEFLATE code length repeat overflows"));
                }
                for _ in 0..count {
                    lengths[i] = prev;
                    i += 1;
                }
            }
            17 => {
                let count = 3 + reader.bits(3)? as usize;
                if i + count > lengths.len() {
                    return Err(Error::new("DEFLATE code length repeat overflows"));
                }
                i += count;
            }
            18 => {
                let count = 11 + reader.bits(7)? as usize;
                if i + count > lengths.len() {
                    return Err(Error::new("DEFLATE code length repeat overflows"));
                }
                i += count;
            }
            _ => return Err(Error::new("invalid DEFLATE code length symbol")),
        }
    }
    if lengths[256] == 0 {
        return Err(Error::new("missing end-of-block code in DEFLATE tables"));
    }
    Ok((
        Huffman::new(&lengths[..hlit]),
        Huffman::new(&lengths[hlit..]),
    ))
}

/// Decompresses a gzip stream (RFC 1952) using the built-in inflate.
pub fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 18 {
        return Err(Error::new("gzip stream too short"));
    }
    if data[0] != 0x1F || data[1] != 0x8B {
        return Err(Error::new("not a gzip stream (bad magic)"));
    }
    if data[2] != 8 {
        return Err(Error::new(format!(
            "unsupported gzip compression method {}",
            data[2]
        )));
    }
    let flags = data[3];
    let mut pos = 10usize;
    if flags & 0x04 != 0 {
        if pos + 2 > data.len() {
            return Err(Error::new("truncated gzip FEXTRA field"));
        }
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + xlen;
    }
    if flags & 0x08 != 0 {
        pos = skip_cstr(data, pos, "FNAME")?;
    }
    if flags & 0x10 != 0 {
        pos = skip_cstr(data, pos, "FCOMMENT")?;
    }
    if flags & 0x02 != 0 {
        pos += 2;
    }
    if pos >= data.len() {
        return Err(Error::new("truncated gzip header"));
    }
    let mut out = Vec::new();
    inflate(&data[pos..], &mut out)?;
    let trailer = &data[data.len() - 8..];
    let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let isize_ = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    if crc32(&out) != crc {
        return Err(Error::new("gzip checksum mismatch"));
    }
    if (out.len() as u32) != isize_ {
        return Err(Error::new("gzip size trailer mismatch"));
    }
    Ok(out)
}

/// Inflates a raw DEFLATE stream (RFC 1951) appending to `out`.
fn inflate(data: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let mut reader = BitReader {
        data,
        byte: 0,
        bit: 0,
    };
    loop {
        let bfinal = reader.bits(1)?;
        match reader.bits(2)? {
            0 => {
                reader.align();
                if reader.byte + 4 > data.len() {
                    return Err(Error::new("truncated stored DEFLATE block"));
                }
                let len = u16::from_le_bytes([data[reader.byte], data[reader.byte + 1]]) as usize;
                let nlen = u16::from_le_bytes([data[reader.byte + 2], data[reader.byte + 3]]);
                if u16::from(!len as u8) | (u16::from(!(len >> 8) as u8) << 8) != nlen {
                    return Err(Error::new("stored DEFLATE block length check failed"));
                }
                reader.byte += 4;
                if reader.byte + len > data.len() {
                    return Err(Error::new("truncated stored DEFLATE block"));
                }
                out.extend_from_slice(&data[reader.byte..reader.byte + len]);
                reader.byte += len;
                reader.bit = 0;
            }
            1 => {
                let (lit, dist) = fixed_tables();
                inflate_block(&mut reader, out, &lit, &dist)?;
            }
            2 => {
                let (lit, dist) = dynamic_tables(&mut reader)?;
                inflate_block(&mut reader, out, &lit, &dist)?;
            }
            _ => return Err(Error::new("invalid DEFLATE block type 3")),
        }
        if bfinal == 1 {
            return Ok(());
        }
    }
}

/// Decodes one DEFLATE block with the given literal/length and distance tables.
fn inflate_block(
    reader: &mut BitReader,
    out: &mut Vec<u8>,
    lit: &Huffman,
    dist: &Huffman,
) -> Result<()> {
    loop {
        let sym = lit.decode(reader)?;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Ok(()),
            257..=285 => {
                let idx = sym as usize - 257;
                let len = LBASE[idx] + reader.bits(u32::from(LEXT[idx]))? as u16;
                let dsym = dist.decode(reader)?;
                if dsym >= 30 {
                    return Err(Error::new("invalid DEFLATE distance symbol"));
                }
                let d = DBASE[dsym as usize] + reader.bits(u32::from(DEXT[dsym as usize]))? as u16;
                let start = out
                    .len()
                    .checked_sub(d as usize)
                    .ok_or_else(|| Error::new("DEFLATE distance before start of output"))?;
                for k in 0..len {
                    let byte = out[start + k as usize];
                    out.push(byte);
                }
            }
            _ => return Err(Error::new("invalid DEFLATE literal/length symbol")),
        }
    }
}

/// Extracts a tar archive (ustar/GNU) into `dest`, refusing unsafe paths.
pub fn unpack_tar(data: &[u8], dest: &Path) -> Result<()> {
    let mut pos = 0usize;
    let mut long_name: Option<String> = None;
    let mut pax_path: Option<String> = None;
    while pos + 512 <= data.len() {
        let header = &data[pos..pos + 512];
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let size = octal_field(header, 124, 12)?;
        let typeflag = header[156];
        let data_start = pos + 512;
        let end = data_start
            .checked_add(size.div_ceil(512) * 512)
            .ok_or_else(|| Error::new("tar archive size overflow"))?;
        if end > data.len() {
            return Err(Error::new("truncated tar archive"));
        }
        let rel = if let Some(name) = long_name.take() {
            safe_rel_path(&name)?
        } else if let Some(name) = pax_path.take() {
            safe_rel_path(&name)?
        } else {
            let name = cstr_field(header, 0, 100);
            let prefix = cstr_field(header, 345, 155);
            let joined = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}/{name}")
            };
            safe_rel_path(&joined)?
        };
        match typeflag {
            b'0' | 0 => {
                if rel.as_os_str().is_empty() {
                    pos = end;
                    continue;
                }
                let path = dest.join(&rel);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| Error::new(format!("{}: {e}", path.display())))?;
                }
                std::fs::write(&path, &data[data_start..data_start + size])
                    .map_err(|e| Error::new(format!("{}: {e}", path.display())))?;
            }
            b'5' => {
                if rel.as_os_str().is_empty() {
                    pos = end;
                    continue;
                }
                let dir_path = dest.join(&rel);
                std::fs::create_dir_all(&dir_path)
                    .map_err(|e| Error::new(format!("{}: {e}", dir_path.display())))?;
            }
            b'L' => {
                long_name = Some(
                    String::from_utf8_lossy(&data[data_start..data_start + size])
                        .trim_end_matches('\0')
                        .trim_end_matches('\n')
                        .to_string(),
                );
            }
            b'x' | b'X' => {
                pax_path = pax_path_value(&data[data_start..data_start + size]);
            }
            b'g' | b'1' | b'2' | b'3' | b'4' | b'6' => {}
            other => {
                return Err(Error::new(format!("unsupported tar entry type {other:?}")));
            }
        }
        pos = end;
    }
    Ok(())
}

fn octal_field(header: &[u8], offset: usize, len: usize) -> Result<usize> {
    let text = cstr_field(header, offset, len);
    let text = text.trim_matches(|c: char| c == ' ' || c == '\0');
    if text.is_empty() {
        return Ok(0);
    }
    usize::from_str_radix(text, 8).map_err(|_| Error::new("invalid octal field in tar header"))
}

fn cstr_field(header: &[u8], offset: usize, len: usize) -> String {
    let end = header[offset..offset + len]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(len);
    String::from_utf8_lossy(&header[offset..offset + end]).into_owned()
}

/// Rejects absolute paths, `..` components, Windows drive letters and empty components.
fn safe_rel_path(name: &str) -> Result<std::path::PathBuf> {
    let mut path = std::path::PathBuf::new();
    for part in name.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(Error::new(format!(
                "tar entry {name:?} escapes the destination directory"
            )));
        }
        if part.contains(':') {
            return Err(Error::new(format!(
                "tar entry {name:?} contains a drive letter component"
            )));
        }
        path.push(part);
    }
    Ok(path)
}

/// Extracts the `path` record value from a pax extended header payload.
fn pax_path_value(payload: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(payload);
    for record in text.split('\n') {
        let record = record.trim_end_matches('\0');
        let Some((_len_text, rest)) = record.split_once(' ') else {
            continue;
        };
        let Some((key, value)) = rest.split_once('=') else {
            continue;
        };
        if key == "path" {
            return Some(value.to_string());
        }
    }
    None
}

/// Parses the registry index JSON into `(name, version)` pairs.
pub fn registry_versions(index_json: &[u8]) -> Vec<(String, String)> {
    #[derive(Clone, PartialEq)]
    enum Tok {
        Str(String),
        Colon,
        Open,
        Close,
    }
    let mut tokens = Vec::new();
    let bytes = index_json;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                tokens.push(Tok::Open);
                i += 1;
            }
            b'}' => {
                tokens.push(Tok::Close);
                i += 1;
            }
            b':' => {
                tokens.push(Tok::Colon);
                i += 1;
            }
            b'"' => {
                i += 1;
                let mut value = String::new();
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 1;
                    }
                    value.push(bytes[i] as char);
                    i += 1;
                }
                i += 1;
                tokens.push(Tok::Str(value));
            }
            _ => i += 1,
        }
    }
    let mut pairs = Vec::new();
    let mut depth = 0usize;
    let mut current_key;
    let mut seen_name: Option<String> = None;
    let mut idx = 0usize;
    while idx < tokens.len() {
        match &tokens[idx] {
            Tok::Open => depth += 1,
            Tok::Close => {
                depth -= 1;
                if depth == 1 {
                    seen_name = None;
                }
            }
            Tok::Str(value) => {
                if depth == 1 && idx + 1 < tokens.len() && tokens[idx + 1] == Tok::Colon {
                    current_key = Some(value.clone());
                    idx += 2;
                    if idx < tokens.len() {
                        if let Tok::Str(val) = &tokens[idx] {
                            match current_key.as_deref() {
                                Some("name") => seen_name = Some(val.clone()),
                                Some("version") => {
                                    if let Some(name) = seen_name.take() {
                                        pairs.push((name, val.clone()));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    continue;
                }
            }
            Tok::Colon => {}
        }
        idx += 1;
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal stored-block gzip payload for a byte slice.
    fn stored_gzip(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 3];
        out.push(0x01);
        let len = payload.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(&crc32(payload).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out
    }

    /// Builds a 512-byte tar header with the given name, size and typeflag.
    fn tar_header(name: &str, size: usize, typeflag: u8) -> Vec<u8> {
        let mut header = vec![0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        let size_field = format!("{size:011o}\0");
        header[124..136].copy_from_slice(size_field.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        let checksum = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(checksum.as_bytes());
        header
    }

    #[test]
    fn gunzip_and_unpack_tar_roundtrip() {
        let payload = b"hello typship";
        let mut tar = tar_header("pkg/typst.toml", payload.len(), b'0');
        tar.extend_from_slice(payload);
        tar.extend(std::iter::repeat_n(0u8, 512 - payload.len()));
        let gz = stored_gzip(&tar);
        let data = gunzip(&gz).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "typship-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        unpack_tar(&data, &dir).unwrap();
        let written = std::fs::read(dir.join("pkg").join("typst.toml")).unwrap();
        assert_eq!(written, payload);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn registry_versions_parses_sample() {
        let json = br#"[{"name":"example","version":"0.1.0"},{"name":"other","version":"1.2.3"}]"#;
        let pairs = registry_versions(json);
        assert_eq!(
            pairs,
            vec![
                ("example".to_string(), "0.1.0".to_string()),
                ("other".to_string(), "1.2.3".to_string()),
            ]
        );
    }

    #[test]
    fn safe_rel_path_rejects_dot_dot() {
        assert!(safe_rel_path("pkg/file").is_ok());
        assert!(safe_rel_path("../escape").is_err());
        assert!(safe_rel_path("C:/windows").is_err());
    }
}
