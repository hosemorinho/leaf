use std::cmp;
use std::convert::TryFrom;
use std::io;
use std::str;
use std::{net::IpAddr, pin::Pin, task::Context, task::Poll};

use ::http::{Method, Uri};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    proxy::*,
    session::{Session, SocksAddr, SocksAddrWireType},
};

// ---------------------------------------------------------------------------
// Shared constants (from http handler)
// ---------------------------------------------------------------------------

const BUFFER_SIZE: usize = 1024;
const EOL: [u8; 2] = [13, 10];
const EOH: [u8; 4] = [13, 10, 13, 10];

fn bad_request() -> io::Error {
    io::Error::other("bad request")
}

fn split_slice_once(s: &[u8], sep: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    s.windows(sep.len())
        .position(|w| w == sep)
        .map(|loc| (s[..loc].to_vec(), s[loc..].to_vec()))
}

// ---------------------------------------------------------------------------
// HTTP helpers (inlined from proxy/http/inbound/stream.rs)
// ---------------------------------------------------------------------------

/// Parse a URI into a SocksAddr (local function to avoid duplicate trait impl).
fn socks_addr_from_uri(uri: &Uri) -> io::Result<SocksAddr> {
    let host = uri.host().ok_or(bad_request())?;
    let port = uri
        .port_u16()
        .or_else(|| match uri.scheme_str() {
            Some("http") => Some(80),
            Some("https") => Some(443),
            _ => None,
        })
        .ok_or(bad_request())?;
    let addr = if let Ok(host) = host.parse::<IpAddr>() {
        SocksAddr::from((host, port))
    } else {
        SocksAddr::try_from((host, port))?
    };
    Ok(addr)
}

enum TargetFormat {
    Origin,
    Absolute,
    Authority,
    Asterisk,
}

struct RequestHead {
    method: Method,
    uri: Uri,
    version: String,
    headers: Vec<(String, String)>,
    target_format: TargetFormat,
}

impl RequestHead {
    fn parse_request_line(request_line: &[u8]) -> io::Result<(Method, Uri, String)> {
        let mut tokens = str::from_utf8(request_line).unwrap_or("").splitn(3, ' ');
        let method = match Method::try_from(tokens.next().unwrap_or("")) {
            Ok(v) => v,
            Err(_e) => return Err(bad_request()),
        };
        let uri = match Uri::try_from(tokens.next().unwrap_or("")) {
            Ok(v) => v,
            Err(_e) => return Err(bad_request()),
        };
        let version = tokens.next().unwrap_or("HTTP/1.1");
        Ok((method, uri, version.to_string()))
    }

    fn parse_headers(header_lines: &[u8]) -> io::Result<Vec<(String, String)>> {
        let mut headers = Vec::new();
        let lines = str::from_utf8(header_lines).unwrap_or("").split("\r\n");
        for line in lines {
            let (name, value) = match line.split_once(':') {
                Some((n, v)) => (n.trim(), v.trim()),
                None => continue,
            };
            headers.push((name.to_string(), value.to_string()));
        }
        Ok(headers)
    }

    fn set_header(&mut self, name: String, value: String) {
        for (i, (n, _v)) in self.headers.iter().enumerate() {
            if n.to_lowercase() == name.to_lowercase() {
                self.headers[i] = (n.clone(), value);
                return;
            }
        }
        self.headers.push((name, value));
    }
}

impl From<RequestHead> for Vec<u8> {
    fn from(v: RequestHead) -> Self {
        let mut head = Vec::new();
        let request_line = format!("{} {} {}\r\n", v.method, v.uri, v.version);
        head.append(&mut request_line.into_bytes());
        for (name, value) in v.headers {
            let header = format!("{}: {}\r\n", name, value);
            head.append(&mut header.into_bytes());
        }
        head.extend_from_slice("\r\n".as_bytes());
        head
    }
}

impl TryFrom<Vec<u8>> for RequestHead {
    type Error = io::Error;
    fn try_from(head: Vec<u8>) -> Result<Self, Self::Error> {
        let (request_line, header) = split_slice_once(&head, &EOL).unwrap_or((head, Vec::new()));
        let (method, uri, version) = RequestHead::parse_request_line(&request_line)?;
        let headers = RequestHead::parse_headers(&header)?;
        let target_format = if uri == "*" {
            TargetFormat::Asterisk
        } else if uri.scheme().is_some() {
            TargetFormat::Absolute
        } else if method == Method::CONNECT {
            TargetFormat::Authority
        } else {
            TargetFormat::Origin
        };
        Ok(RequestHead {
            method,
            uri,
            version,
            headers,
            target_format,
        })
    }
}

// ---------------------------------------------------------------------------
// HttpStream wrapper (from proxy/http/inbound/stream.rs)
// ---------------------------------------------------------------------------

struct HttpStream {
    cache: Vec<u8>,
    destination: Option<SocksAddr>,
    origin: AnyStream,
}

impl HttpStream {
    async fn sniff(&mut self) -> io::Result<()> {
        let (head_buf, mut rest_buf) = self.drain(&EOH).await?;
        let mut head = RequestHead::try_from(head_buf)?;

        let addr = socks_addr_from_uri(&head.uri)?;
        self.destination = Some(addr.clone());

        match head.target_format {
            TargetFormat::Absolute => {
                if rest_buf.starts_with(&EOH) {
                    let _ = rest_buf.drain(..EOH.len());
                }
                let path_and_query = head
                    .uri
                    .path_and_query()
                    .map(|paq| paq.as_str())
                    .unwrap_or("/");
                head.uri = path_and_query.parse().unwrap();
                head.set_header("host".to_string(), addr.to_string());
                self.cache.clear();
                self.cache.append(&mut head.into());
                self.cache.append(&mut rest_buf);
                Ok(())
            }
            TargetFormat::Authority => {
                self.origin
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await?;
                Ok(())
            }
            _ => Err(bad_request()),
        }
    }

    async fn drain(&mut self, stop_sign: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut data = Vec::new();
        let mut buf = BytesMut::with_capacity(BUFFER_SIZE);
        loop {
            buf.clear();
            let n = self.origin.read_buf(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }
            data.extend_from_slice(&buf[..n]);
            match split_slice_once(&data, stop_sign) {
                Some(v) => return Ok(v),
                None => continue,
            }
        }
    }
}

impl AsyncRead for HttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.cache.is_empty() {
            let n = cmp::min(buf.capacity(), self.cache.len());
            let cached_data = self.cache.drain(..n);
            buf.put_slice(cached_data.as_slice());
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.origin).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.origin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.origin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.origin).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// PeekedStream — wraps a stream with a prepended byte buffer
// ---------------------------------------------------------------------------

struct PeekedStream {
    peeked: Vec<u8>,
    inner: AnyStream,
}

impl AsyncRead for PeekedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.peeked.is_empty() {
            let n = cmp::min(buf.capacity(), self.peeked.len());
            let data = self.peeked.drain(..n);
            buf.put_slice(data.as_slice());
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PeekedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Mixed handler — peek first byte to detect SOCKS5 vs HTTP
// ---------------------------------------------------------------------------

pub struct Handler;

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        // Read the first byte to detect protocol
        let mut first = [0u8; 1];
        stream.read_exact(&mut first).await?;

        if first[0] == 0x05 {
            // SOCKS5 — handle inline (first byte already consumed)
            handle_socks5(sess, stream).await
        } else {
            // HTTP — wrap with PeekedStream so the first byte is not lost
            let peeked = PeekedStream {
                peeked: first.to_vec(),
                inner: stream,
            };
            let boxed: AnyStream = Box::new(peeked);
            let mut http_stream = HttpStream {
                cache: Vec::new(),
                destination: None,
                origin: boxed,
            };
            http_stream.sniff().await?;
            sess.destination = http_stream.destination.clone().ok_or(bad_request())?;
            Ok(InboundTransport::Stream(Box::new(http_stream), sess))
        }
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 handling (inlined from proxy/socks/inbound/stream.rs)
// First byte (0x05) already consumed by the mixed handler.
// ---------------------------------------------------------------------------

async fn handle_socks5(
    mut sess: Session,
    mut stream: AnyStream,
) -> io::Result<AnyInboundTransport> {
    let mut buf = BytesMut::new();

    // Auth negotiation — version byte already read, read nmethods
    buf.resize(1, 0);
    stream.read_exact(&mut buf[..]).await?;
    let nmethods = buf[0] as usize;
    if nmethods == 0 {
        return Err(io::Error::other("no socks5 authentication method specified"));
    }
    buf.resize(nmethods, 0);
    stream.read_exact(&mut buf[..]).await?;

    // Accept "no auth" (0x00)
    let mut method_accepted = false;
    let mut method_idx: u8 = 0;
    for (idx, method) in buf[..].iter().enumerate() {
        if *method == 0x00 {
            method_accepted = true;
            method_idx = idx as u8;
            break;
        }
    }
    if !method_accepted {
        stream.write_all(&[0x05, 0xff]).await?;
        return Err(io::Error::other("unsupported socks5 authentication methods"));
    }
    stream.write_all(&[0x05, method_idx]).await?;

    // Request
    buf.resize(3, 0);
    stream.read_exact(&mut buf[..]).await?;
    if buf[0] != 0x05 {
        return Err(io::Error::other(format!("unknown socks version {}", buf[0])));
    }
    if buf[2] != 0x00 {
        return Err(io::Error::other("non-zero socks5 reserved field"));
    }
    let cmd = buf[1];
    if cmd != 0x01 && cmd != 0x03 {
        return Err(io::Error::other(format!("unsupported socks5 cmd {}", cmd)));
    }

    let destination = SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await?;

    match cmd {
        // CONNECT
        0x01 => {
            buf.clear();
            buf.put_u8(0x05);
            buf.put_u8(0x00);
            buf.put_u8(0x00);
            let resp_addr = SocksAddr::any();
            resp_addr.write_buf(&mut buf, SocksAddrWireType::PortLast);
            stream.write_all(&buf[..]).await?;
            sess.destination = destination;
            Ok(InboundTransport::Stream(stream, sess))
        }
        // UDP ASSOCIATE
        0x03 => {
            buf.clear();
            buf.put_u8(0x05);
            buf.put_u8(0x00);
            buf.put_u8(0x00);
            let relay_addr = SocksAddr::from(sess.local_addr);
            relay_addr.write_buf(&mut buf, SocksAddrWireType::PortLast);
            stream.write_all(&buf[..]).await?;
            tokio::spawn(async move {
                let mut buf = [0u8; 1];
                let _ = stream.read_exact(&mut buf).await;
            });
            Ok(InboundTransport::Empty)
        }
        _ => Err(io::Error::other("invalid cmd")),
    }
}
