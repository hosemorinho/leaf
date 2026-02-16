use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tracing::debug;

#[cfg(target_os = "android")]
use std::os::unix::io::AsRawFd;

/// A parsed DoH server endpoint. Only IP-based hosts are allowed
/// to avoid circular DNS dependency.
#[derive(Clone, Debug)]
pub struct DoHServer {
    pub ip: IpAddr,
    pub port: u16,
    pub path: String,
    /// HTTP/1.1 Host header authority value.
    /// - IPv6 uses brackets, e.g. `[2606:4700::1111]`
    /// - Non-default ports append `:port`
    pub host_header: String,
    /// TLS server name used for certificate verification (IP literal, no port/brackets).
    pub tls_server_name: String,
}

impl DoHServer {
    /// Parse a DoH URL like `https://1.1.1.1/dns-query` or `https://[2606:4700::1111]/dns-query`.
    /// Only IP addresses are accepted as the host to avoid circular DNS lookups.
    pub fn parse(url: &str) -> Result<Self> {
        let url = url.trim();
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| anyhow!("DoH URL must start with https://: {}", url))?;

        // Split host and path
        let (host_part, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/dns-query"),
        };

        // Parse host:port — handle IPv6 bracket notation
        let (host_str, port) = if host_part.starts_with('[') {
            // IPv6: [::1]:443 or [::1]
            let end_bracket = host_part
                .find(']')
                .ok_or_else(|| anyhow!("missing closing bracket in IPv6 address: {}", url))?;
            let ip_str = &host_part[1..end_bracket];
            let port = if host_part.len() > end_bracket + 1 {
                let port_str = host_part[end_bracket + 1..]
                    .strip_prefix(':')
                    .ok_or_else(|| anyhow!("invalid port separator in: {}", url))?;
                port_str.parse::<u16>()?
            } else {
                443
            };
            (ip_str, port)
        } else {
            // IPv4 or plain: 1.1.1.1:443 or 1.1.1.1
            match host_part.rfind(':') {
                Some(idx) => {
                    let maybe_port = &host_part[idx + 1..];
                    if let Ok(p) = maybe_port.parse::<u16>() {
                        (&host_part[..idx], p)
                    } else {
                        (host_part, 443)
                    }
                }
                None => (host_part, 443),
            }
        };

        let ip: IpAddr = host_str
            .parse()
            .map_err(|_| anyhow!("DoH host must be an IP address, got: {}", host_str))?;

        let tls_server_name = ip.to_string();
        let host_authority = match ip {
            IpAddr::V4(_) => tls_server_name.clone(),
            IpAddr::V6(_) => format!("[{}]", tls_server_name),
        };
        let host_header = if port == 443 {
            host_authority
        } else {
            format!("{}:{}", host_authority, port)
        };

        Ok(DoHServer {
            ip,
            port,
            path: path.to_string(),
            host_header,
            tls_server_name,
        })
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}

type TlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

/// Pooled TLS connection wrapper.
struct PooledConnection {
    stream: TlsStream,
}

/// DoH client that races queries across multiple servers via direct TLS connections.
pub struct DoHClient {
    servers: Vec<DoHServer>,
    tls_config: Arc<ClientConfig>,
    /// Per-server connection pool (single connection per server for simplicity).
    pools: Vec<Mutex<Option<PooledConnection>>>,
}

impl DoHClient {
    pub fn new(servers: Vec<DoHServer>) -> Result<Self> {
        if servers.is_empty() {
            return Err(anyhow!("no DoH servers configured"));
        }

        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        #[cfg(feature = "rustls-tls-aws-lc")]
        let provider = rustls::crypto::aws_lc_rs::default_provider().into();
        #[cfg(not(feature = "rustls-tls-aws-lc"))]
        let provider = rustls::crypto::ring::default_provider().into();

        let tls_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow!("TLS config error: {}", e))?
            .with_root_certificates(roots)
            .with_no_client_auth();

        let pools = servers.iter().map(|_| Mutex::new(None)).collect();

        Ok(DoHClient {
            servers,
            tls_config: Arc::new(tls_config),
            pools,
        })
    }

    /// Create a direct TCP connection to a DoH server IP, bypassing the proxy dispatcher.
    async fn direct_tcp_connect(&self, addr: &SocketAddr) -> io::Result<tokio::net::TcpStream> {
        let socket = match addr {
            SocketAddr::V4(..) => TcpSocket::new_v4()?,
            SocketAddr::V6(..) => TcpSocket::new_v6()?,
        };

        crate::proxy::bind_outbound_tcp_socket(&socket, addr).await?;

        #[cfg(target_os = "android")]
        crate::proxy::protect_socket(socket.as_raw_fd()).await?;

        let stream = timeout(Duration::from_secs(5), socket.connect(*addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoH TCP connect timeout"))?
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("DoH TCP connect to {} failed: {}", addr, e),
                )
            })?;

        Ok(stream)
    }

    /// Establish a new TLS connection to the specified server.
    async fn tls_connect(&self, server: &DoHServer) -> io::Result<TlsStream> {
        let addr = server.socket_addr();
        let tcp_stream = self.direct_tcp_connect(&addr).await?;

        let connector = TlsConnector::from(self.tls_config.clone());
        let domain = ServerName::try_from(server.tls_server_name.as_str())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid DoH server name {}: {}", server.tls_server_name, e),
                )
            })?
            .to_owned();

        let tls_stream = timeout(
            Duration::from_secs(5),
            connector.connect(domain, tcp_stream),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoH TLS handshake timeout"))?
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("DoH TLS handshake with {} failed: {}", addr, e),
            )
        })?;

        debug!("DoH TLS connected to {}", addr);
        Ok(tls_stream)
    }

    /// Get a pooled connection or create a new one.
    async fn get_or_connect(&self, server_idx: usize) -> io::Result<TlsStream> {
        let mut pool = self.pools[server_idx].lock().await;
        if let Some(conn) = pool.take() {
            return Ok(conn.stream);
        }
        drop(pool);
        self.tls_connect(&self.servers[server_idx]).await
    }

    /// Return a connection to the pool for reuse.
    async fn return_to_pool(&self, server_idx: usize, stream: TlsStream) {
        let mut pool = self.pools[server_idx].lock().await;
        *pool = Some(PooledConnection { stream });
    }

    /// Send a DNS wire-format query to a specific DoH server and return the wire-format response.
    /// Uses HTTP/1.1 POST per RFC 8484.
    pub async fn query(&self, server_idx: usize, dns_wire: &[u8]) -> Result<Vec<u8>> {
        let server = &self.servers[server_idx];
        let mut stream = self.get_or_connect(server_idx).await?;

        // Build HTTP/1.1 POST request
        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/dns-message\r\n\
             Accept: application/dns-message\r\n\
             Content-Length: {}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            server.path,
            server.host_header,
            dns_wire.len()
        );

        // Send request
        if let Err(e) = stream.write_all(request.as_bytes()).await {
            debug!(
                "DoH write header to {} failed: {}, reconnecting",
                server.socket_addr(),
                e
            );
            stream = self.tls_connect(server).await?;
            stream.write_all(request.as_bytes()).await?;
        }
        stream
            .write_all(dns_wire)
            .await
            .map_err(|e| anyhow!("DoH write body to {} failed: {}", server.socket_addr(), e))?;
        stream.flush().await?;

        // Read HTTP response
        match self.read_http_response(&mut stream, server_idx).await {
            Ok(body) => {
                // Return connection to pool for reuse
                self.return_to_pool(server_idx, stream).await;
                Ok(body)
            }
            Err(e) => {
                // Connection is broken, don't return to pool
                Err(e)
            }
        }
    }

    /// Read a minimal HTTP/1.1 response: status line + headers + body.
    async fn read_http_response(
        &self,
        stream: &mut TlsStream,
        _server_idx: usize,
    ) -> Result<Vec<u8>> {
        // Read headers (up to 4KB should be more than enough)
        let mut header_buf = Vec::with_capacity(1024);
        let mut byte = [0u8; 1];
        let mut headers_done = false;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

        while !headers_done {
            if tokio::time::Instant::now() > deadline {
                return Err(anyhow!("DoH response header read timeout"));
            }
            match timeout(Duration::from_secs(10), stream.read(&mut byte)).await {
                Ok(Ok(1)) => {
                    header_buf.push(byte[0]);
                    // Check for \r\n\r\n end-of-headers
                    if header_buf.len() >= 4 && &header_buf[header_buf.len() - 4..] == b"\r\n\r\n" {
                        headers_done = true;
                    }
                    if header_buf.len() > 4096 {
                        return Err(anyhow!("DoH response headers too large"));
                    }
                }
                Ok(Ok(_)) => return Err(anyhow!("DoH connection closed during headers")),
                Ok(Err(e)) => return Err(anyhow!("DoH header read error: {}", e)),
                Err(_) => return Err(anyhow!("DoH header read timeout")),
            }
        }

        let header_str = String::from_utf8_lossy(&header_buf);

        // Parse status line
        let status_line = header_str
            .lines()
            .next()
            .ok_or_else(|| anyhow!("empty DoH response"))?;
        if !status_line.contains("200") {
            return Err(anyhow!("DoH HTTP error: {}", status_line));
        }

        // Parse Content-Length
        let content_length = header_str
            .lines()
            .find_map(|line| {
                let lower = line.to_lowercase();
                if lower.starts_with("content-length:") {
                    lower
                        .strip_prefix("content-length:")
                        .and_then(|v| v.trim().parse::<usize>().ok())
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("DoH response missing Content-Length"))?;

        if content_length > 65535 {
            return Err(anyhow!("DoH response body too large: {}", content_length));
        }

        // Read body
        let mut body = vec![0u8; content_length];
        timeout(Duration::from_secs(10), stream.read_exact(&mut body))
            .await
            .map_err(|_| anyhow!("DoH body read timeout"))?
            .map_err(|e| anyhow!("DoH body read error: {}", e))?;

        Ok(body)
    }

    /// Number of configured servers.
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Get server info for logging.
    pub fn server_addr(&self, idx: usize) -> SocketAddr {
        self.servers[idx].socket_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_default_port() {
        let s = DoHServer::parse("https://1.1.1.1/dns-query").unwrap();
        assert_eq!(s.ip, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(s.port, 443);
        assert_eq!(s.path, "/dns-query");
        assert_eq!(s.host_header, "1.1.1.1");
        assert_eq!(s.tls_server_name, "1.1.1.1");
    }

    #[test]
    fn test_parse_ipv4_custom_port() {
        let s = DoHServer::parse("https://8.8.8.8:8443/resolve").unwrap();
        assert_eq!(s.ip, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(s.port, 8443);
        assert_eq!(s.path, "/resolve");
        assert_eq!(s.host_header, "8.8.8.8:8443");
        assert_eq!(s.tls_server_name, "8.8.8.8");
    }

    #[test]
    fn test_parse_ipv4_no_path() {
        let s = DoHServer::parse("https://1.1.1.1").unwrap();
        assert_eq!(s.path, "/dns-query");
    }

    #[test]
    fn test_parse_ipv6() {
        let s = DoHServer::parse("https://[2606:4700::1111]/dns-query").unwrap();
        assert_eq!(s.ip, "2606:4700::1111".parse::<IpAddr>().unwrap());
        assert_eq!(s.port, 443);
        assert_eq!(s.host_header, "[2606:4700::1111]");
        assert_eq!(s.tls_server_name, "2606:4700::1111");
    }

    #[test]
    fn test_parse_ipv6_with_port() {
        let s = DoHServer::parse("https://[::1]:8443/dns-query").unwrap();
        assert_eq!(s.ip, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(s.port, 8443);
        assert_eq!(s.host_header, "[::1]:8443");
        assert_eq!(s.tls_server_name, "::1");
    }

    #[test]
    fn test_reject_hostname() {
        assert!(DoHServer::parse("https://dns.google/dns-query").is_err());
    }

    #[test]
    fn test_reject_http() {
        assert!(DoHServer::parse("http://1.1.1.1/dns-query").is_err());
    }
}
