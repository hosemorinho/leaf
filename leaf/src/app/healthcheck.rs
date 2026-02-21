use std::time::Duration;

use anyhow::anyhow;
use tokio::time::Instant;

use crate::{
    app::SyncDnsClient,
    proxy::AnyOutboundHandler,
    session::{Session, SocksAddr},
};

const HTTP_HEAD_HOST: &str = "www.google.com";
const HTTP_HEAD_PORT: u16 = 80;
const HTTP_HEAD_PATH: &str = "/generate_204";

fn parse_http_status_code(buf: &[u8]) -> Option<u16> {
    let line_end = buf.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&buf[..line_end]).ok()?;
    let mut parts = line.split_whitespace();
    let protocol = parts.next()?;
    if !protocol.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}

pub async fn tcp(
    dns_client: SyncDnsClient,
    handler: AnyOutboundHandler,
) -> anyhow::Result<Duration> {
    let sess = Session {
        destination: SocksAddr::Domain(HTTP_HEAD_HOST.to_string(), HTTP_HEAD_PORT),
        new_conn_once: true,
        ..Default::default()
    };
    let start = Instant::now();
    let stream = crate::proxy::connect_stream_outbound(&sess, dns_client, &handler).await?;
    let mut stream = handler.stream()?.handle(&sess, None, stream).await?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let request = format!(
        "HEAD {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: leaf-healthcheck\r\n\r\n",
        HTTP_HEAD_PATH, HTTP_HEAD_HOST
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut buf = Vec::with_capacity(1024);
    let n = stream.read_buf(&mut buf).await?;
    if n == 0 {
        Err(anyhow!(
            "EOF during TCP health check for [{}]",
            handler.tag()
        ))
    } else {
        let status = parse_http_status_code(&buf).ok_or_else(|| {
            anyhow!(
                "Unexpected TCP health check response from [{}]: {}",
                handler.tag(),
                String::from_utf8_lossy(&buf)
            )
        })?;
        if (200..500).contains(&status) {
            Ok(Instant::now().duration_since(start))
        } else {
            Err(anyhow!(
                "HTTP status {} during TCP health check for [{}]",
                status,
                handler.tag()
            ))
        }
    }
}

pub async fn udp(
    dns_client: SyncDnsClient,
    handler: AnyOutboundHandler,
) -> anyhow::Result<Duration> {
    let addr = SocksAddr::Domain("healthcheck.leaf".to_string(), 80);
    let sess = Session {
        destination: addr.clone(),
        new_conn_once: true,
        ..Default::default()
    };
    let start = Instant::now();
    let dgram = crate::proxy::connect_datagram_outbound(&sess, dns_client, &handler).await?;
    let dgram = handler.datagram()?.handle(&sess, dgram).await?;
    let (mut recv, mut send) = dgram.split();
    send.send_to(b"PING", &addr).await?;
    let mut buf = [0u8; 2 * 1024];
    let (n, _src_addr) = recv.recv_from(&mut buf).await?;
    if &buf[..n] == b"PONG" {
        Ok(Instant::now().duration_since(start))
    } else {
        Err(anyhow!(
            "Unexpected UDP health check response from [{}]",
            handler.tag()
        ))
    }
}
