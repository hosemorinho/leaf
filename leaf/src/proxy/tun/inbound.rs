use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::{sink::SinkExt, stream::StreamExt};
use protobuf::Message;
use tokio::sync::mpsc::channel as tokio_channel;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};
use tracing::{debug, error, info, warn};

use crate::{
    app::dispatcher::Dispatcher,
    app::fake_dns::{FakeDns, FakeDnsMode},
    app::nat_manager::NatManager,
    app::nat_manager::UdpPacket,
    config::{Inbound, TunInboundSettings},
    option,
    session::{DatagramSource, Network, Session, SocksAddr},
    Runner,
};

use super::netstack;

async fn handle_inbound_stream(
    stream: Pin<Box<netstack::TcpStream>>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    inbound_tag: String,
    dispatcher: Arc<Dispatcher>,
    fakedns: Arc<FakeDns>,
) {
    let mut sess = Session {
        network: Network::Tcp,
        source: local_addr,
        local_addr: remote_addr,
        destination: SocksAddr::Ip(remote_addr),
        inbound_tag,
        ..Default::default()
    };
    // Whether to override the destination according to Fake DNS.
    if fakedns.is_fake_ip(&remote_addr.ip()).await {
        if let Some(domain) = fakedns.query_domain(&remote_addr.ip()).await {
            sess.destination = SocksAddr::Domain(domain, remote_addr.port());
        } else {
            // Although requests targeting fake IPs are assumed
            // never happen in real network traffic, which are
            // likely caused by poisoned DNS cache records, we
            // still have a chance to sniff the request domain
            // for TLS traffic in dispatcher.
            if remote_addr.port() != 443 && remote_addr.port() != 80 {
                debug!(
                    "No paired domain found for this fake IP: {}, connection is rejected.",
                    &remote_addr.ip()
                );
                return;
            }
        }
    }
    dispatcher.dispatch_stream(sess, stream).await;
}

async fn handle_inbound_datagram(
    socket: Pin<Box<netstack::UdpSocket>>,
    inbound_tag: String,
    nat_manager: Arc<NatManager>,
    fakedns: Arc<FakeDns>,
) {
    // The socket to receive/send packets from/to the netstack.
    let (ls, mut lr) = socket.split();
    let ls = Arc::new(ls);

    // The channel for sending back datagrams from NAT manager to netstack.
    let (l_tx, mut l_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) =
        tokio_channel(*crate::option::UDP_DOWNLINK_CHANNEL_SIZE);

    // Receive datagrams from NAT manager and send back to netstack.
    let fakedns_cloned = fakedns.clone();
    let ls_cloned = ls.clone();
    tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            let src_addr = match pkt.src_addr {
                SocksAddr::Ip(a) => a,
                SocksAddr::Domain(domain, port) => {
                    if let Some(ip) = fakedns_cloned.query_fake_ip(&domain).await {
                        SocketAddr::new(ip, port)
                    } else {
                        warn!(
                                "Received datagram with source address {}:{} without paired fake IP found.",
                                &domain, &port
                            );
                        continue;
                    }
                }
            };
            if let Err(e) = ls_cloned.send_to(&pkt.data[..], &src_addr, pkt.dst_addr.must_ip()) {
                warn!("A packet failed to send to the netstack: {}", e);
            }
        }
    });

    // Accept datagrams from netstack and send to NAT manager.
    loop {
        match lr.recv_from().await {
            Err(e) => {
                warn!("Failed to accept a datagram from netstack: {}", e);
            }
            Ok((data, src_addr, dst_addr)) => {
                // Fake DNS logic.
                if dst_addr.port() == 53 {
                    match fakedns.generate_fake_response(&data).await {
                        Ok(resp) => {
                            if let Err(e) = ls.send_to(resp.as_ref(), &dst_addr, &src_addr) {
                                warn!("A packet failed to send to the netstack: {}", e);
                            }
                            continue;
                        }
                        Err(err) => {
                            debug!("generate fake ip failed: {}", err);
                        }
                    }
                }

                // Whether to override the destination according to Fake DNS.
                //
                // WARNING
                //
                // This allows datagram to have a domain name as destination,
                // but real UDP traffic are sent with IP address only. If the
                // outbound for this datagram is a direct one, the outbound
                // would resolve the domain to IP address before sending out
                // the datagram. If the outbound is a proxy one, it would
                // require a proxy server with the ability to handle datagrams
                // with domain name destination, leaf itself of course supports
                // this feature very well.
                let dst_addr = if fakedns.is_fake_ip(&dst_addr.ip()).await {
                    if let Some(domain) = fakedns.query_domain(&dst_addr.ip()).await {
                        SocksAddr::Domain(domain, dst_addr.port())
                    } else {
                        debug!(
                            "No paired domain found for this fake IP: {}, datagram is rejected.",
                            &dst_addr.ip()
                        );
                        continue;
                    }
                } else {
                    SocksAddr::Ip(dst_addr)
                };

                let dgram_src = DatagramSource::new(src_addr, None);
                let pkt = UdpPacket::new(data, SocksAddr::Ip(src_addr), dst_addr);
                nat_manager
                    .send(None, &dgram_src, &inbound_tag, &l_tx, pkt)
                    .await;
            }
        }
    }
}

pub fn new(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> Result<Runner> {
    let settings = TunInboundSettings::parse_from_bytes(&inbound.settings)?;

    let empty_name = String::new();
    info!("TUN inbound: configuring (fd={}, auto={}, name={:?})",
        settings.fd, settings.auto,
        if settings.fd < 0 && !settings.auto { &settings.name } else { &empty_name });

    let tun = if settings.fd >= 0 {
        // Android/iOS: use raw fd from VPN service
        info!("TUN inbound: creating device from raw fd={}", settings.fd);
        #[cfg(target_family = "unix")]
        {
            unsafe { tun_rs::AsyncDevice::from_fd(settings.fd as _) }.map_err(|e| {
                error!("TUN inbound: from_fd({}) FAILED: {}", settings.fd, e);
                anyhow!("create tun from fd {} failed: {}", settings.fd, e)
            })?
        }
        #[cfg(not(target_family = "unix"))]
        {
            return Err(anyhow!("tun fd is only supported on Unix-like systems"));
        }
    } else if settings.auto {
        info!("TUN inbound: auto mode — name={}, addr={}/{}, gw={}, mtu=1500",
            &*option::DEFAULT_TUN_NAME, &*option::DEFAULT_TUN_IPV4_ADDR,
            &*option::DEFAULT_TUN_IPV4_MASK, &*option::DEFAULT_TUN_IPV4_GW);
        // DeviceBuilder is only available on desktop platforms (not Android/iOS)
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let dev = tun_rs::DeviceBuilder::new()
                .name(&*option::DEFAULT_TUN_NAME)
                .mtu(1500)
                .ipv4(
                    (*option::DEFAULT_TUN_IPV4_ADDR).clone(),
                    (*option::DEFAULT_TUN_IPV4_MASK).clone(),
                    Some((*option::DEFAULT_TUN_IPV4_GW).clone()),
                )
                .build_async()
                .map_err(|e| {
                    error!("TUN inbound: build_async (auto) FAILED: {}", e);
                    anyhow!("create tun (auto) failed: {}. On Windows: ensure wintun.dll is \
                             next to the executable and the app is running as Administrator.", e)
                })?;
            info!("TUN inbound: auto mode device created successfully");
            dev
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            return Err(anyhow!(
                "TUN auto mode is not supported on mobile platforms. \
                 Provide a TUN file descriptor from the VPN service instead."
            ));
        }
    } else {
        info!("TUN inbound: manual mode — name={}, addr={}/{}, gw={}, mtu={}",
            &settings.name, &settings.address, &settings.netmask,
            &settings.gateway, settings.mtu);
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let dev = tun_rs::DeviceBuilder::new()
                .name(&settings.name)
                .mtu(settings.mtu as u16)
                .ipv4(settings.address.clone(), settings.netmask.clone(), Some(settings.gateway.clone()))
                .build_async()
                .map_err(|e| {
                    error!("TUN inbound: build_async (manual) FAILED: {}", e);
                    anyhow!("create tun (manual) failed: {}. On Windows: ensure wintun.dll is \
                             next to the executable and the app is running as Administrator.", e)
                })?;
            info!("TUN inbound: manual mode device created successfully");
            dev
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            return Err(anyhow!(
                "TUN manual mode is not supported on mobile platforms. \
                 Provide a TUN file descriptor from the VPN service instead."
            ));
        }
    };

    if settings.auto {
        assert!(settings.fd == -1, "tun-auto is not compatible with tun-fd");
    }

    // FIXME it's a bad design to have 2 lists in config while we need only one
    let fake_dns_exclude = settings.fake_dns_exclude;
    let fake_dns_include = settings.fake_dns_include;
    if !fake_dns_exclude.is_empty() && !fake_dns_include.is_empty() {
        return Err(anyhow!(
            "fake DNS run in either include mode or exclude mode"
        ));
    }
    let (fake_dns_mode, fake_dns_filters) = if !fake_dns_include.is_empty() {
        (FakeDnsMode::Include, fake_dns_include)
    } else {
        (FakeDnsMode::Exclude, fake_dns_exclude)
    };
    let fakedns = Arc::new(FakeDns::new(fake_dns_mode, fake_dns_filters));

    let (stack, mut tcp_listener, udp_socket) = netstack::NetStack::with_buffer_size(
        *crate::option::NETSTACK_OUTPUT_CHANNEL_SIZE,
        *crate::option::NETSTACK_UDP_UPLINK_CHANNEL_SIZE,
    )?;

    Ok(Box::pin(async move {
        let inbound_tag = inbound.tag.clone();

        let framed = tun_rs::async_framed::DeviceFramed::new(
            tun,
            tun_rs::async_framed::BytesCodec::new(),
        );
        let (mut tun_sink, mut tun_stream) = framed.split::<Bytes>();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let mut futs: Vec<Runner> = Vec::new();

        // netstack → TUN: read packets from stack, send to TUN device
        futs.push(Box::pin(async move {
            while let Some(pkt) = stack_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) = tun_sink.send(Bytes::from(pkt)).await {
                            error!("Sending packet to TUN failed: {}", e);
                            return;
                        }
                    }
                    Err(e) => {
                        error!("NetStack error: {}", e);
                        return;
                    }
                }
            }
        }));

        // TUN → netstack: read packets from TUN device, send to stack
        futs.push(Box::pin(async move {
            while let Some(pkt) = tun_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) = stack_sink.send(pkt.into()).await {
                            error!("Sending packet to NetStack failed: {}", e);
                            return;
                        }
                    }
                    Err(e) => {
                        error!("TUN read error: {}", e);
                        return;
                    }
                }
            }
        }));

        // TCP: extract connections from stack and dispatch
        let inbound_tag_cloned = inbound_tag.clone();
        let fakedns_cloned = fakedns.clone();
        futs.push(Box::pin(async move {
            while let Some((stream, local_addr, remote_addr)) = tcp_listener.next().await {
                tokio::spawn(handle_inbound_stream(
                    stream,
                    local_addr,
                    remote_addr,
                    inbound_tag_cloned.clone(),
                    dispatcher.clone(),
                    fakedns_cloned.clone(),
                ));
            }
        }));

        // UDP: handle datagrams via NAT manager
        futs.push(Box::pin(async move {
            handle_inbound_datagram(udp_socket, inbound_tag, nat_manager, fakedns.clone()).await;
        }));

        info!("start tun inbound");
        futures::future::select_all(futs).await;
    }))
}
