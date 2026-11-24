use super::*;
use std::collections::HashMap;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

#[derive(Debug)]
struct MapRequest {
    nonce: [u8; 12],
    port: u16,
    lifetime: u32,
    accepted: bool,
    suggested_port: u16,
    suggested_address: std::net::Ipv6Addr,
}

struct Gateway {
    requests: mpsc::UnboundedReceiver<MapRequest>,
    upnp: upnp::Gateway,
    pcp_task: AbortOnDropHandle<()>,
    upnp_task: AbortOnDropHandle<()>,
}

impl Gateway {
    async fn start() -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 5351)).await.unwrap();
        let (requests, received) = mpsc::unbounded_channel();
        let pcp_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut nonces = HashMap::new();
            let mut bytes = [0u8; 128];
            loop {
                let (size, peer) = match socket.recv_from(&mut bytes).await {
                    Ok(packet) => packet,
                    // Windows reports the closed deletion-request socket's ICMP reply here.
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => continue,
                    Err(error) => panic!("gateway receive failed: {error}"),
                };
                assert!(peer.ip().is_loopback());
                assert_eq!((bytes[0], bytes[1], size), (2, 1, 60));
                let nonce = bytes[24..36].try_into().unwrap();
                let port = u16::from_be_bytes(bytes[40..42].try_into().unwrap());
                let lifetime = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
                let suggested_port = u16::from_be_bytes(bytes[42..44].try_into().unwrap());
                let suggested_address =
                    std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[44..60]).unwrap());
                let accepted = nonces.get(&port).is_none_or(|existing| *existing == nonce);
                let mut response = vec![0u8; 24];
                response[0] = 2;
                response[1] = 129;
                // RFC 6887 section 11.3 rejects a new nonce for an active mapping.
                response[3] = if accepted { 0 } else { 2 };
                response[4..8].copy_from_slice(&lifetime.to_be_bytes());
                response[8..12].copy_from_slice(&1u32.to_be_bytes());
                response.extend_from_slice(&bytes[24..60]);
                response[42..44].copy_from_slice(&40000u16.to_be_bytes());
                response[44..60]
                    .copy_from_slice(&Ipv4Addr::new(203, 0, 113, 8).to_ipv6_mapped().octets());
                if accepted {
                    if lifetime == 0 {
                        nonces.remove(&port);
                    } else {
                        nonces.insert(port, nonce);
                    }
                }
                eprintln!(
                    "PCP port={port} nonce={nonce:x?} lifetime={lifetime} suggested={suggested_address}:{suggested_port} accepted={accepted}"
                );
                requests
                    .send(MapRequest {
                        nonce,
                        port,
                        lifetime,
                        accepted,
                        suggested_port,
                        suggested_address,
                    })
                    .unwrap();
                socket.send_to(&response, peer).await.unwrap();
            }
        }));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upnp = upnp::Gateway {
            addr: listener.local_addr().unwrap(),
            root_url: "/".into(),
            control_url: "/test".into(),
            control_schema_url: "/schema".into(),
            control_schema: HashMap::new(),
            provider: igd_next::aio::tokio::Tokio,
        };
        let upnp_task = AbortOnDropHandle::new(tokio::spawn(async move {
            while let Ok((mut connection, peer)) = listener.accept().await {
                assert!(peer.ip().is_loopback());
                let mut request = [0; 4096];
                let _ = connection.read(&mut request).await;
                connection.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            }
        }));
        Self {
            requests: received,
            upnp,
            pcp_task,
            upnp_task,
        }
    }

    async fn request(&mut self) -> MapRequest {
        tokio::time::timeout(Duration::from_secs(2), self.requests.recv())
            .await
            .unwrap()
            .unwrap()
    }

    async fn close(self) {
        self.pcp_task.abort();
        self.upnp_task.abort();
        let _ = self.pcp_task.await;
        let _ = self.upnp_task.await;
    }
}

async fn renew_with_probe_age(age: Duration) {
    let mut gateway = Gateway::start().await;
    let first_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let first_port = NonZeroU16::new(first_socket.local_addr().unwrap().port()).unwrap();
    let (_tx, rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);
    let (mut service, mut address) =
        Service::new(Config::default(), rx, Arc::new(Metrics::default()));
    service.local_port = Some(first_port);
    service.full_probe.last_pcp = Some(Instant::now());
    // Any alternate UPnP request stays in this fixture; no SSDP or real router is used.
    service.full_probe.last_upnp_gateway_addr = Some((gateway.upnp.clone(), Instant::now()));
    service.start_mapping(Ipv4Addr::LOCALHOST, first_port, Ipv4Addr::LOCALHOST, None);
    let created = service.mapping_task.take().unwrap().await.unwrap();
    assert!(created.is_ok());
    service.on_mapping_result(Ok(created));
    let first = gateway.request().await;
    assert!(first.accepted && first.port == first_port.get());
    assert!(address.borrow_and_update().is_some());

    let last_probe = Instant::now() - age;
    service.full_probe.last_pcp = Some(last_probe);
    service.full_probe.last_probe = last_probe;
    service
        .full_probe
        .last_upnp_gateway_addr
        .as_mut()
        .unwrap()
        .1 = last_probe;
    let external = service.current_mapping.external();
    service.start_mapping(
        Ipv4Addr::LOCALHOST,
        first_port,
        Ipv4Addr::LOCALHOST,
        external,
    );
    let renewed = service.mapping_task.take().unwrap().await.unwrap();
    assert!(
        renewed.is_ok(),
        "an active PCP lease must renew through its existing protocol and nonce: {renewed:?}"
    );
    service.on_mapping_result(Ok(renewed));
    let refresh = gateway.request().await;
    assert!(refresh.accepted && refresh.nonce == first.nonce && refresh.port == first.port);
    assert_eq!(refresh.suggested_port, 40000);
    assert_eq!(
        refresh.suggested_address,
        Ipv4Addr::new(203, 0, 113, 8).to_ipv6_mapped()
    );
    assert!(
        !address.has_changed().unwrap(),
        "same mapped address must not be republished"
    );

    service.update_local_port(None).await;
    let deleted = gateway.request().await;
    assert!(deleted.accepted && deleted.lifetime == 0 && deleted.nonce == first.nonce);
    assert!(address.borrow_and_update().is_none());
    let replacement_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let replacement_port =
        NonZeroU16::new(replacement_socket.local_addr().unwrap().port()).unwrap();
    service.local_port = Some(replacement_port);
    service.full_probe.last_pcp = Some(Instant::now());
    service.start_mapping(
        Ipv4Addr::LOCALHOST,
        replacement_port,
        Ipv4Addr::LOCALHOST,
        None,
    );
    let replacement = service.mapping_task.take().unwrap().await.unwrap();
    assert!(replacement.is_ok());
    service.on_mapping_result(Ok(replacement));
    let replaced = gateway.request().await;
    assert!(replaced.accepted && replaced.port == replacement_port.get());
    assert_ne!(
        replaced.nonce, first.nonce,
        "a new lease gets a fresh nonce"
    );
    service.update_local_port(None).await;
    let deleted = gateway.request().await;
    assert!(deleted.accepted && deleted.lifetime == 0 && deleted.nonce == replaced.nonce);
    gateway.close().await;
}

#[tokio::test]
async fn pcp_lease_lifecycle() {
    // PCP uses one fixed port, so keep these loopback controls in one test process.
    renew_with_probe_age(Duration::ZERO).await;
    renew_with_probe_age(AVAILABILITY_TRUST_DURATION).await;
    pcp_falls_back_only_for_unsupported_mapping_with_pmp_available().await;
}

async fn pcp_falls_back_only_for_unsupported_mapping_with_pmp_available() {
    use crate::mapping::PortMapped;
    use std::sync::atomic::{AtomicUsize, Ordering};

    for (error_code, pmp_available, expected_fallback) in
        [(4, true, true), (4, false, false), (2, true, false)]
    {
        let gateway = UdpSocket::bind((Ipv4Addr::LOCALHOST, 5351)).await.unwrap();
        let pmp_requests = Arc::new(AtomicUsize::new(0));
        let counter = pmp_requests.clone();
        let server = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut bytes = [0u8; 128];
            loop {
                let (size, peer) = match gateway.recv_from(&mut bytes).await {
                    Ok(packet) => packet,
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => continue,
                    Err(error) => panic!("gateway receive failed: {error}"),
                };
                assert!(peer.ip().is_loopback());
                let response = match (bytes[0], bytes[1], size) {
                    (2, 1, 60) => {
                        let mut response = vec![0; 24];
                        response[0] = 2;
                        response[1] = 129;
                        response[3] = error_code;
                        response
                    }
                    (0, 1, 12) => {
                        counter.fetch_add(1, Ordering::Relaxed);
                        let mut response = vec![0, 129, 0, 0, 0, 0, 0, 1];
                        response.extend_from_slice(&bytes[4..6]);
                        response.extend_from_slice(&50000u16.to_be_bytes());
                        response.extend_from_slice(&bytes[8..12]);
                        response
                    }
                    (0, 0, 2) => vec![0, 128, 0, 0, 0, 0, 0, 1, 203, 0, 113, 7],
                    other => panic!("unexpected gateway request {other:?}"),
                };
                gateway.send_to(&response, peer).await.unwrap();
            }
        }));
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = NonZeroU16::new(socket.local_addr().unwrap().port()).unwrap();
        let result = mapping::Mapping::new_pcp(
            Protocol::Udp,
            Ipv4Addr::LOCALHOST,
            port,
            Ipv4Addr::LOCALHOST,
            None,
            pmp_available,
            None,
        )
        .await;
        assert_eq!(result.is_ok(), expected_fallback);
        assert_eq!(
            pmp_requests.load(Ordering::Relaxed),
            usize::from(expected_fallback)
        );
        if let Ok(mapping) = result {
            assert!(matches!(mapping, mapping::Mapping::NatPmp(_)));
            assert_eq!(
                mapping.external(),
                (
                    Ipv4Addr::new(203, 0, 113, 7),
                    NonZeroU16::new(50000).unwrap()
                )
            );
            mapping.release().await.unwrap();
        }
        eprintln!(
            "PCP error={error_code} PMP available={pmp_available} fallback={expected_fallback}"
        );
        server.abort();
        let _ = server.await;
    }
}
