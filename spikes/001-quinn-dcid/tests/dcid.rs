use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::Endpoint;
use rustls::pki_types::CertificateDer;
use spike_quinn_dcid::*;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const T: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(1500);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// xorshift filler; deterministic is fine, the bytes only need to differ from the token.
fn fill(buf: &mut [u8], mut seed: u64) {
    for b in buf {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *b = (seed >> 24) as u8;
    }
}

/// Long header packet, `total` bytes, empty SCID, Initial-shaped (token len 0, 2-byte length).
fn long_pkt(first: u8, version: u32, dcid: &[u8], total: usize, seed: u64) -> Vec<u8> {
    let mut p = vec![first];
    p.extend(version.to_be_bytes());
    p.push(dcid.len() as u8);
    p.extend(dcid);
    p.extend([0, 0, 0x44, 0x00]); // scid len 0, token len 0, length varint
    let at = p.len();
    p.resize(total, 0);
    fill(&mut p[at..], seed);
    p
}

fn short_pkt(cid: &[u8], total: usize, seed: u64) -> Vec<u8> {
    let mut p = vec![0x41];
    p.extend(cid);
    let at = p.len();
    p.resize(total, 0);
    fill(&mut p[at..], seed);
    p
}

/// Send `pkt` from a fresh raw socket; return (prober addr, datagrams received within `window`).
async fn probe(dst: SocketAddr, pkt: Vec<u8>, window: Duration) -> (SocketAddr, Vec<Vec<u8>>) {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(&pkt, dst).await.unwrap();
    let mut got = vec![];
    let end = Instant::now() + window;
    let mut buf = vec![0u8; 2048];
    while let Ok(Ok((n, _))) = timeout(
        end.saturating_duration_since(Instant::now()),
        s.recv_from(&mut buf),
    )
    .await
    {
        got.push(buf[..n].to_vec());
    }
    (s.local_addr().unwrap(), got)
}

/// Real quinn client Initial datagrams (DCID provider = SYNTHETIC_DCID) captured on a raw socket.
async fn capture_client_initials() -> Vec<Vec<u8>> {
    let raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (_sc, cert) = server_config();
    let ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let connecting = ep
        .connect_with(
            client_config(&cert, SYNTHETIC_DCID),
            raw.local_addr().unwrap(),
            "localhost",
        )
        .unwrap();
    let h = tokio::spawn(connecting); // keep the handshake alive while we sniff
    let mut got = vec![];
    let mut buf = vec![0u8; 2048];
    let (n, _) = timeout(T, raw.recv_from(&mut buf))
        .await
        .expect("no client datagram")
        .unwrap();
    got.push(buf[..n].to_vec());
    // The retransmission timer (~1 s+) is far longer than this burst window.
    while let Ok(Ok((n, _))) = timeout(Duration::from_millis(400), raw.recv_from(&mut buf)).await {
        got.push(buf[..n].to_vec());
    }
    h.abort();
    got
}

async fn echo(inc: quinn::Incoming) {
    let Ok(connecting) = inc.accept() else { return };
    let Ok(conn) = connecting.await else { return };
    let Ok((mut tx, mut rx)) = conn.accept_bi().await else {
        return;
    };
    let Ok(data) = rx.read_to_end(1024).await else {
        return;
    };
    let _ = tx.write_all(&data).await;
    let _ = tx.finish();
    let _ = conn.closed().await;
}

struct Edge {
    ep: Endpoint,
    addr: SocketAddr,
    fs: Option<Arc<FilterSocket>>,
    cert: CertificateDer<'static>,
    orig_dcids: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn edge(filter: Option<Mode>) -> Edge {
    let (ep, fs, cert) = server_endpoint(filter);
    let orig_dcids: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let (ep2, o2) = (ep.clone(), orig_dcids.clone());
    tokio::spawn(async move {
        while let Some(inc) = ep2.accept().await {
            let o = inc.orig_dst_cid();
            o2.lock().unwrap().push(o.to_vec());
            if o[..] != SYNTHETIC_DCID {
                inc.ignore(); // never refuse(): that sends bytes
            } else {
                tokio::spawn(echo(inc));
            }
        }
    });
    Edge {
        addr: ep.local_addr().unwrap(),
        ep,
        fs,
        cert,
        orig_dcids,
    }
}

impl Edge {
    fn stats<R>(&self, f: impl FnOnce(&Stats) -> R) -> R {
        f(&self.fs.as_ref().unwrap().stats.lock().unwrap())
    }
}

/// Connect with a synthetic-DCID client, echo "ping". Err = handshake did not complete in `wait`.
async fn client_roundtrip(e: &Edge, wait: Duration) -> Result<Vec<u8>, String> {
    let ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let c = ep
        .connect_with(client_config(&e.cert, SYNTHETIC_DCID), e.addr, "localhost")
        .unwrap();
    let conn = timeout(wait, c)
        .await
        .map_err(|_| "handshake timed out".to_string())?
        .map_err(|x| format!("handshake failed: {x}"))?;
    let (mut tx, mut rx) = conn.open_bi().await.map_err(|x| x.to_string())?;
    tx.write_all(b"ping").await.map_err(|x| x.to_string())?;
    tx.finish().unwrap();
    let r = timeout(T, rx.read_to_end(1024))
        .await
        .map_err(|_| "echo timeout")?
        .map_err(|x| x.to_string())?;
    conn.close(0u32.into(), b"done");
    Ok(r)
}

#[test]
fn lock_resolves_exact_versions() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock")).unwrap();
    assert!(lock.contains("name = \"quinn\"\nversion = \"0.11.12\""));
    assert!(lock.contains("name = \"quinn-proto\"\nversion = \"0.11.19\""));
}

#[test]
fn peek_never_panics_on_truncation() {
    let p = long_pkt(0xC0, 1, &SYNTHETIC_DCID, 1200, 7);
    for n in 0..p.len().min(40) {
        let _ = peek(&p[..n]); // every prefix must be handled without panic
    }
    assert_eq!(peek(&p[..5]), None);
    assert!(matches!(
        peek(&p),
        Some(Peek::Long {
            version: 1,
            ty: 0,
            ..
        })
    ));
    assert_eq!(peek(&[0xC0, 0, 0, 0, 1, 255, 1, 2]), None); // dcid len beyond buffer
}

/// Test 1: (a) the client can choose a 20-byte Initial DCID and it is on the wire.
#[tokio::test]
async fn client_initial_carries_synthetic_dcid() {
    let dgrams = capture_client_initials().await;
    println!(
        "captured {} client datagram(s) before first retransmission",
        dgrams.len()
    );
    for d in &dgrams {
        let Some(Peek::Long { version, ty, dcid }) = peek(d) else {
            panic!("not a long header: {}", hex(&d[..8]))
        };
        println!(
            "  len={} first={:02x} version={version} type={ty} dcid_len={} dcid={}",
            d.len(),
            d[0],
            dcid.len(),
            hex(dcid)
        );
        assert_eq!((version, ty, dcid.len()), (1, 0, 20));
        assert_eq!(dcid, SYNTHETIC_DCID);
        assert!(d.len() >= 1200);
    }
}

/// Test 2 control: the SAME probes DO get answers from an unfiltered server (so zeros below are the filter).
#[tokio::test]
async fn control_unfiltered_server_answers_probes() {
    let e = edge(None);
    let (_, vn) = probe(
        e.addr,
        long_pkt(0xC0, 0x1a2a3a4a, &[7u8; 20], 1200, 1),
        QUIET,
    )
    .await;
    println!(
        "control unknown-version probe: {} response(s), lens {:?}",
        vn.len(),
        vn.iter().map(Vec::len).collect::<Vec<_>>()
    );
    assert_eq!(
        vn.len(),
        1,
        "unfiltered quinn must answer with Version Negotiation"
    );
    assert!(
        vn[0][0] & 0x80 != 0 && vn[0][1..5] == [0, 0, 0, 0],
        "not a VN packet"
    );
    println!(
        "  VN supported versions: {}",
        hex(&vn[0][vn[0].len().saturating_sub(8)..])
    );

    let mut cid = *SERVER_CID_PREFIX_ARR;
    cid[8..].copy_from_slice(&[9u8; 8]);
    let (_, rst) = probe(e.addr, short_pkt(&cid, 1200, 2), QUIET).await;
    println!(
        "control short-header, unknown CID: {} response(s), lens {:?}",
        rst.len(),
        rst.iter().map(Vec::len).collect::<Vec<_>>()
    );
    assert_eq!(rst.len(), 1, "unfiltered quinn must send a stateless reset");
}

const SERVER_CID_PREFIX_ARR: &[u8; 16] = b"SYNSRVID\0\0\0\0\0\0\0\0";

/// Test 2: zero response, and zero bytes sent by the endpoint, for every unauthenticated probe.
#[tokio::test]
async fn filtered_server_is_silent() {
    let e = edge(Some(Mode::Binding));
    let probes: Vec<(&str, Vec<u8>)> = vec![
        (
            "v1 Initial-looking, random 20B DCID, 1200B",
            long_pkt(0xC0, 1, &[0x55u8; 20], 1200, 11),
        ),
        (
            "unknown version 0x1a2a3a4a, 1200B",
            long_pkt(0xC0, 0x1a2a3a4a, &[0x66u8; 20], 1200, 12),
        ),
        ("truncated long header (3B)", vec![0xC0, 0, 0]),
        (
            "long header, DCID len 255 beyond buffer",
            vec![0xC0, 0, 0, 0, 1, 255, 1, 2, 3],
        ),
        ("empty datagram", vec![]),
        (
            "1200B short header, random 16B CID",
            short_pkt(&[0x77u8; 16], 1200, 13),
        ),
        (
            "token DCID but Handshake type (not Initial)",
            long_pkt(0xE0, 1, &SYNTHETIC_DCID, 1200, 14),
        ),
        (
            "token DCID Initial but < 1200B",
            long_pkt(0xC0, 1, &SYNTHETIC_DCID, 600, 15),
        ),
        (
            "v1 Initial, wrong-length DCID (8B)",
            long_pkt(0xC0, 1, &[0x11u8; 8], 1200, 16),
        ),
    ];
    let mut tasks = vec![];
    for (name, p) in probes {
        let addr = e.addr;
        tasks.push((name, tokio::spawn(probe(addr, p, QUIET))));
    }
    let n = tasks.len();
    for (name, t) in tasks {
        let (paddr, got) = t.await.unwrap();
        let sent = e.stats(|s| s.sent_to(paddr));
        println!(
            "probe [{name}]: responses={} send_counter={sent:?}",
            got.len()
        );
        assert!(got.is_empty(), "{name}: got a response");
        assert_eq!(sent, (0, 0), "{name}: endpoint sent bytes");
    }
    e.stats(|s| {
        println!(
            "filter: dropped={} total_sent_dgrams={} token_seen={}",
            s.dropped,
            s.total_sent_dgrams(),
            s.token_seen
        );
        // the empty datagram is skipped by the filter's own stride loop (total==0 never
        // iterates, w stays 0, the datagram is compacted out), so it counts neither as dropped nor accepted
        assert!(s.dropped as usize >= n - 1, "dropped {} of {n}", s.dropped);
        assert_eq!(s.total_sent_dgrams(), 0);
    });
    assert!(
        e.orig_dcids.lock().unwrap().is_empty(),
        "quinn must never have seen an Incoming"
    );
    drop(e.ep);
}

/// Test 3 + 4a: valid-token handshake completes in Binding mode over >= 2 token Initials.
#[tokio::test]
async fn handshake_binding_mode() {
    let e = edge(Some(Mode::Binding));
    let r = client_roundtrip(&e, T)
        .await
        .expect("handshake must complete");
    assert_eq!(r, b"ping");
    let (seen, acc, sc) = e.stats(|s| (s.token_seen, s.token_accepted, s.server_cid_accepted));
    println!("binding: token_dcid_seen={seen} accepted={acc} server_cid_accepted={sc}");
    assert!(
        seen >= 2,
        "ClientHello did not span >= 2 Initials; replay hypothesis not exercised"
    );
    assert_eq!(acc, seen);
    let o = e.orig_dcids.lock().unwrap().clone();
    println!(
        "Incoming::orig_dst_cid = {:?}",
        o.iter().map(|x| hex(x)).collect::<Vec<_>>()
    );
    assert_eq!(o, vec![SYNTHETIC_DCID.to_vec()]);
    let (a, b) = e.stats(|s| s.sent.values().fold((0, 0), |a, v| (a.0 + v.0, a.1 + v.1)));
    println!("server sent {a} datagram(s) / {b} bytes, all to the bound client");
}

/// Test 4b: with NO loss, "drop exact replays" does NOT break the handshake: the server's ACK of the
/// first Initial teaches the client the server CID, so the lost-by-filter 2nd Initial is retransmitted
/// under the server CID (accepted by prefix). Research hypothesis "breaks every PQ handshake" is false here.
#[tokio::test]
async fn naive_replay_cache_clean_path_completes_via_server_cid() {
    let e = edge(Some(Mode::NaiveReplay));
    let t0 = Instant::now();
    let r = client_roundtrip(&e, T).await;
    let (seen, acc) = e.stats(|s| (s.token_seen, s.token_accepted));
    println!(
        "naive/no-loss: result={r:?} elapsed={:?} token_dcid_seen={seen} accepted={acc}",
        t0.elapsed()
    );
    assert!(r.is_ok());
    // timer-dependent retransmissions can add sightings; the invariant is:
    // at least the 2-Initial ClientHello was seen, exactly one accepted
    assert!(
        seen >= 2 && acc == 1,
        "2nd token Initial must have been dropped (seen={seen} accepted={acc})"
    );
}

/// Test 4c: lose the server's first reply (simulated), so the client keeps using the token DCID and
/// retransmits it. Binding completes; the naive "drop exact replays" cache never answers again.
#[tokio::test]
async fn retransmission_after_lost_server_reply() {
    for (mode, expect_ok) in [(Mode::Binding, true), (Mode::NaiveReplay, false)] {
        let e = edge(Some(mode));
        e.fs.as_ref()
            .unwrap()
            .drop_next_sends
            .store(1, std::sync::atomic::Ordering::SeqCst);
        let t0 = Instant::now();
        let r = client_roundtrip(&e, Duration::from_secs(if expect_ok { 10 } else { 5 })).await;
        let (seen, acc) = e.stats(|s| (s.token_seen, s.token_accepted));
        println!("{mode:?}/first server reply lost: result={r:?} elapsed={:?} token_dcid_seen={seen} accepted={acc}", t0.elapsed());
        assert_eq!(r.is_ok(), expect_ok, "{mode:?}");
        assert!(
            seen >= 3,
            "no token retransmission happened: hypothesis not exercised"
        );
        if expect_ok {
            assert_eq!(acc, seen);
        } else {
            assert_eq!(acc, 1);
            // the swallowed try_send is not counted, so a zero send counter proves the
            // endpoint never answers again, from the counter rather than inference
            assert_eq!(e.stats(|s| s.total_sent_dgrams()), 0);
        }
    }
}

/// Extra: a captured valid token from another source address is dropped after binding (A1 replay).
#[tokio::test]
async fn token_replay_from_other_address_is_silent() {
    let captured = capture_client_initials().await;
    let e = edge(Some(Mode::Binding));
    client_roundtrip(&e, T).await.expect("handshake");
    let seen0 = e.stats(|s| s.token_seen);
    let (paddr, got) = probe(e.addr, captured[0].clone(), QUIET).await;
    println!(
        "replayed captured Initial from {paddr}: responses={}",
        got.len()
    );
    assert!(got.is_empty());
    assert_eq!(e.stats(|s| s.sent_to(paddr)), (0, 0));
    assert_eq!(e.stats(|s| s.token_seen), seen0 + 1);
}

/// Extra: junk flood before a valid handshake does not stall (no Ok(0), no starvation).
#[tokio::test]
async fn junk_flood_then_valid_handshake() {
    let e = edge(Some(Mode::Binding));
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 0..100u64 {
        s.send_to(
            &long_pkt(0xC0, 1, &[(i % 251) as u8 + 1; 20], 1200, 100 + i),
            e.addr,
        )
        .await
        .unwrap();
    }
    let t0 = Instant::now();
    client_roundtrip(&e, T).await.expect("handshake after junk");
    let d = e.stats(|s| s.dropped);
    println!(
        "junk flood: dropped={d}, handshake after junk took {:?}",
        t0.elapsed()
    );
    assert!(d >= 50);
}

/// Recorded, not a pass criterion: the probed CID was NEVER ISSUED (prefix-valid random bytes),
/// not a closed connection's CID (a genuinely closed CID was never tested). The filter cannot
/// tell a never-issued server CID from a live one (prefix-only recognition), so quinn answers
/// with exactly one stateless reset.
#[tokio::test]
async fn recorded_never_issued_cid_gets_one_stateless_reset() {
    let e = edge(Some(Mode::Binding));
    let mut cid = *SERVER_CID_PREFIX_ARR;
    cid[8..].copy_from_slice(&[0xAB; 8]);
    let (paddr, got) = probe(e.addr, short_pkt(&cid, 1200, 21), QUIET).await;
    let sent = e.stats(|s| s.sent_to(paddr));
    println!(
        "RECORDED never-issued/unknown prefix-valid CID: responses={} send_counter={sent:?}",
        got.len()
    );
    assert_eq!(got.len(), 1);
}

/// Group check, in-memory rustls handshake with the same provider/features (quinn does not expose the group).
#[test]
fn rustls_prefers_x25519mlkem768() {
    use rustls::NamedGroup;
    let (sc, cert) = rustls_server();
    let mut c = rustls::ClientConnection::new(
        Arc::new(rustls_client(&cert)),
        "localhost".try_into().unwrap(),
    )
    .unwrap();
    let mut s = rustls::ServerConnection::new(Arc::new(sc)).unwrap();
    let mut ch_len = 0;
    for _ in 0..10 {
        let mut b = vec![];
        c.write_tls(&mut b).unwrap();
        if ch_len == 0 {
            ch_len = b.len();
        }
        s.read_tls(&mut &b[..]).unwrap();
        s.process_new_packets().unwrap();
        let mut b = vec![];
        s.write_tls(&mut b).unwrap();
        c.read_tls(&mut &b[..]).unwrap();
        c.process_new_packets().unwrap();
        if !c.is_handshaking() && !s.is_handshaking() {
            break;
        }
    }
    let g = c.negotiated_key_exchange_group().map(|g| g.name());
    println!("negotiated group = {g:?}, first client flight = {ch_len} bytes (> ~1160 usable per Initial)");
    assert_eq!(g, Some(NamedGroup::X25519MLKEM768));
}
