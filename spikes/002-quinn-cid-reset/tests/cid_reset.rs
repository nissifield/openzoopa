// SPDX-License-Identifier: Apache-2.0
//! Spike 002 runtime tests. Every wait is bounded; counters, not wall-clock, are pass criteria.
//! Items map to the task list: 2a-d reset behavior, 3 A2 dead-CID Initial, 4a/b token field,
//! 5 GRO/coalescing, 6 IPv6/netns, 7 loss, 8 parser robustness, plus spike-001 regressions.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::Endpoint;
use rustls::pki_types::CertificateDer;
use spike_quinn_cid_reset::*;
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
    let bind = match dst {
        SocketAddr::V4(_) => "127.0.0.1:0",
        SocketAddr::V6(_) => "[::1]:0",
    };
    let s = UdpSocket::bind(bind).await.unwrap();
    s.send_to(&pkt, dst).await.unwrap();
    let got = collect(&s, window).await;
    (s.local_addr().unwrap(), got)
}

/// Collect datagrams until `window` elapses.
async fn collect(s: &UdpSocket, window: Duration) -> Vec<Vec<u8>> {
    let mut got = vec![];
    let end = Instant::now() + window;
    let mut buf = vec![0u8; 4096];
    while let Ok(Ok((n, _))) = timeout(
        end.saturating_duration_since(Instant::now()),
        s.recv_from(&mut buf),
    )
    .await
    {
        got.push(buf[..n].to_vec());
    }
    got
}

/// Real quinn client Initial datagrams (token DCID) captured on a raw socket.
async fn capture_client_initials(cfg: quinn::ClientConfig) -> Vec<Vec<u8>> {
    let raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let connecting = ep
        .connect_with(cfg, raw.local_addr().unwrap(), "localhost")
        .unwrap();
    let h = tokio::spawn(connecting); // keep the handshake alive while we sniff
    let mut got = vec![];
    let mut buf = vec![0u8; 4096];
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

/// What the edge accept loop observed. This accept loop never calls `refuse()` and explicitly
/// calls `ignore()` on rejection. An implicit drop of an `Incoming` (quinn incoming.rs:103-109)
/// WOULD refuse, so product code must explicitly `ignore()` on rejection. A closing endpoint
/// (quinn endpoint.rs:810-816) refuses before the application ever sees the `Incoming`, so
/// `ignore()` cannot prevent that path (source-only; needs filter/socket suppression).
#[derive(Debug, Default)]
struct AcceptLog {
    orig_dcids: Vec<Vec<u8>>,
    validated: Vec<bool>,
    incoming: u64,
    ignored: u64,
}

struct Edge {
    ep: Endpoint,
    addr: SocketAddr,
    fs: Option<Arc<FilterSocket>>,
    cert: CertificateDer<'static>,
    log: Arc<Mutex<AcceptLog>>,
}

fn edge(filter: Option<Mode>) -> Edge {
    edge_keys(filter, MacCidKeys::random(&[0, 1]))
}

fn edge_keys(filter: Option<Mode>, keys: Arc<MacCidKeys>) -> Edge {
    let (ep, fs, cert) = server_endpoint("127.0.0.1:0", filter, keys);
    edge_from(ep, fs, cert)
}

fn edge_from(ep: Endpoint, fs: Option<Arc<FilterSocket>>, cert: CertificateDer<'static>) -> Edge {
    let log: Arc<Mutex<AcceptLog>> = Arc::default();
    let (ep2, l2) = (ep.clone(), log.clone());
    tokio::spawn(async move {
        while let Some(inc) = ep2.accept().await {
            let o = inc.orig_dst_cid().to_vec();
            let v = inc.remote_address_validated();
            let mut l = l2.lock().unwrap();
            l.incoming += 1;
            l.orig_dcids.push(o.clone());
            l.validated.push(v);
            if o[..] != SYNTHETIC_DCID {
                l.ignored += 1;
                drop(l);
                inc.ignore(); // never refuse(): that sends bytes
            } else {
                drop(l);
                tokio::spawn(echo(inc));
            }
        }
    });
    Edge {
        addr: ep.local_addr().unwrap(),
        ep,
        fs,
        cert,
        log,
    }
}

impl Edge {
    fn stats<R>(&self, f: impl FnOnce(&Stats) -> R) -> R {
        f(&self.fs.as_ref().unwrap().stats.lock().unwrap())
    }
}

/// Connect with a synthetic-DCID client, echo "ping". Err = handshake did not complete in `wait`.
async fn client_roundtrip(e: &Edge, wait: Duration) -> Result<Vec<u8>, String> {
    client_roundtrip_cfg(e, client_config(&e.cert), wait).await
}

/// Same, with a caller-supplied client config.
async fn client_roundtrip_cfg(
    e: &Edge,
    cfg: quinn::ClientConfig,
    wait: Duration,
) -> Result<Vec<u8>, String> {
    let ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    roundtrip_on(&ep, e.addr, cfg, wait).await
}

/// Echo round trip on an EXISTING client endpoint (reusing its source address: the filter's
/// Binding mode ties the token to the address, so a second connection must come from it).
async fn roundtrip_on(
    ep: &Endpoint,
    addr: SocketAddr,
    cfg: quinn::ClientConfig,
    wait: Duration,
) -> Result<Vec<u8>, String> {
    let c = ep.connect_with(cfg, addr, "localhost").unwrap();
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

// ---------- regressions ported from spike 001 ----------

#[test]
fn lock_resolves_exact_versions() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock")).unwrap();
    assert!(lock.contains("name = \"quinn\"\nversion = \"0.11.12\""));
    assert!(lock.contains("name = \"quinn-proto\"\nversion = \"0.11.19\""));
}

/// Spike 001 control, with MAC minting but accept-all validate: the SAME probes DO get answers
/// from an unfiltered accept-all server (so the zeros elsewhere are the filter / validate()).
#[tokio::test]
async fn control_unfiltered_server_answers_probes() {
    let keys = MacCidKeys::random(&[0, 1]);
    let (ep, _, _) = server_endpoint_accept_all("127.0.0.1:0", None, keys.clone());
    let addr = ep.local_addr().unwrap();

    let (_, vn) = probe(addr, long_pkt(0xC0, 0x1a2a3a4a, &[7u8; 20], 1200, 1), QUIET).await;
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

    // non-MAC CID, but accept-all validate => stateless reset (the behavior validate() turns off)
    let (_, rst) = probe(addr, short_pkt(&[0x77u8; 16], 1200, 2), QUIET).await;
    println!(
        "control short-header, unknown CID, accept-all validate: {} response(s)",
        rst.len()
    );
    assert_eq!(
        rst.len(),
        1,
        "accept-all validate must send a stateless reset"
    );

    // MAC-valid but never-issued CID, accept-all validate => also a reset (control for item 2b)
    let dead = keys.mint();
    let (_, rst2) = probe(addr, short_pkt(&dead, 1200, 3), QUIET).await;
    println!(
        "control short-header, never-issued MAC CID, accept-all validate: {} response(s)",
        rst2.len()
    );
    assert_eq!(rst2.len(), 1);

    // 7-byte DCID is below RFC 9000's 8-byte minimum; unfiltered quinn answers with
    // CONNECTION_CLOSE(PROTOCOL_VIOLATION) (quinn-proto 0.11.19 endpoint.rs -> initial_close),
    // so the filtered server's silence on this probe is the filter, not quinn.
    let (_, bad) = probe(addr, long_pkt(0xC0, 1, &[0x11u8; 7], 1200, 4), QUIET).await;
    println!("control short-DCID Initial: {} response(s)", bad.len());
    assert_eq!(bad.len(), 1);
    assert!(bad[0][0] & 0x80 != 0 && bad[0][1..5] == [0, 0, 0, 1]);
}

/// Zero response, and zero bytes sent by the endpoint, for every unauthenticated probe.
/// Covers item 2(a1): unknown non-MAC short-header CID through the filter => silence.
/// Covers item 6 IPv4 core probes: random-DCID Initial, unknown version, random-CID short header.
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
            "1200B short header, random 16B CID (2a1: non-MAC)",
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
            "v1 Initial, wrong-length DCID (7B, below RFC 9000 min 8B)",
            long_pkt(0xC0, 1, &[0x11u8; 7], 1200, 16),
        ),
        (
            "Handshake long header, random 16B non-MAC CID",
            long_pkt(0xE0, 1, &[0x88u8; 16], 1200, 17),
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
        // the empty datagram counts neither as dropped nor accepted (stride loop never iterates)
        assert!(s.dropped as usize >= n - 1, "dropped {} of {n}", s.dropped);
        assert_eq!(s.total_sent_dgrams(), 0);
    });
    assert!(
        e.log.lock().unwrap().orig_dcids.is_empty(),
        "quinn must never have seen an Incoming"
    );
    drop(e.ep);
}

/// Valid-token handshake completes in Binding mode over >= 2 token Initials.
#[tokio::test]
async fn handshake_binding_mode() {
    let e = edge(Some(Mode::Binding));
    let r = client_roundtrip(&e, T)
        .await
        .expect("handshake must complete");
    assert_eq!(r, b"ping");
    let (seen, acc, sc) = e.stats(|s| (s.token_seen, s.token_accepted, s.server_cid_accepted));
    println!("binding: token_dcid_seen={seen} accepted={acc} server_cid_accepted={sc}");
    assert!(seen >= 2, "ClientHello did not span >= 2 Initials");
    assert_eq!(acc, seen);
    let l = e.log.lock().unwrap();
    println!(
        "Incoming::orig_dst_cid = {:?} validated={:?}",
        l.orig_dcids.iter().map(|x| hex(x)).collect::<Vec<_>>(),
        l.validated
    );
    assert_eq!(l.orig_dcids, vec![SYNTHETIC_DCID.to_vec()]);
    assert_eq!(l.validated, vec![false]);
    drop(l);
    assert_eq!(
        e.stats(|s| s.sent.len()),
        1,
        "all server datagrams must go to a single destination (the bound client)"
    );
}

/// A captured valid token from another source address is dropped after binding (A1 replay).
#[tokio::test]
async fn token_replay_from_other_address_is_silent() {
    let captured = capture_client_initials(client_config(&server_config().1)).await;
    let e = edge(Some(Mode::Binding));
    client_roundtrip(&e, T).await.expect("handshake");
    let seen0 = e.stats(|s| s.token_seen);
    let acc0 = e.stats(|s| s.token_accepted);
    let (paddr, got) = probe(e.addr, captured[0].clone(), QUIET).await;
    println!(
        "replayed captured Initial from {paddr}: responses={}",
        got.len()
    );
    assert!(got.is_empty());
    assert_eq!(e.stats(|s| s.sent_to(paddr)), (0, 0));
    assert_eq!(e.stats(|s| s.token_seen), seen0 + 1);
    assert_eq!(
        e.stats(|s| s.token_accepted),
        acc0,
        "replay must be rejected"
    );
    let l = e.log.lock().unwrap();
    assert_eq!(
        l.orig_dcids.len(),
        1,
        "replay must not create a second Incoming"
    );
}

/// Junk flood before a valid handshake does not stall (no Ok(0), no starvation).
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
    println!("negotiated group = {g:?}, first client flight = {ch_len} bytes");
    assert_eq!(g, Some(NamedGroup::X25519MLKEM768));
}

/// Group check, strong form: client offers ONLY X25519MLKEM768 through the filter.
#[tokio::test]
async fn mlkem_only_client_completes_handshake_through_filter() {
    let e = edge(Some(Mode::Binding));
    let r = client_roundtrip_cfg(&e, client_config_mlkem_only(&e.cert), T)
        .await
        .expect("MLKEM-only handshake must complete (no common group would fail)");
    assert_eq!(r, b"ping");
}

// ---------- item 2: reset behavior ----------

/// 2(a2): an UNFILTERED endpoint whose cid_generator is the MAC generator drops unknown-CID
/// short headers with ZERO response: `ConnectionIdGenerator::validate() == Err` hits the
/// endpoint.rs:259-263 drop branch before `stateless_reset()` (:270). The filter is not needed for
/// this class (unrouted short headers only); long-header darkness needs the filter (see control test).
#[tokio::test]
async fn unfiltered_mac_generator_drops_unknown_cid() {
    let keys = MacCidKeys::random(&[0, 1]);
    let (ep, _, _) = server_endpoint("127.0.0.1:0", None, keys);
    let addr = ep.local_addr().unwrap();
    let (_, got) = probe(addr, short_pkt(&[0x77u8; 16], 1200, 31), QUIET).await;
    println!(
        "2a2 unfiltered+MAC-validate, unknown short CID: responses={}",
        got.len()
    );
    assert!(
        got.is_empty(),
        "validate()==Err must suppress the stateless reset"
    );

    // a MAC-valid (never-issued) CID minted under an endpoint's real keys still gets ONE reset:
    // validate() cannot tell never-issued from live. RECORDED; contrast with 2b and control.
    let keys2 = MacCidKeys::random(&[0, 1]);
    let (ep2, _, _) = server_endpoint("127.0.0.1:0", None, keys2.clone());
    let minted = keys2.mint();
    let (_, got2) = probe(
        ep2.local_addr().unwrap(),
        short_pkt(&minted, 1200, 32),
        QUIET,
    )
    .await;
    println!(
        "2a2-contrast unfiltered+MAC-validate, never-issued MAC CID: responses={}",
        got2.len()
    );
    assert_eq!(
        got2.len(),
        1,
        "MAC-valid but unrouted CID: one rate-limited reset"
    );
}

/// 2(b): MAC-valid but NEVER-ISSUED CID through the filter. Filter accepts (shared validate),
/// quinn validate() Ok, no connection => exactly one stateless reset. RECORDED, not a failure:
/// a stateless MAC validator cannot distinguish never-issued from live. Design consequence:
/// this leak needs either acceptance or a stateful check in the RFC.
#[tokio::test]
async fn never_issued_mac_cid_gets_one_stateless_reset() {
    let keys = MacCidKeys::random(&[0, 1]);
    let dead = keys.mint(); // MAC valid, never handed to any connection
    let e = edge_keys(Some(Mode::Binding), keys);
    let (paddr, got) = probe(e.addr, short_pkt(&dead, 1200, 33), QUIET).await;
    let sent = e.stats(|s| s.sent_to(paddr));
    let acc = e.stats(|s| s.server_cid_accepted);
    println!(
        "RECORDED 2b never-issued MAC CID: responses={} send_counter={sent:?} filter_accepts={acc}",
        got.len()
    );
    assert_eq!(acc, 1, "filter must accept a MAC-valid CID");
    assert_eq!(got.len(), 1, "quinn answers exactly one stateless reset");
    assert!(
        got[0][0] & 0x80 == 0,
        "reset looks like a short-header packet"
    );
}

/// 2(c): CID of a CLOSED connection, with an explicit 1 s `min_reset_interval` (not the 20 ms
/// default) so the result is not scheduling-sensitive. Phase A: one probe gets exactly one
/// stateless reset, which shows the CID no longer routes to live connection state. Phase B: two
/// probes within the interval get zero responses and no extra sends; the filter accepted both, so
/// both reached quinn's endpoint (filter acceptance is not proof of quinn processing, and quinn
/// discards send errors). Phase C: one probe after the interval gets exactly one more reset.
/// The response pattern is consistent with quinn's endpoint-wide limiter (endpoint.rs:283-289);
/// which branch suppressed phase B is source-only (the only other silent branch, padding
/// :296-304, cannot fire at 1200 B). NOT one reset per CID forever: resets resume after the interval.
#[tokio::test]
async fn closed_connection_cid_reset_is_rate_limited() {
    const RESET_INTERVAL: Duration = Duration::from_secs(1);
    let keys = MacCidKeys::random(&[0, 1]);
    let mut ec = endpoint_config(keys.clone());
    ec.min_reset_interval(RESET_INTERVAL);
    let (sc, cert) = server_config();
    let (ep, fs, cert) =
        server_endpoint_cfg("127.0.0.1:0", Some(Mode::Binding), ec, sc, cert, keys);
    let e = edge_from(ep, fs, cert);
    client_roundtrip(&e, T).await.expect("handshake");
    let cid = e
        .stats(|s| s.last_server_cid.clone())
        .expect("filter must have learned the server CID during the handshake");
    println!("2c learned server CID {} (now closing)", hex(&cid));
    // timing assumption: 500 ms is enough for the close to propagate and the server to drop the
    // connection state; phase A verifies it did (a still-routed CID would give no reset)
    tokio::time::sleep(Duration::from_millis(500)).await;

    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let paddr = s.local_addr().unwrap();

    // Phase A: exactly one reset.
    s.send_to(&short_pkt(&cid, 1200, 34), e.addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    timeout(T, s.recv_from(&mut buf))
        .await
        .expect("2c phase A: no stateless reset — connection state may still be live")
        .unwrap();
    let t_a = Instant::now();
    assert!(
        buf[0] & 0x80 == 0,
        "phase A response must look like a short-header stateless reset"
    );
    let sent_a = e.stats(|st| st.sent_to(paddr));
    assert_eq!(sent_a.0, 1, "phase A: exactly one reset datagram sent");

    // Phase B: two probes inside the interval; both must reach quinn, neither gets a response.
    let acc_before = e.stats(|st| st.server_cid_accepted);
    s.send_to(&short_pkt(&cid, 1200, 35), e.addr).await.unwrap();
    s.send_to(&short_pkt(&cid, 1200, 36), e.addr).await.unwrap();
    let got_b = collect(&s, QUIET).await;
    let sent_b = e.stats(|st| st.sent_to(paddr));
    let acc_delta = e.stats(|st| st.server_cid_accepted) - acc_before;
    println!(
        "2c phase A: 1 reset, send_counter={sent_a:?}; phase B (two probes inside {RESET_INTERVAL:?}): filter_accepted_delta={acc_delta} responses={} send_counter={sent_b:?}",
        got_b.len()
    );
    assert_eq!(
        acc_delta, 2,
        "phase B: both probes must pass the filter to quinn"
    );
    assert!(got_b.is_empty(), "phase B: no response inside the interval");
    assert_eq!(sent_b, sent_a, "phase B: endpoint sent nothing more");

    // Phase C: wait out the interval (measured from phase-A receipt) with margin, then probe.
    tokio::time::sleep_until((t_a + RESET_INTERVAL + Duration::from_millis(200)).into()).await;
    s.send_to(&short_pkt(&cid, 1200, 37), e.addr).await.unwrap();
    let got_c = collect(&s, QUIET).await;
    let sent_c = e.stats(|st| st.sent_to(paddr));
    println!(
        "2c phase C (after interval): responses={} send_counter={sent_c:?}",
        got_c.len()
    );
    assert_eq!(got_c.len(), 1, "phase C: resets resume after the interval");
    assert_eq!(sent_c.0, 2, "phase C: exactly one more reset datagram sent");
}

/// 2(d): fresh-key instance. A FRESH MacCidKeys (fresh filter+endpoint) silently drops a CID
/// minted under the OLD keys. Also the endpoint-without-filter case: new keys => validate Err
/// => drop, no reset. This is NOT a real process restart nor an in-place key rotation; with
/// persisted keys the old CIDs would behave like 2b/2c instead.
#[tokio::test]
async fn restart_with_fresh_keys_drops_old_cids() {
    let old_keys = MacCidKeys::random(&[0, 1]);
    let old_cid = old_keys.mint();

    // filtered edge with fresh keys
    let e = edge(Some(Mode::Binding)); // fresh random keys inside
    let (paddr, got) = probe(e.addr, short_pkt(&old_cid, 1200, 36), QUIET).await;
    let sent = e.stats(|s| s.sent_to(paddr));
    println!(
        "2d filtered, CID from old keys: responses={} send_counter={sent:?}",
        got.len()
    );
    assert!(
        got.is_empty(),
        "filter must drop a CID from the old key instance"
    );
    assert_eq!(sent, (0, 0));

    // unfiltered endpoint with fresh keys: validate()==Err drop
    let (ep2, _, _) = server_endpoint("127.0.0.1:0", None, MacCidKeys::random(&[0, 1]));
    let (_, got2) = probe(
        ep2.local_addr().unwrap(),
        short_pkt(&old_cid, 1200, 37),
        QUIET,
    )
    .await;
    println!(
        "2d unfiltered+new-keys, CID from old keys: responses={}",
        got2.len()
    );
    assert!(
        got2.is_empty(),
        "new keys => validate Err => drop, no reset"
    );
}

// ---------- item 3: A2 dead-CID Initial ----------

/// A2 emulation: a real quinn client whose `initial_dst_cid_provider` returns a freshly minted,
/// never-issued, unrouted, MAC-valid server CID. It is NOT copied from a live or closed
/// connection: existing CID routing (endpoint.rs:1099-1126) takes precedence over `Incoming` for
/// a routed (live) CID, which is untested here. Observed via Incoming count, orig_dst_cid, the
/// ignore()-branch counter, the per-address send counter and the client handshake timeout; zero
/// sends hold over the 6 s observation window for this specimen only.
#[tokio::test]
async fn a2_never_issued_cid_initial_reaches_incoming_and_is_ignored() {
    let keys = MacCidKeys::random(&[0, 1]);
    let dead_cid = keys.mint().to_vec(); // MAC valid, never issued
    let e = edge_keys(Some(Mode::Binding), keys);
    let cfg = client_config_dcid(&e.cert, dead_cid.clone());

    let client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let client_addr = client.local_addr().unwrap();
    let connecting = client.connect_with(cfg, e.addr, "localhost").unwrap();
    let r = timeout(Duration::from_secs(6), connecting).await;
    println!("3 client handshake result (expect timeout): {}", r.is_err());

    let l = e.log.lock().unwrap();
    let sent = e.stats(|s| s.sent_to(client_addr));
    println!(
        "3 incoming={} ignored={} orig_dcids={:?} validated={:?} send_to_client={sent:?}",
        l.incoming,
        l.ignored,
        l.orig_dcids.iter().map(|x| hex(x)).collect::<Vec<_>>(),
        l.validated
    );
    assert!(r.is_err(), "client handshake must never complete");
    assert!(l.incoming >= 1, "unrouted Initial produced an Incoming");
    assert_eq!(
        l.ignored, l.incoming,
        "every Incoming took the ignore() branch"
    );
    assert!(
        l.orig_dcids.iter().all(|o| *o == dead_cid),
        "orig_dst_cid is the never-issued CID"
    );
    assert!(l.validated.iter().all(|v| !*v));
    assert_eq!(
        sent,
        (0, 0),
        "ignore() sent zero bytes; refuse() is never called"
    );
}

// ---------- item 4: Retry off + Initial Token field ----------

/// TokenStore whose `take()` hands back 64 arbitrary bytes once. quinn puts them verbatim into
/// the client's Initial Token field (no Retry needed).
#[derive(Debug)]
struct GarbageTokenStore(Mutex<Option<Bytes>>);

impl quinn::TokenStore for GarbageTokenStore {
    fn insert(&self, _: &str, _: Bytes) {}
    fn take(&self, _: &str) -> Option<Bytes> {
        self.0.lock().unwrap().take()
    }
}

/// 4(a): garbage token with Retry disabled. The Initial carries a 64-byte Token field (verified
/// on the wire via the filter's parse of the accepted datagram), Incoming IS produced, the
/// handshake completes, no CONNECTION_CLOSE, and remote_address_validated() == false.
/// Source basis: token.rs:141-143 — an UNDECODABLE token falls through as unvalidated. The
/// initial_close(INVALID_TOKEN) path (endpoint.rs:510-522) fires for a successfully DECODED Retry
/// token whose full SocketAddr mismatches or which is expired (token.rs:152-157). Retry-off here
/// means this fixture never issues Retry; it does not disable recognition of Retry tokens minted
/// under a shared token key.
#[tokio::test]
async fn garbage_token_field_accepted_unvalidated() {
    let mut garbage = vec![0u8; 64];
    fill(&mut garbage, 0x510e002u64);
    let store = Arc::new(GarbageTokenStore(Mutex::new(Some(Bytes::from(garbage)))));
    let e = edge(Some(Mode::Binding));
    let cfg = client_config_token(&e.cert, store);

    let r = client_roundtrip_cfg(&e, cfg, T)
        .await
        .expect("handshake with garbage token must complete (Retry off)");
    assert_eq!(r, b"ping");

    let lens = e.stats(|s| s.token_field_lens.clone());
    let l = e.log.lock().unwrap();
    println!(
        "4a token field lengths on the wire: {lens:?} validated={:?}",
        l.validated
    );
    assert!(
        lens.contains(&64),
        "client Initial must carry the 64-byte Token field"
    );
    assert_eq!(
        l.orig_dcids,
        vec![SYNTHETIC_DCID.to_vec()],
        "Incoming IS produced"
    );
    assert_eq!(
        l.validated,
        vec![false],
        "garbage token must not validate the address"
    );
}

/// TokenStore that records NEW_TOKEN via insert() and hands tokens back one at a time.
#[derive(Debug, Default)]
struct RecordingTokenStore(Mutex<HashMap<String, VecDeque<Bytes>>>);

impl quinn::TokenStore for RecordingTokenStore {
    fn insert(&self, server_name: &str, token: Bytes) {
        self.0
            .lock()
            .unwrap()
            .entry(server_name.to_string())
            .or_default()
            .push_back(token);
    }
    fn take(&self, server_name: &str) -> Option<Bytes> {
        self.0
            .lock()
            .unwrap()
            .get_mut(server_name)
            .and_then(VecDeque::pop_front)
    }
}

/// 4(b): real NEW_TOKEN round trip. quinn-proto built without `bloom` sends 0 NEW_TOKEN frames
/// by default (config/mod.rs:533), so the server sets validation_token.sent(1) with a spike-only
/// accept-all TokenLog. Connection 1 records the token; connection 2 reuses it.
#[tokio::test]
async fn new_token_round_trip_validates() {
    let (sc, cert) = server_config_new_token();
    let (ep, fs, cert) = server_endpoint_with(
        "127.0.0.1:0",
        Some(Mode::Binding),
        MacCidKeys::random(&[0, 1]),
        sc,
        cert,
    );
    let e = edge_from(ep, fs, cert.clone());

    let store = Arc::new(RecordingTokenStore::default());
    // ONE client endpoint for both connections: quinn ties a NEW_TOKEN token to the client IP for
    // address validation only (IP mismatch -> connection proceeds unvalidated, token.rs:165-167);
    // the spike filter binds the full SocketAddr, which is why conn2 reuses conn1's endpoint.
    let client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    // connection 1: no token yet; handshake; wait until NEW_TOKEN lands in the store
    {
        let cfg = client_config_token(&cert, store.clone());
        let conn = timeout(T, client.connect_with(cfg, e.addr, "localhost").unwrap())
            .await
            .expect("conn1 handshake timeout")
            .expect("conn1 handshake failed");
        let t0 = Instant::now();
        loop {
            if store
                .0
                .lock()
                .unwrap()
                .get("localhost")
                .is_some_and(|q| !q.is_empty())
            {
                break;
            }
            assert!(t0.elapsed() < T, "server never delivered NEW_TOKEN");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        conn.close(0u32.into(), b"done");
    }
    println!("4b connection 1 recorded a NEW_TOKEN token");

    // connection 2: reuses the recorded token => validated
    let r = roundtrip_on(&client, e.addr, client_config_token(&cert, store), T)
        .await
        .expect("conn2 handshake must complete");
    assert_eq!(r, b"ping");
    let l = e.log.lock().unwrap();
    println!("4b validated flags per Incoming: {:?}", l.validated);
    assert_eq!(l.validated.len(), 2);
    assert!(!l.validated[0], "conn1 had no token");
    assert!(
        l.validated[1],
        "conn2's NEW_TOKEN must validate the address"
    );
}

// ---------- item 5: GRO / coalescing ----------

/// 5(i): coalesced long headers. Captures an MLKEM-only client's first flight; if a datagram
/// contains 2+ coalesced long-header packets, feeds it at the filtered edge and asserts the
/// filter handles it as ONE datagram. If no coalescing is observed, prints NOT RUN.
#[tokio::test]
async fn coalesced_first_flight_detection() {
    let (_sc, cert) = server_config();
    let dgrams = capture_client_initials(client_config_mlkem_only(&cert)).await;
    let mut coalesced = None;
    for d in &dgrams {
        let ranges = split_coalesced(d);
        println!(
            "5i captured datagram len={} -> {} packet(s) {:?}",
            d.len(),
            ranges.len(),
            ranges
        );
        if ranges.len() >= 2 {
            coalesced = Some(d.clone());
        }
    }
    let Some(dgram) = coalesced else {
        println!(
            "5i NOT RUN: captured first flight was never coalesced (one Initial per datagram)"
        );
        return;
    };
    let e = edge(Some(Mode::Binding));
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let before = e.stats(|st| (st.token_seen, st.token_accepted));
    s.send_to(&dgram, e.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = e.stats(|st| (st.token_seen, st.token_accepted));
    println!("5i filter counters before={before:?} after={after:?} (one coalesced datagram)");
    assert_eq!(
        after.0,
        before.0 + 1,
        "coalesced datagram handled as ONE datagram"
    );
    assert_eq!(after.1, before.1 + 1, "filter accepted it");
}

/// 5(ii): GRO batch observation. Counts poll_recv batches where stride < len. On loopback the
/// kernel decides; forcing GRO needs controlled input (e.g. deterministic constructed datagrams or
/// socket fixtures, or netns/veth). The count is printed, not asserted; mixed accept/drop
/// compaction and all-dropped batches are untested.
#[tokio::test]
async fn gro_batch_observation() {
    let e = edge(Some(Mode::Binding));
    client_roundtrip(&e, T).await.expect("handshake");
    let g = e.stats(|s| s.gro_batches);
    println!("5ii gro_batches observed during handshake: {g}");
    if g == 0 {
        println!("5ii forced-GRO NOT RUN: loopback never delivered a coalesced GRO batch");
    }
}

// ---------- item 6: IPv6 / netns darkness ----------

/// Core silence probes on [::1]. A bind failure (no IPv6 loopback) FAILS the test rather than
/// silently passing. No netns test exists here (an earlier `unshare -Urn true` failed; not
/// reproduced in this pass).
#[tokio::test]
async fn silence_probes_ipv6() {
    let keys = MacCidKeys::random(&[0, 1]);
    let (ep, fs, _cert) = server_endpoint("[::1]:0", Some(Mode::Binding), keys);
    let addr = ep.local_addr().unwrap();
    let probes: Vec<(&str, Vec<u8>)> = vec![
        (
            "v6 random-DCID Initial",
            long_pkt(0xC0, 1, &[0x55u8; 20], 1200, 41),
        ),
        (
            "v6 unknown version",
            long_pkt(0xC0, 0x1a2a3a4a, &[0x66u8; 20], 1200, 42),
        ),
        (
            "v6 random-CID short header",
            short_pkt(&[0x77u8; 16], 1200, 43),
        ),
    ];
    for (name, p) in probes {
        let (paddr, got) = probe(addr, p, QUIET).await;
        let sent = fs.as_ref().unwrap().stats.lock().unwrap().sent_to(paddr);
        println!(
            "6 probe [{name}]: responses={} send_counter={sent:?}",
            got.len()
        );
        assert!(got.is_empty(), "{name}: got a response");
        assert_eq!(sent, (0, 0));
    }
    println!("6 IPv6 silence probes: all silent on {addr}");
}

// ---------- item 7: loss ----------

/// Binding mode, recovery after one swallowed outgoing `Transmit` batch (may hold several GSO
/// datagrams): handshake completes, injected drop consumed, every sighting accepted.
/// `token_seen >= 3` is consistent with a client retransmission, but retransmission is INFERRED
/// from sightings, not counted directly.
#[tokio::test]
async fn retransmission_after_lost_server_reply() {
    let e = edge(Some(Mode::Binding));
    e.fs.as_ref()
        .unwrap()
        .drop_next_sends
        .store(1, Ordering::SeqCst);
    let t0 = Instant::now();
    let r = client_roundtrip(&e, T).await;
    let (seen, acc) = e.stats(|s| (s.token_seen, s.token_accepted));
    println!(
        "7 binding/first server reply lost: result={r:?} elapsed={:?} token_dcid_seen={seen} accepted={acc}",
        t0.elapsed()
    );
    assert!(r.is_ok(), "binding mode must survive the lost first reply");
    assert_eq!(
        e.fs.as_ref()
            .unwrap()
            .drop_next_sends
            .load(Ordering::SeqCst),
        0,
        "injected drop was never consumed"
    );
    assert!(
        seen >= 3,
        "token_seen < 3: no retransmission inferred, hypothesis not exercised"
    );
    assert_eq!(acc, seen);
}

// ---------- item 8: parser robustness ----------

/// Bounded panic-freedom checks: prefixes 0..63 and one 0xa5 XOR at each of the first 64
/// positions (no panic only), plus 26 selected denial assertions and a positive control. Not
/// packet validation, not fuzzing.
/// Tokio test because the FilterSocket rig needs `quinn::default_runtime()` (tokio context).
#[tokio::test]
async fn parser_robustness() {
    let p = long_pkt(0xC0, 1, &SYNTHETIC_DCID, 1200, 7);
    for n in 0..p.len().min(64) {
        let _ = peek(&p[..n]);
        let _ = initial_token_field_len(&p[..n]);
        let _ = split_coalesced(&p[..n]);
    }
    // single-byte mutations across the header region
    for i in 0..p.len().min(64) {
        let mut m = p.clone();
        m[i] ^= 0xa5;
        let _ = peek(&m);
        let _ = initial_token_field_len(&m);
        let _ = split_coalesced(&m);
    }
    assert_eq!(peek(&[]), None);
    assert_eq!(peek(&[0xC0, 0, 0, 0, 1, 255, 1, 2]), None); // dcid len beyond buffer
    assert!(split_coalesced(&[]).is_empty());

    // fixed bit cleared (grease): grease_quic_bit(false) on the edge, so the filter must drop it
    let keys = MacCidKeys::random(&[0, 1]);
    let rt = runtime();
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let inner = rt.wrap_udp_socket(sock).unwrap();
    let f = FilterSocket::new(inner, Mode::Binding, keys.clone());
    let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let mut grease = p.clone();
    grease[0] &= !0x40;
    assert!(
        !f.accept(&grease, src),
        "fixed-bit-cleared packet must be dropped"
    );
    assert!(!f.accept(&[], src));
    assert!(!f.accept(&p[..3], src), "truncated must be denied");

    // a well-formed token Initial is accepted (binds src; rig sanity)
    let ok = long_pkt(0xC0, 1, &SYNTHETIC_DCID, 1200, 8);
    assert!(f.accept(&ok, src));
    // long_pkt layout: 0 first byte, 1..=4 version, 5 DCID len, 6..=25 DCID (20 B), 26 SCID len,
    // 27 token len, 28..=29 length varint, 30+ filler. Filter acceptance depends only on bytes
    // 0..26 (plus datagram length), so
    // those 26 mutations must ALL be denied (deny is the default branch).
    for i in 0..26 {
        let mut m = ok.clone();
        m[i] ^= 0xa5;
        assert!(!f.accept(&m, src), "header mutation at {i} accepted");
    }
    // positive control: binding cap is 16 and only one accept (the rig-sanity accept) happened above
    assert!(
        f.accept(&ok, src),
        "unmutated token Initial must still be accepted (rig sanity)"
    );
    println!("8 parser robustness: no panics; 26/26 header mutations denied; grease dropped; positive control accepted");
}
