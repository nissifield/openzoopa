// SPDX-License-Identifier: Apache-2.0
//! Throwaway phase-0 spike 002: MAC'd server CIDs, stateless-reset behavior, A2 dead-CID
//! Initials, Initial Token field with Retry off, GRO/coalescing, IPv6, loss.
//! NOT product code. `SYNTHETIC_DCID` is NOT a security mechanism: no MAC, no key, no secrets.
//! `src/cid.rs` and this file must never become production code.

pub mod cid;
pub use cid::{AcceptAllCidGen, MacCidGen, MacCidKeys, CID_LEN};

use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use quinn_proto::ConnectionId;

/// Obviously fake 20-byte "token" the client puts in its first Initial's DCID (unchanged from spike 001).
pub const SYNTHETIC_DCID: [u8; 20] = *b"SYNTHETIC-NOT-A-KEY!";
pub const MIN_INITIAL: usize = 1200;
pub const BINDING_CAP: u32 = 16;
pub const ALPN: &[u8] = b"spike";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// First token sighting binds token -> source addr; repeats accepted from that addr only.
    Binding,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub token_seen: u64,
    pub token_accepted: u64,
    pub server_cid_accepted: u64,
    pub dropped: u64,
    /// destination -> (datagrams, bytes) actually handed to the kernel by quinn
    pub sent: HashMap<SocketAddr, (u64, u64)>,
    /// shortcut: single token (constant), so a single binding slot; real design keys by token.
    binding: Option<(SocketAddr, u32)>,
    /// last server-issued CID seen in a client packet (for tests)
    pub last_server_cid: Option<Vec<u8>>,
    /// Token-field lengths parsed from accepted token Initials (wire verification for item 4a)
    pub token_field_lens: Vec<usize>,
    /// poll_recv batches where stride < len: GRO actually coalesced datagrams (item 5)
    pub gro_batches: u64,
}

impl Stats {
    pub fn sent_to(&self, a: SocketAddr) -> (u64, u64) {
        self.sent.get(&a).copied().unwrap_or((0, 0))
    }
    pub fn total_sent_dgrams(&self) -> u64 {
        self.sent.values().map(|v| v.0).sum()
    }
}

/// Bounds-checked header prefix extraction (not packet validation). Never indexes; returns None
/// for anything malformed.
#[derive(Debug, PartialEq, Eq)]
pub enum Peek<'a> {
    /// version, packet-type bits (0 = Initial), dcid
    Long {
        version: u32,
        ty: u8,
        dcid: &'a [u8],
    },
    /// fixed-length (CID_LEN) dcid of a short header
    Short { dcid: &'a [u8] },
}

pub fn peek(d: &[u8]) -> Option<Peek<'_>> {
    let first = *d.first()?;
    if first & 0x40 == 0 {
        return None; // fixed bit cleared: grease is disabled on the edge
    }
    if first & 0x80 != 0 {
        let version = u32::from_be_bytes(d.get(1..5)?.try_into().ok()?);
        let dcid_len = usize::from(*d.get(5)?);
        let dcid = d.get(6..6usize.checked_add(dcid_len)?)?;
        Some(Peek::Long {
            version,
            ty: (first >> 4) & 3,
            dcid,
        })
    } else {
        Some(Peek::Short {
            dcid: d.get(1..1 + CID_LEN)?,
        })
    }
}

/// QUIC varint at the front of `b`: (value, bytes consumed). Bounds-checked.
fn varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let n = 1usize << (first >> 6);
    let mut v = u64::from(first & 0x3f);
    for &x in b.get(1..n)? {
        v = (v << 8) | u64::from(x);
    }
    Some((v, n))
}

/// Token-field length of the FIRST packet of a datagram, if it is a long-header Initial.
/// Wire-level check that the client put bytes into the Initial Token field (item 4a).
/// Prefix extraction, not validation: returns the DECLARED length without checking those bytes exist.
pub fn initial_token_field_len(d: &[u8]) -> Option<usize> {
    let first = *d.first()?;
    if first & 0x80 == 0 || (first >> 4) & 3 != 0 {
        return None; // not a long-header Initial
    }
    let mut p = 5; // first byte + version
    let dcid_len = usize::from(*d.get(p)?);
    p = p.checked_add(1 + dcid_len)?;
    let scid_len = usize::from(*d.get(p)?);
    p = p.checked_add(1 + scid_len)?;
    let (tok_len, _) = varint(d.get(p..)?)?;
    Some(tok_len as usize)
}

/// Walk a UDP datagram's coalesced packets via each long header's length field (v1 layout:
/// token varint only on Initial). Stops at the first unparsable packet; a short header runs
/// to the end of the datagram. Returns (offset, end) ranges. Bounds-checked, never panics.
/// Diagnostic only: assumes the v1 layout and does not validate the packets it splits.
pub fn split_coalesced(d: &[u8]) -> Vec<(usize, usize)> {
    let mut out = vec![];
    let mut off = 0;
    while off < d.len() {
        let first = d[off];
        if first & 0x80 == 0 {
            out.push((off, d.len()));
            break;
        }
        let Some(end) = long_packet_end(d, off) else {
            break;
        };
        out.push((off, end));
        off = end;
    }
    out
}

fn long_packet_end(d: &[u8], off: usize) -> Option<usize> {
    let ty = (d.get(off)? >> 4) & 3;
    let mut p = off.checked_add(5)?; // first byte + version
    let dcid_len = usize::from(*d.get(p)?);
    p = p.checked_add(1 + dcid_len)?;
    let scid_len = usize::from(*d.get(p)?);
    p = p.checked_add(1 + scid_len)?;
    if ty == 0 {
        let (tok_len, n) = varint(d.get(p..)?)?;
        p = p.checked_add(n)?.checked_add(tok_len as usize)?;
    }
    let (pay_len, n) = varint(d.get(p..)?)?;
    let end = p.checked_add(n)?.checked_add(pay_len as usize)?;
    if end > d.len() {
        return None;
    }
    Some(end)
}

#[derive(Debug)]
pub struct FilterSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    mode: Mode,
    keys: Arc<MacCidKeys>,
    pub stats: Arc<Mutex<Stats>>,
    /// Simulated network loss: swallow the next N outgoing `Transmit` batches (not counted as
    /// sent). One swallowed `Transmit` may hold several GSO datagrams.
    pub drop_next_sends: AtomicU32,
}

impl FilterSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, mode: Mode, keys: Arc<MacCidKeys>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            mode,
            keys,
            stats: Arc::default(),
            drop_next_sends: AtomicU32::new(0),
        })
    }

    /// Deny is the default branch. Server-CID recognition IS `MacCidKeys::validate` — the same
    /// function quinn's `ConnectionIdGenerator::validate` uses.
    pub fn accept(&self, d: &[u8], src: SocketAddr) -> bool {
        let mut s = self.stats.lock().unwrap();
        let ok = match peek(d) {
            Some(Peek::Long {
                version: 1,
                ty,
                dcid,
            }) => {
                if dcid == SYNTHETIC_DCID {
                    s.token_seen += 1;
                    let ok = ty == 0 && d.len() >= MIN_INITIAL && self.token_ok(&mut s, src);
                    if ok {
                        if let Some(n) = initial_token_field_len(d) {
                            s.token_field_lens.push(n);
                        }
                    }
                    s.token_accepted += u64::from(ok);
                    ok
                } else if self.keys.validate(dcid) {
                    s.last_server_cid = Some(dcid.to_vec());
                    s.server_cid_accepted += 1;
                    true
                } else {
                    false
                }
            }
            Some(Peek::Short { dcid }) if self.keys.validate(dcid) => {
                s.last_server_cid = Some(dcid.to_vec());
                s.server_cid_accepted += 1;
                true
            }
            _ => false, // other versions, malformed, unknown CIDs
        };
        s.dropped += u64::from(!ok);
        if std::env::var_os("SPIKE_TRACE").is_some() {
            eprintln!(
                "filter: src={src} len={} first={:02x?} accept={ok}",
                d.len(),
                d.first()
            );
        }
        ok
    }

    fn token_ok(&self, s: &mut Stats, src: SocketAddr) -> bool {
        match self.mode {
            Mode::Binding => match &mut s.binding {
                None => {
                    s.binding = Some((src, 1));
                    true
                }
                Some((a, n)) if *a == src && *n < BINDING_CAP => {
                    *n += 1;
                    true
                }
                Some(_) => false,
            },
        }
    }
}

impl AsyncUdpSocket for FilterSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        // atomic conditional decrement: concurrent try_send callers cannot both swallow one token
        if self
            .drop_next_sends
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Ok(());
        }
        self.inner.try_send(t)?;
        let n = match t.segment_size {
            Some(s) if s > 0 => t.contents.len().div_ceil(s),
            _ => 1,
        } as u64;
        let mut st = self.stats.lock().unwrap();
        let e = st.sent.entry(t.destination).or_default();
        e.0 += n;
        e.1 += t.contents.len() as u64;
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Bounded so a junk flood cannot starve the runtime; never returns Ok(0).
        for _ in 0..64 {
            let n = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => n,
                other => return other,
            };
            let mut kept = 0;
            for i in 0..n.min(bufs.len()).min(meta.len()) {
                let m = meta[i];
                let total = m.len.min(bufs[i].len());
                let stride = if m.stride == 0 {
                    total.max(1)
                } else {
                    m.stride
                };
                if stride < total {
                    self.stats.lock().unwrap().gro_batches += 1; // GRO actually exercised
                }
                // GRO batch: split on stride, compact the accepted datagrams to the front.
                let (mut r, mut w) = (0, 0);
                while r < total {
                    let end = (r + stride).min(total);
                    if self.accept(&bufs[i][r..end], m.addr) {
                        bufs[i].copy_within(r..end, w);
                        w += end - r;
                    }
                    r = end;
                }
                if w > 0 {
                    meta[kept] = RecvMeta { len: w, ..m };
                    bufs.swap(kept, i);
                    kept += 1;
                }
            }
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

// ---- fixtures (spike only) ----

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::ConnectionIdGenerator;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;

fn endpoint_config_with(
    gen: impl Fn() -> Box<dyn ConnectionIdGenerator> + Send + Sync + 'static + Clone,
) -> quinn::EndpointConfig {
    let mut c = quinn::EndpointConfig::default();
    c.supported_versions(vec![1]).grease_quic_bit(false);
    c.cid_generator(gen);
    c
}

/// Endpoint config whose CID generator shares `keys` with the filter (MAC validate on).
pub fn endpoint_config(keys: Arc<MacCidKeys>) -> quinn::EndpointConfig {
    endpoint_config_with(move || Box::new(MacCidGen { keys: keys.clone() }))
}

/// Control config: MAC minting but accept-all validate (spike 001 behavior => resets happen).
pub fn endpoint_config_accept_all(keys: Arc<MacCidKeys>) -> quinn::EndpointConfig {
    endpoint_config_with(move || Box::new(AcceptAllCidGen { keys: keys.clone() }))
}

pub fn rustls_server() -> (rustls::ServerConfig, CertificateDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .unwrap();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    (tls, cert)
}

pub fn server_config() -> (quinn::ServerConfig, CertificateDer<'static>) {
    let (tls, cert) = rustls_server();
    let qs = QuicServerConfig::try_from(tls).unwrap();
    (quinn::ServerConfig::with_crypto(Arc::new(qs)), cert)
}

/// Server config that pushes one NEW_TOKEN after handshake (Retry stays off).
/// quinn-proto built without `bloom` defaults `validation_token.sent` to 0 and the log to
/// `NoneTokenLog` (config/mod.rs:524-535), so both must be set explicitly.
pub fn server_config_new_token() -> (quinn::ServerConfig, CertificateDer<'static>) {
    let (mut sc, cert) = server_config();
    let mut vtc = quinn::ValidationTokenConfig::default();
    vtc.sent(1);
    vtc.log(Arc::new(AcceptAllTokenLog));
    sc.validation_token_config(vtc);
    (sc, cert)
}

/// shortcut: spike-only TokenLog that accepts every validation token (no reuse tracking).
#[derive(Debug)]
pub struct AcceptAllTokenLog;

impl quinn::TokenLog for AcceptAllTokenLog {
    fn check_and_insert(
        &self,
        _: u128,
        _: std::time::SystemTime,
        _: std::time::Duration,
    ) -> Result<(), quinn::TokenReuseError> {
        Ok(())
    }
}

pub fn rustls_client(cert: &CertificateDer<'static>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls
}

/// Client config whose first Initial DCID is `dcid` (any length >= 8; `initial_dst_cid_provider`).
pub fn client_config_dcid(cert: &CertificateDer<'static>, dcid: Vec<u8>) -> quinn::ClientConfig {
    let mut cc = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(rustls_client(cert)).unwrap(),
    ));
    cc.initial_dst_cid_provider(Arc::new(move || ConnectionId::new(&dcid)));
    cc
}

/// Client config with the synthetic 20-byte token DCID.
pub fn client_config(cert: &CertificateDer<'static>) -> quinn::ClientConfig {
    client_config_dcid(cert, SYNTHETIC_DCID.to_vec())
}

/// Client config with a custom TokenStore (its `take()` bytes go verbatim into the Initial
/// Token field — config/mod.rs:609, connection/mod.rs SideArgs::Client).
pub fn client_config_token(
    cert: &CertificateDer<'static>,
    store: Arc<dyn quinn::TokenStore>,
) -> quinn::ClientConfig {
    let mut cc = client_config(cert);
    cc.token_store(store);
    cc
}

/// Client config offering ONLY X25519MLKEM768: a completed handshake proves that group was
/// negotiated (quinn exposes no stable API to read it back).
pub fn client_config_mlkem_only(cert: &CertificateDer<'static>) -> quinn::ClientConfig {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut cc = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
    cc.initial_dst_cid_provider(Arc::new(move || ConnectionId::new(&SYNTHETIC_DCID)));
    cc
}

pub fn runtime() -> Arc<dyn quinn::Runtime> {
    quinn::default_runtime().expect("tokio runtime")
}

/// Server endpoint on `bind` (e.g. "127.0.0.1:0" or "[::1]:0"). `filter` = Some(mode) wraps the
/// socket in `FilterSocket` sharing `keys`; the endpoint's CID generator always shares `keys`.
pub fn server_endpoint(
    bind: &str,
    filter: Option<Mode>,
    keys: Arc<MacCidKeys>,
) -> (
    quinn::Endpoint,
    Option<Arc<FilterSocket>>,
    CertificateDer<'static>,
) {
    let (sc, cert) = server_config();
    server_endpoint_with(bind, filter, keys, sc, cert)
}

/// Same, with a caller-supplied server config (e.g. `server_config_new_token`).
pub fn server_endpoint_with(
    bind: &str,
    filter: Option<Mode>,
    keys: Arc<MacCidKeys>,
    sc: quinn::ServerConfig,
    cert: CertificateDer<'static>,
) -> (
    quinn::Endpoint,
    Option<Arc<FilterSocket>>,
    CertificateDer<'static>,
) {
    server_endpoint_cfg(bind, filter, endpoint_config(keys.clone()), sc, cert, keys)
}

/// Control endpoint: accept-all CID validation, optionally filtered.
pub fn server_endpoint_accept_all(
    bind: &str,
    filter: Option<Mode>,
    keys: Arc<MacCidKeys>,
) -> (
    quinn::Endpoint,
    Option<Arc<FilterSocket>>,
    CertificateDer<'static>,
) {
    let (sc, cert) = server_config();
    server_endpoint_cfg(
        bind,
        filter,
        endpoint_config_accept_all(keys.clone()),
        sc,
        cert,
        keys,
    )
}

pub fn server_endpoint_cfg(
    bind: &str,
    filter: Option<Mode>,
    ec: quinn::EndpointConfig,
    sc: quinn::ServerConfig,
    cert: CertificateDer<'static>,
    keys: Arc<MacCidKeys>,
) -> (
    quinn::Endpoint,
    Option<Arc<FilterSocket>>,
    CertificateDer<'static>,
) {
    let rt = runtime();
    let sock = std::net::UdpSocket::bind(bind).unwrap();
    let inner = rt.wrap_udp_socket(sock).unwrap();
    let (abs, fs): (Arc<dyn AsyncUdpSocket>, _) = match filter {
        Some(m) => {
            let f = FilterSocket::new(inner, m, keys);
            (f.clone(), Some(f))
        }
        None => (inner, None),
    };
    let ep = quinn::Endpoint::new_with_abstract_socket(ec, Some(sc), abs, rt).unwrap();
    (ep, fs, cert)
}
