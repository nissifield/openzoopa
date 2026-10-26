//! Throwaway phase-0 spike: quinn 0.11.12 initial-DCID control + userspace UDP prefilter.
//! NOT product code. `SYNTHETIC_DCID` is NOT a security mechanism: no MAC, no key, no secrets.

use std::collections::{hash_map::RandomState, HashMap};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use quinn_proto::{ConnectionId, ConnectionIdGenerator};

/// Obviously fake 20-byte "token" the client puts in its first Initial's DCID.
pub const SYNTHETIC_DCID: [u8; 20] = *b"SYNTHETIC-NOT-A-KEY!";
/// shortcut: non-crypto server CID recognition (fixed prefix), replace with MAC'd CIDs per RFC.
pub const SERVER_CID_PREFIX: &[u8; 8] = b"SYNSRVID";
pub const SERVER_CID_LEN: usize = 16;
pub const MIN_INITIAL: usize = 1200;
pub const BINDING_CAP: u32 = 16;
pub const ALPN: &[u8] = b"spike";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// DESIGN.md §3.4 as written: drop any second occurrence of the token DCID.
    NaiveReplay,
    /// Proposed: first token sighting binds token -> source addr; repeats accepted from that addr only.
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
}

impl Stats {
    pub fn sent_to(&self, a: SocketAddr) -> (u64, u64) {
        self.sent.get(&a).copied().unwrap_or((0, 0))
    }
    pub fn total_sent_dgrams(&self) -> u64 {
        self.sent.values().map(|v| v.0).sum()
    }
}

/// Bounds-checked header peek. Never indexes; returns None for anything malformed.
#[derive(Debug, PartialEq, Eq)]
pub enum Peek<'a> {
    /// version, packet-type bits (0 = Initial), dcid
    Long {
        version: u32,
        ty: u8,
        dcid: &'a [u8],
    },
    /// fixed-length (SERVER_CID_LEN) dcid of a short header
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
            dcid: d.get(1..1 + SERVER_CID_LEN)?,
        })
    }
}

fn is_server_cid(c: &[u8]) -> bool {
    c.len() == SERVER_CID_LEN && c.starts_with(SERVER_CID_PREFIX)
}

#[derive(Debug)]
pub struct FilterSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    mode: Mode,
    pub stats: Arc<Mutex<Stats>>,
    /// Simulated network loss: swallow the next N outgoing datagram batches (not counted as sent).
    pub drop_next_sends: AtomicU32,
}

impl FilterSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            inner,
            mode,
            stats: Arc::default(),
            drop_next_sends: AtomicU32::new(0),
        })
    }

    /// Deny is the default branch.
    fn accept(&self, d: &[u8], src: SocketAddr) -> bool {
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
                    s.token_accepted += u64::from(ok);
                    ok
                } else if is_server_cid(dcid) {
                    s.last_server_cid = Some(dcid.to_vec());
                    s.server_cid_accepted += 1;
                    true
                } else {
                    false
                }
            }
            Some(Peek::Short { dcid }) if is_server_cid(dcid) => {
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
            Mode::NaiveReplay => s.token_seen == 1,
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
        // load-then-sub is NOT race-free in general (endpoint and connection driver tasks both
        // call try_send); sound here only because every spike test runs on a current-thread runtime
        if self.drop_next_sends.load(Ordering::SeqCst) > 0 {
            self.drop_next_sends.fetch_sub(1, Ordering::SeqCst);
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

/// shortcut: prefix + std-random bytes, no MAC; a closed connection's CID still passes the filter.
#[derive(Debug)]
pub struct SynthCidGen;

impl ConnectionIdGenerator for SynthCidGen {
    fn generate_cid(&mut self) -> ConnectionId {
        let mut b = [0u8; SERVER_CID_LEN];
        b[..8].copy_from_slice(SERVER_CID_PREFIX);
        b[8..].copy_from_slice(&RandomState::new().build_hasher().finish().to_le_bytes());
        ConnectionId::new(&b)
    }
    fn cid_len(&self) -> usize {
        SERVER_CID_LEN
    }
    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

// ---- fixtures (spike only) ----

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;

pub fn endpoint_config() -> quinn::EndpointConfig {
    let mut c = quinn::EndpointConfig::default();
    c.supported_versions(vec![1]).grease_quic_bit(false);
    c.cid_generator(|| Box::new(SynthCidGen));
    c
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

pub fn rustls_client(cert: &CertificateDer<'static>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls
}

/// Client config whose first Initial DCID is `dcid` (exactly what `initial_dst_cid_provider` allows).
pub fn client_config(cert: &CertificateDer<'static>, dcid: [u8; 20]) -> quinn::ClientConfig {
    let mut cc = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(rustls_client(cert)).unwrap(),
    ));
    cc.initial_dst_cid_provider(Arc::new(move || ConnectionId::new(&dcid)));
    cc
}

pub fn runtime() -> Arc<dyn quinn::Runtime> {
    quinn::default_runtime().expect("tokio runtime")
}

/// Server endpoint on 127.0.0.1:0. `filter` = Some(mode) wraps the socket in `FilterSocket`.
pub fn server_endpoint(
    filter: Option<Mode>,
) -> (
    quinn::Endpoint,
    Option<Arc<FilterSocket>>,
    CertificateDer<'static>,
) {
    let (sc, cert) = server_config();
    let rt = runtime();
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let inner = rt.wrap_udp_socket(sock).unwrap();
    let (abs, fs): (Arc<dyn AsyncUdpSocket>, _) = match filter {
        Some(m) => {
            let f = FilterSocket::new(inner, m);
            (f.clone(), Some(f))
        }
        None => (inner, None),
    };
    let ep =
        quinn::Endpoint::new_with_abstract_socket(endpoint_config(), Some(sc), abs, rt).unwrap();
    (ep, fs, cert)
}
