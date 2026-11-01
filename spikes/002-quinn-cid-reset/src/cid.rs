// SPDX-License-Identifier: Apache-2.0
//! Throwaway MAC'd server-CID plumbing for spike 002. Spike crypto plumbing ONLY:
//! the final construction needs crypto review; this code makes no production MAC claims.
//! This file must never become production code.
//!
//! Scheme (16 bytes): `kid(1) || nonce(7) || tag(8)` where
//! `tag = HMAC-SHA256(K_cid[kid], label || kid || nonce)[0..8]`, label = b"spike002-cid".
//! A small key map simulates rotation: every known kid validates, only the current kid mints.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac::{self, HMAC_SHA256};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use quinn_proto::{ConnectionId, ConnectionIdGenerator, InvalidCid};

pub const CID_LEN: usize = 16;
pub const CID_LABEL: &[u8] = b"spike002-cid";
const NONCE_LEN: usize = 7;
const TAG_LEN: usize = 8;
const MSG_LEN: usize = CID_LABEL.len() + 1 + NONCE_LEN;

#[derive(Debug)]
pub struct MacCidKeys {
    current: u8,
    keys: HashMap<u8, hmac::Key>,
}

impl MacCidKeys {
    /// Random keys, one per kid; the first kid mints, all validate (simulates rotation).
    pub fn random(kids: &[u8]) -> Arc<Self> {
        assert!(!kids.is_empty());
        let rng = SystemRandom::new();
        let keys = kids
            .iter()
            .map(|&kid| {
                let mut raw = [0u8; 32];
                rng.fill(&mut raw).expect("aws-lc-rs rng");
                (kid, hmac::Key::new(HMAC_SHA256, &raw))
            })
            .collect();
        Arc::new(Self {
            current: kids[0],
            keys,
        })
    }

    /// Fixed keys, for known-answer tests only.
    pub fn from_raw(current: u8, raw: &[(u8, [u8; 32])]) -> Arc<Self> {
        let keys = raw
            .iter()
            .map(|(kid, k)| (*kid, hmac::Key::new(HMAC_SHA256, k)))
            .collect();
        Arc::new(Self { current, keys })
    }

    fn tag(&self, kid: u8, nonce: [u8; NONCE_LEN]) -> Option<[u8; TAG_LEN]> {
        let key = self.keys.get(&kid)?;
        let mut msg = [0u8; MSG_LEN];
        msg[..CID_LABEL.len()].copy_from_slice(CID_LABEL);
        msg[CID_LABEL.len()] = kid;
        msg[CID_LABEL.len() + 1..].copy_from_slice(&nonce);
        let t = hmac::sign(key, &msg);
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(&t.as_ref()[..TAG_LEN]);
        Some(out)
    }

    /// Mint a CID under an explicit kid/nonce (random nonce for live issuance; fixed for tests).
    pub fn assemble(&self, kid: u8, nonce: [u8; NONCE_LEN]) -> Option<[u8; CID_LEN]> {
        let tag = self.tag(kid, nonce)?;
        let mut cid = [0u8; CID_LEN];
        cid[0] = kid;
        cid[1..1 + NONCE_LEN].copy_from_slice(&nonce);
        cid[1 + NONCE_LEN..].copy_from_slice(&tag);
        Some(cid)
    }

    /// Mint a live CID under the current kid.
    pub fn mint(&self) -> [u8; CID_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce).expect("aws-lc-rs rng");
        self.assemble(self.current, nonce)
            .expect("current kid has a key")
    }

    /// The ONE shared validation used by BOTH the UDP filter's server-CID recognition and
    /// quinn's `ConnectionIdGenerator::validate`. Deny is the default branch.
    pub fn validate(&self, cid: &[u8]) -> bool {
        let (kid, rest) = match cid.split_first() {
            Some(x) if cid.len() == CID_LEN => x,
            _ => return false,
        };
        let nonce: [u8; NONCE_LEN] = match rest[..NONCE_LEN].try_into() {
            Ok(n) => n,
            Err(_) => return false,
        };
        let Some(expected) = self.tag(*kid, nonce) else {
            return false;
        };
        verify_slices_are_equal(&expected, &rest[NONCE_LEN..]).is_ok()
    }
}

/// quinn server-side CID generator whose `validate()` shares `MacCidKeys::validate`.
/// `validate() == Err` drops an UNROUTED SHORT-HEADER packet with an invalid MAC before
/// `stateless_reset` (quinn-proto 0.11.19 endpoint.rs:259-263 vs :270). Long headers never reach
/// `validate()`: the VN, short-DCID Initial close and Retry INVALID_TOKEN paths need the filter.
#[derive(Debug)]
pub struct MacCidGen {
    pub keys: Arc<MacCidKeys>,
}

impl ConnectionIdGenerator for MacCidGen {
    fn generate_cid(&mut self) -> ConnectionId {
        ConnectionId::new(&self.keys.mint())
    }
    fn validate(&self, cid: &ConnectionId) -> Result<(), InvalidCid> {
        if self.keys.validate(cid) {
            Ok(())
        } else {
            Err(InvalidCid)
        }
    }
    fn cid_len(&self) -> usize {
        CID_LEN
    }
    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

/// Control generator: mints MAC'd CIDs but keeps the accept-all default `validate()`
/// (spike 001 behavior), so unknown CIDs still get a stateless reset.
#[derive(Debug)]
pub struct AcceptAllCidGen {
    pub keys: Arc<MacCidKeys>,
}

impl ConnectionIdGenerator for AcceptAllCidGen {
    fn generate_cid(&mut self) -> ConnectionId {
        ConnectionId::new(&self.keys.mint())
    }
    fn cid_len(&self) -> usize {
        CID_LEN
    }
    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Arc<MacCidKeys> {
        MacCidKeys::random(&[0, 1])
    }

    #[test]
    fn round_trip_generate_validate() {
        let k = keys();
        for _ in 0..64 {
            let cid = k.mint();
            assert!(k.validate(&cid));
        }
    }

    /// Known-answer vector. SELF-GENERATED consistency vector (computed once from this code,
    /// pasted as a constant): it guards against regressions of this exact construction,
    /// it is NOT an external KAT.
    #[test]
    fn known_answer_vector() {
        let mut raw = [0u8; 32];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        let k = MacCidKeys::from_raw(1, &[(0, raw), (1, raw)]);
        let cid = k
            .assemble(1, [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6])
            .unwrap();
        assert_eq!(
            cid,
            [
                0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0x64, 0x19, 0xca, 0x48, 0x50, 0x3b,
                0x3f, 0xbc
            ],
            "actual: {}",
            cid.iter().map(|x| format!("{x:02x}")).collect::<String>()
        );
    }

    #[test]
    fn tamper_every_byte_rejected() {
        let k = keys();
        let cid = k.mint();
        // kid byte (both flip and unknown-kid), every nonce byte, every tag byte
        for i in 0..CID_LEN {
            let mut t = cid;
            t[i] ^= 0x5a;
            assert!(!k.validate(&t), "flip at byte {i} must be rejected");
        }
        // wrong lengths
        assert!(!k.validate(&cid[..CID_LEN - 1]));
        assert!(!k.validate(&[]));
        let mut long = cid.to_vec();
        long.push(0);
        assert!(!k.validate(&long));
        // unknown kid
        let mut t = cid;
        t[0] = 0xff;
        assert!(!k.validate(&t));
    }

    #[test]
    fn cross_instance_rejected() {
        // the "process/key restart" primitive: a CID minted under instance A's keys
        // must not validate under a fresh instance B.
        let a = keys();
        let b = keys();
        let cid = a.mint();
        assert!(a.validate(&cid));
        assert!(!b.validate(&cid));
    }

    #[test]
    fn validate_never_panics_on_garbage() {
        let k = keys();
        let mut xorshift = 0x243f6a8885a308d3u64;
        for len in 0..40usize {
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                xorshift ^= xorshift << 13;
                xorshift ^= xorshift >> 7;
                xorshift ^= xorshift << 17;
                *b = (xorshift >> 24) as u8;
            }
            let _ = k.validate(&buf);
        }
    }
}
