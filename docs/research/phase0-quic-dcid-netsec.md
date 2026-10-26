> Preliminary read-only analysis by the zoopa-netsec project agent, task fd59ec49. Claims other than the client API require independent source/run verification before becoming design decisions. **SUPERSEDED where it disagrees with the runtime spike:** `spikes/001-quinn-dcid/` ran the mechanism on loopback against pinned quinn 0.11.12 / quinn-proto 0.11.19; where this document's preliminary source-only claims and the spike's measured results disagree, the spike wins.

# Can the quinn client set the Initial DCID? (§3.4 / §8 phase-0 question 1)

**Answer: yes, with released quinn and no patch.** But §3.4 as written has one bug that breaks handshakes and one claim that QUIC itself makes false. Both need an RFC'd amendment (§11 #9) before anyone builds on it.

Only the `initial_dst_cid_provider` API claim was checked first-hand (on docs.rs). Everything else below relies on upstream source fetches; line numbers marked `~` are approximate. Where a line range is exact (`:NNN-MMM`), it was verified against the local cargo registry copy of quinn-proto 0.11.19 during the spike review.

**Versions:** quinn 0.11.12 and quinn-proto 0.11.19 are the latest releases. quinn-rs/quinn `main` is quinn-proto 0.12.0, unreleased. The spike pins exact versions via `spikes/001-quinn-dcid/Cargo.lock`.

## The aspects you listed

| Aspect | Finding | Evidence | Verdict |
|---|---|---|---|
| **Choosing the Initial DCID** | `quinn_proto::ClientConfig::initial_dst_cid_provider(&mut self, Arc<dyn Fn() -> ConnectionId + Send + Sync>) -> &mut Self`, re-exported by `quinn`. It is called once per `connect`. quinn does not check the length; the docs say "MUST be at least 8 bytes long and unpredictable" (RFC 9000 §7.2). The default is 20 random bytes (`MAX_CID_SIZE = 20`). It first appears in the 0.11.5 docs (0.11.4 docs are missing, so that's uncertain). | [docs.rs quinn-proto 0.11.19 ClientConfig](https://docs.rs/quinn-proto/0.11.19/quinn_proto/struct.ClientConfig.html) (I checked this); `quinn-proto/src/endpoint.rs` ~345 @0.11.19 (agent) | **Holds** |
| ↳ catch | The closure takes no arguments, so it can't see `edge_id`. Build one `ClientConfig` per edge dial, with a closure that captures `edge_id`, and dial with `Endpoint::connect_with`. Assert the result is exactly 20 bytes on the client side. | same | Easy to handle |
| **Server-issued CIDs** | After the server's first Initial, the client must send to the server's SCID (RFC 9000 §7.2), so the filter has to accept MAC-valid server CIDs on Initials. quinn's `HashedConnectionIdGenerator` uses a non-cryptographic hash (3-byte nonce, 5-byte tag) and isn't good enough. We need a custom `ConnectionIdGenerator` built on aws-lc-rs HMAC, with `validate()` sharing the filter's code. That is a new construction, so it needs an RFC and crypto review (§5.3). | `cid_generator.rs` ~167 @main (agent) | Needs a project construction |
| **Retry** | The second Initial's DCID is the Retry SCID, which comes from `local_cid_generator`, so the server-CID MAC covers it. quinn takes `orig_dst_cid` from its own sealed Retry token, so the token check still works after a Retry. **Caveat (added after the spike):** with Retry enabled, quinn can emit CONNECTION_CLOSE(INVALID_TOKEN) *before* any `Incoming` exists — `handle_first_packet` (`endpoint.rs:512-525` @0.11.19) replies via `initial_close` (`endpoint.rs:875`) when `IncomingToken::from_header` fails — so `Incoming::ignore()` gating alone is insufficient for darkness. Unverified at runtime; the spike never ran the Retry path. | `endpoint.rs` ~701 @0.11.19 (agent); `endpoint.rs:512-525`, `:875` @0.11.19 (verified) | Holds, with the INVALID_TOKEN caveat |
| **Stateless reset** | Unknown short headers fail `validate()` and are dropped before any reset: the validate branch is `endpoint.rs:259-263` @0.11.19 (verified), `fn stateless_reset` is `:275`. `EndpointConfig` has no switch to turn resets off (only `min_reset_interval`). A2 replaying the CID of a *closed* connection gets one reset back — that is the case where `validate()` accepts but no connection matches. | `endpoint.rs:259-263`, `:275` @0.11.19 (verified) | Holds against A1. Against A2 it's a leftover leak that the invariant's wording allows. **No patch is needed for the unknown-CID case**: a `ConnectionIdGenerator::validate()` that returns `Err` for unknown/retired CIDs suppresses the reset entirely (source-only; the spike did not exercise it — its CID generator keeps the accept-all default). What quinn lacks is a switch for the closed/unknown-CID-with-valid-prefix case where `validate()` accepts. |
| **Version Negotiation** | quinn sends VN only when it has a server config and the datagram is ≥1200 bytes. The filter drops every version except `0x00000001` before quinn sees it. Also set `EndpointConfig::supported_versions(vec![1])`. | `endpoint.rs:172-211` @0.11.19 (verified) | Holds |
| **CID lengths** | A 20-byte Initial DCID can coexist with the server's fixed `cid_len`, because long headers carry an explicit length. Server CIDs should be ≥16 bytes so the MAC has room, and should leave space for the QUIC-LB server IDs planned in §7.8. | `early_validate_first_packet` ~650 (agent) | Holds |
| **NAT / migration** | Short headers are checked by CID MAC only, never by source address. Migration goes through quinn's normal path validation, so CGNAT is fine (§7.6). | RFC 9000 §8, §9 | Holds |
| **QUIC-bit greasing** | quinn greases the fixed bit by default. RFC 9287 §3 then requires accepting packets with the bit cleared, so a filter that checks the bit would break. Set `grease_quic_bit(false)` on the edge. | RFC 9287 §3 | Small fix |

## Conflicts with the QUIC wire format and security model

1. **The replay cache breaks every PQ handshake (design bug).** *(INVALIDATED as stated by the spike: a clean handshake completes, because the server's ACK of the first Initial hands the client the server CID and the client switches its DCID to it. The real failure needs loss of the server's ACK-only reply — the server's only reply to the first token Initial, which is never retransmitted — after which the client keeps retransmitting under the token DCID and the naive rule drops every retransmission. The binding fix below stands.)*
   - An X25519MLKEM768 key share is about 1216 bytes, so the ClientHello takes two Initials (§3.6).
   - RFC 9000 §7.2 says the client MUST use the same DCID on every packet until the server replies, and retransmissions reuse it too.
   - So §3.4's rule "drop exact replays of `(ts, nonce)`" throws away the second Initial and every retransmission.
   - **Fix:** turn the cache into a binding. The first sighting of token T from address R records `T → R`. Later packets with T are accepted only from R, up to about 16. Anything else is dropped.

2. **"The QUIC/TLS stacks are unreachable without a current SPA key" can't be true against A2.**
   - Server CIDs travel in the clear, and the filter must accept them on Initials (see the Server-issued CIDs row).
   - So an on-path observer can copy one into a fresh Initial and reach quinn without K_spa.
   - **Fix:** in the edge accept loop, call `Incoming::ignore()` unless `spa_verify(incoming.orig_dst_cid())` passes. Never call `refuse()`, because it sends bytes.
   - Even with that fix, A2 still reaches quinn's Initial decoding and Retry-token decryption. The §3.4 wording needs an amendment to say darkness is targeted at A1 (off-path) — not proven as a guarantee; against A2 it is reduced to that pre-auth surface.

3. **No other conflicts.**
   - RFC 9001 §5.2 derives Initial keys from the token, which is fine: Initial protection isn't confidential anyway.
   - The `hdr` and `ts` fields make tokens distinguishable from random bytes. That's a fingerprint, but it falls under §9.4 (traffic analysis is out of scope).
   - A3, a compromised endpoint holding K_spa, gets past SPA for up to about 48 h, as §3.4 already documents.
   - No project invariant is violated.
   - Also drop the 0-RTT row from the filter table, since 0-RTT is disabled anyway.

## Proposed spike (throwaway, 2-day time box)

**Setup:** one binary, quinn pinned to `=0.11.12` and quinn-proto to `=0.11.19`, with rustls and aws-lc-rs. Two `Endpoint`s on 127.0.0.1. The edge uses `Endpoint::new_with_abstract_socket` with a filter on receive and a byte counter per destination on send. A raw `UdpSocket` acts as the prober.

**Pass if every item below holds:**
1. The first datagram's DCID is the 20-byte token, and `Incoming::orig_dst_cid()` equals it.
2. The negotiated group is X25519MLKEM768 and at least 2 datagrams carry the token DCID. With "drop exact replays" the handshake times out; with the binding from conflict 1 it completes. This proves both the bug and the fix.
3. If the edge's first send is dropped once, the handshake still completes.
4. When `retry()` is forced, the second DCID is the Retry SCID, `validate()` passes, `orig_dst_cid()` is still the token, and the handshake completes.
5. Each of these probes gets **0 bytes back within 2 s**, and the send counter for the probe address stays at 0:
   - an Initial with a random DCID;
   - a version `0x1a2a3a4a` probe;
   - a 1200-byte short header with a random CID;
   - a captured token sent from another source port;
   - a Handshake packet with a random CID;
   - an Initial carrying a captured server CID.
6. Recorded, not counted as a failure: the CID of a closed connection gets exactly one stateless reset back.
7. Filter robustness: 64 junk datagrams followed by one valid Initial still complete the handshake with no stall. This covers what `poll_recv` does when the filter drops every datagram in a GRO batch, which isn't documented.

**Fallback if DCID control turns out to be impossible** (not expected, given the source):
- First, carry a small quinn-proto patch and offer it upstream.
- Next, put the token in the Initial Token field via `ClientConfig::token_store`. How quinn's server handles a token it can't decode is unverified.
- Rejected: hiding the token in the ClientHello ALPN. The filter would have to derive Initial keys, decrypt, and reassemble CRYPTO frames across two Initials. That's a second pre-auth parser, which defeats the point.

## Does this wait on §11 licensing and trademark? (from the `zoopa-architect` rules; that agent wasn't invoked)

No. §11 #1 and #2 block the *public repo and releases* (amendment §11 table), not private throwaway work. The spike answers §11 #9, which is the spike itself.

Keep it outside the product tree, with no license header, nothing published, and no "openzoopa" artifacts. Clean-room from public docs only; quinn and rustls are MIT/Apache, so there's no conflict. Nothing in it is assumed to carry over into AGPL or Apache crates.

Skipped/Not checked: I checked only the `initial_dst_cid_provider` API myself; every other upstream claim comes from the agent's fetches, with approximate line numbers. Not checked by anyone: the exact RFC 9000 §10.3 "MAY" wording, what `poll_recv` does with `Ok(0)` or GRO batches, how quinn handles an undecodable NEW_TOKEN, whether rustls offers X25519MLKEM768 by default, and the anti-amplification spike.
Risk: Until §3.4 is amended, the replay-cache rule breaks any handshake in which the client must retransmit under the token DCID (a lost first server reply deadlocks it — demonstrated; clean handshakes complete, so "breaks every PQ handshake" is false), and the "unreachable without K_spa" claim is false against an on-path observer. quinn 0.12 changes the `AsyncUdpSocket` API, so the filter wrapper will need a rewrite.