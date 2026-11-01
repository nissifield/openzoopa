# Spike 002: quinn CID reset behavior (phase 0, throwaway)

> **STATUS**
> - "VALIDATED" in this file means: observed on loopback, on one Linux host, in the runs described
>   here. It does **not** close DESIGN §3.4 or the §8 phase-0 exit criteria.
> - Design consequences below are **RFC inputs, not decisions**.
> - `src/cid.rs` (and this whole crate) must **never become production code**. Any adoption needs
>   the §3.4 RFC and a second maintainer.

Standalone spike (empty `[workspace]`, not part of the root workspace, `publish = false`).
The MAC construction in `src/cid.rs` exists only to exercise quinn's
`ConnectionIdGenerator::validate` behavior; the real construction needs crypto review and an RFC.
Spike MAC: `HMAC-SHA256(K_cid[kid], b"spike002-cid" || kid || nonce)[0..8]`, CID = `kid(1) || nonce(7) || tag(8)`.

What it asks: can a MAC'd server CID plus `validate() == Err` give the edge "dark" behavior
(silence, not stateless resets) against unauthenticated probes, and what does quinn do with
never-issued/closed CIDs, garbage Initial Token fields, NEW_TOKEN, GRO/coalescing, IPv6 and loss.

**License.** Apache-2.0 (Cargo `license` + SPDX headers), per LICENSING.md's rule for unlisted
crates. This does NOT address the separate DCO/authorship issue: all agent-authored commits on this
branch still need the human maintainer's own provenance/sign-off action before any public push.

**MSRV.** None declared and none claimed. The highest declared dependency minimum is Rust 1.85;
this code also uses `AtomicU32::try_update`. Everything was built and tested only with rustc 1.99.1.

## How to run

```sh
cargo test --manifest-path spikes/002-quinn-cid-reset/Cargo.toml -- --nocapture   # exit 0: 5 unit + 20 integration passed, 0 failed (run twice)
cargo fmt  --manifest-path spikes/002-quinn-cid-reset/Cargo.toml -- --check       # exit 0
cargo clippy --manifest-path spikes/002-quinn-cid-reset/Cargo.toml --all-targets -- -D warnings  # exit 0
```

`target/` is untracked and ignored (`.gitignore`). Do not commit it.

## Pinned versions and source refs

quinn **0.11.12**, quinn-proto **0.11.19** (exact pins; a lockfile test asserts them). quinn-proto
is built with `default-features = false`, so `bloom` is OFF: `ValidationTokenConfig::default()`
sends 0 NEW_TOKEN frames and its default `NoneTokenLog` rejects every presented validation token
(`token.rs:70-76`), so both are configured explicitly for 4b.

Refs are against `~/.cargo/registry/src/*/quinn-proto-0.11.19/` unless noted.

| Claim | Source |
|---|---|
| Version Negotiation for unsupported versions (packets < 1200 B dropped at :184) | `endpoint.rs:172-211` |
| Existing CID routing runs BEFORE `validate()` | `endpoint.rs:221`, `:1099-1126` |
| Long-header non-Initial with unknown CID is dropped | `endpoint.rs:249-253` |
| `validate()` drops an UNROUTED SHORT-HEADER packet with invalid MAC (non-Initial); long non-Initials are dropped earlier (:249-253); routing (:221) comes first | `endpoint.rs:259-263` |
| Stateless reset: call, fn, limiter | `:270`, `:275`, `:283-289` (ONE endpoint-wide `last_stateless_reset` + `min_reset_interval`, default 20 ms `config/mod.rs:64`; not per CID; resumes after the interval) |
| Reset padding length random (:314-319); tail `ResetToken::new(reset_key, cid)` deterministic per (reset_key, cid), so linkable; default `reset_key` random per endpoint | `endpoint.rs:314-324`, `config/mod.rs:186-189` |
| Short-DCID (< 8 B) Initial -> `initial_close` CONNECTION_CLOSE | `endpoint.rs:480-489` |
| `initial_close(INVALID_TOKEN)`: a successfully DECODED Retry token whose full SocketAddr mismatches, or which is expired | `endpoint.rs:510-522`, `token.rs:152-157` |
| Undecodable token falls through as unvalidated | `token.rs:141-143` |
| NEW_TOKEN token with client-IP mismatch -> `Ok(unvalidated)` (IP is needed for address validation, not to connect) | `token.rs:165-167` |
| `initial_close` emits MAC-valid, never-routed SCIDs | `endpoint.rs:887` |
| `EndpointConfig::min_reset_interval` is pub | `config/mod.rs:147` |
| Dropping an `Incoming` calls `refuse()`; a closing endpoint refuses new connections | quinn-0.11.12 `incoming.rs:103-109`, `endpoint.rs:811-816` |
| Validation-token defaults without `bloom`: `sent = 0`, `NoneTokenLog` | `config/mod.rs:524-536` |
| Client token bytes go verbatim into the Initial Token field | `config/mod.rs:609`, `connection/mod.rs:3851-3856` |

## Verdicts (items 1-8)

Run twice on this machine (loopback, Linux, unprivileged, rustc 1.99.1): 25 tests passed, 0 failed.
Numbers marked "obs." were printed in one run and are NOT asserted.

| # | Item | Verdict | Evidence / scope |
|---|---|---|---|
| 1 | MAC'd 16B CIDs + shared validate | **VALIDATED (unit level)** | 5 unit tests: round-trip, self-generated KAT (not external), every-byte tamper rejected, cross-instance rejected, garbage never panics |
| 2a | Silence for unknown non-MAC SHORT-HEADER CID | **VALIDATED (that class only)** | Filtered: 0 responses, send counter (0,0). Unfiltered MAC-validate endpoint: 0 responses. Control (accept-all validate): exactly 1 reset, so `validate()` is the cause for this class. Long headers (VN, short-DCID close, Retry INVALID_TOKEN) never reach `validate()` and need the filter (control test shows quinn answers VN and the short-DCID Initial with CONNECTION_CLOSE; the Retry INVALID_TOKEN path is source-only) |
| 2b | Never-issued, MAC-valid, unrouted CID | **RECORDED (PARTIAL)** | Filter accepts; quinn answers exactly one stateless reset (reset size is random; obs. 431 B in one run). A party that has SEEN/copied a server CID (no key possession needed) can probe its state: closed/unrouted CID -> reset (observed here); live/routed CID -> silence is SOURCE-ONLY from Quinn routing/decryption, NOT RUN with a live-CID probe. quinn also emits MAC-valid never-routed SCIDs in `initial_close` (`endpoint.rs:887`). The reset tail is linkable per `reset_key`. Reset-key sharing across edges and a stateful issued-CID check are RFC inputs. Not fixed here |
| 2c | Closed-connection CID reset under a 1 s `min_reset_interval` | **VALIDATED (response pattern)** | Phase A: one probe on the closed CID gets exactly 1 reset (CID no longer routes). Phase B: two probes inside the interval, filter accepted both (delta == 2), 0 responses, send counter unchanged. Phase C: after the interval, one probe gets exactly 1 more reset (send counter 2 datagrams). Pattern is consistent with quinn's endpoint-wide limiter (`:283-289`); which branch suppressed B is source-only (padding branch :296-304 cannot fire at 1200 B); filter acceptance is not proof of quinn processing; quinn discards send errors. Not one reset per CID forever. 1 s interval, not the 20 ms default; a 500 ms close-propagation sleep is a timing assumption |
| 2d | Fresh-key instance rejects old-key CIDs | **VALIDATED (narrow)** | Fresh-key endpoint/filter: 0 responses / (0,0) for an old-key CID, filtered and unfiltered. NOT a real process restart nor in-place rotation: with a persisted CID key, old CIDs would behave like 2b/2c. SOURCE-ONLY inference: a filter retiring a kid would kill live connections even though quinn's routing would keep them (routing precedes `validate()`); an RFC needs key overlap / two-epoch handling |
| 3 | Never-issued, unrouted, MAC-valid 16 B DCID Initial -> `Incoming` -> `ignore()` | **OBSERVED (narrow)** | Passes the preliminary checks (v1, >= 1200 B). obs. `incoming=3 ignored=3`, `validated=[false x3]`, send_to_client (0,0) over the 6 s window, client timed out. Not general A2 safety. A live (routed) CID Initial is untested: routing precedes `Incoming`. Product code must call `ignore()` rather than implicitly drop a delivered `Incoming`; a closing endpoint can refuse **before** the application receives it, requiring filter/socket suppression as an RFC input |
| 4a | Garbage Initial Token field, Retry never issued by this fixture | **OBSERVED** | 64-byte token on the wire (obs. field lens `[64, 64]`), handshake completed, `validated=[false]`. Undecodable tokens fall through (`token.rs:141-143`). A decoded Retry token with SocketAddr mismatch/expiry would get INVALID_TOKEN (`token.rs:152-157`); Retry-off does not disable recognition of Retry tokens minted under a shared token key |
| 4b | NEW_TOKEN round trip | **OBSERVED** | `sent(1)` + accept-all TokenLog: `validated=[false, true]` for conn1/conn2 on the same client endpoint. quinn ties the token to client IP for address validation only (`token.rs:165-167`); the filter binds the full SocketAddr. Different-IP/port NEW_TOKEN cases **NOT RUN** |
| 5 | GRO / coalescing | **PARTIAL** | GRO: obs. `gro_batches=1`, printed not asserted; instrumentation + handshake path only. Coalesced long headers: **NOT RUN** in this run (captured first flight was 1 Initial per datagram, 2 x 1200 B). Mixed accept/drop batch compaction and all-dropped batches untested. netns is not necessary to force these; constructed datagrams/socket fixtures could |
| 6 | IPv4+IPv6 silence on loopback | **VALIDATED (loopback) / netns NOT RUN** | IPv4: 10 probe classes silent (obs. `dropped=9`, empty datagram uncounted; `total_sent_dgrams=0` asserted). IPv6 `[::1]`: 3 probes silent; a bind failure now FAILS the test (no `catch_unwind`). netns **NOT RUN**: `unshare -Urn true` failed earlier, not reproduced in this pass |
| 7 | Recovery after one swallowed outgoing `Transmit` batch | **OBSERVED** | Handshake completed (obs. ~1.0 s, `token_dcid_seen=4 accepted=4`). A batch may hold several GSO datagrams. Retransmission is INFERRED from `token_seen >= 3`, not counted directly |
| 8 | Parser panic-freedom, selected denials | **VALIDATED (bounded)** | Prefixes 0..63 and one 0xa5 XOR at each of the first 64 positions (panic-freedom only); 26 selected header-mutation denial assertions (bytes 0..26) plus a positive control (unmutated token Initial still accepted); grease-bit-cleared dropped. Not packet validation, not fuzzing; no fuzz target |

## Skipped / NOT RUN

- `cargo-fuzz` target for the parsers (a product parser of this shape needs one).
- netns/veth darkness runs; forced GRO / coalescing; mixed accept/drop GRO batches.
- Retry-issued cases; different-IP/port NEW_TOKEN cases.
- Live (routed) CID Initial against `Incoming` (A2 live-CID path).
- Closing-endpoint / implicit-drop refusal behavior.
- Real process restart and in-place key rotation.
- MSRV testing; dependency-license audit (cargo-deny/vet).
- Fix for the 2b reset oracle (recorded, not fixed).

## Design consequences (RFC inputs, not decisions)

1. For unrouted short-header packets with an invalid MAC, `validate() == Err` suppresses the stateless
   reset (`endpoint.rs:259-263` vs `:270`). It does not cover long headers (VN, short-DCID close,
   Retry INVALID_TOKEN); per source those need the userspace filter or an equivalent (only VN and short-DCID close were exercised).
2. 2b: MAC-valid but unrouted CIDs get a rate-limited reset (observed). If live CIDs stay silent
   (source-only, not probed), this is a live-vs-closed oracle for anyone who has seen a CID. The
   limiter is endpoint-wide, so it bounds rate, not information. Options for the RFC:
   accept the leak, a stateful issued-CID check, and how `reset_key` is shared across edges.
3. A MAC filter that retires a kid also kills live connections that quinn's routing would keep;
   any rotation design needs overlapping keys. Fresh-key behavior (2d) says nothing about
   persisted-key restarts.
4. The specimen in item 3 was ignored with zero sends. Whether other Initials are safe is untested.
   Product code must call `ignore()` explicitly on rejection, which covers only the implicit-drop
   refusal path. A closing endpoint refuses inside quinn's driver before the application sees the
   `Incoming` (quinn `endpoint.rs:810-816`, source-only); suppressing that needs the filter/socket
   layer and is an RFC input.
5. The Initial Token field is not an auth channel here: undecodable tokens are accepted unvalidated.
   quinn binds NEW_TOKEN address validation to client IP only (mismatch -> connection proceeds unvalidated); the spike filter binds the full SocketAddr.
