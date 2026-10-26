# Spike 001: quinn initial-DCID control + userspace UDP prefilter

**Throwaway phase-0 feasibility spike. Not product code.** It answers DESIGN.md §3.4's "Phase-0 spike (blocking)" and
`docs/research/phase0-quic-dcid-netsec.md`. It validates two things only: (a) the client can choose its Initial DCID with
released quinn 0.11.12, and (b) the demonstrated synthetic filtering plumbing drops unauthenticated packets silently on
loopback and passes valid traffic. The full DESIGN.md §3.4 mechanism is **NOT** validated end-to-end (PARTIAL; see
Verdicts and Missing/unsupported).

Scope disclaimers (read these first):

- `SYNTHETIC_DCID = b"SYNTHETIC-NOT-A-KEY!"` is **not a security mechanism**. There is no HMAC, no key, no real secret. It only
  proves the *plumbing*: the client can put 20 chosen bytes in the Initial DCID, and a prefilter can act on them.
- Server-issued CIDs are recognised by a fixed 8-byte prefix (`SYNSRVID`). Anyone who has seen one packet on the wire can forge
  that. This spike makes **no claim of dark-edge security against an on-path attacker (A2)**: server CIDs travel in the clear.
- Linux client only, loopback only (127.0.0.1, ephemeral ports). Nothing here is assumed to carry into the Apache/AGPL crates.

## Layout

- `src/lib.rs`: `FilterSocket` (a quinn `AsyncUdpSocket` wrapper), `SynthCidGen` (server `ConnectionIdGenerator`), `peek()`
  (bounds-checked header parser), fixtures.
- `tests/dcid.rs`: 13 tests over loopback, every wait bounded: 10 `#[tokio::test]`, 3 plain `#[test]`
  (`lock_resolves_exact_versions`, `peek_never_panics_on_truncation`, `rustls_prefers_x25519mlkem768`). The new test in
  this corrective pass is `mlkem_only_client_completes_handshake_through_filter`.
- Set `SPIKE_TRACE=1` to print a line per datagram the filter sees.

Filter rule (spike only): accept a v1 long header whose DCID is `SYNTHETIC_DCID` **and** is an Initial of >= 1200 bytes **and**
passes the mode check (below), or any v1 long / short header whose DCID is 16 bytes starting with `SYNSRVID`. Everything else
is dropped silently: other versions, fixed bit cleared, malformed, unknown DCID, wrong length. Deny is the default branch.
Only the first coalesced packet's DCID is inspected.

Modes: `NaiveReplay` = DESIGN.md §3.4 as written (second sighting of the token DCID is dropped). `Binding` = first sighting
binds token -> source addr, repeats accepted from that addr only, cap 16.

Server endpoint config: `supported_versions([1])`, `grease_quic_bit(false)`, custom CID generator (16 bytes), 0-RTT not
enabled, no Retry. The edge accept loop calls `Incoming::orig_dst_cid()`, then `ignore()` unless it equals the token (never
`refuse()`, which sends bytes).

## Versions (from `Cargo.lock`)

| crate | resolved |
|---|---|
| quinn | **0.11.12** (pinned `=`) |
| quinn-proto | **0.11.19** (pinned `=`) |
| quinn-udp | 0.5.16 |
| rustls | 0.23.46 (features `std`, `aws-lc-rs`, `prefer-post-quantum`) |
| aws-lc-rs / aws-lc-sys | 1.18.2 / 0.46.0 (built fine here; no ring fallback needed) |
| tokio | 1.54.1 |
| rcgen | 0.13.2 |
| toolchain | rustc 1.99.1 / cargo 1.99.1 |

`lock_resolves_exact_versions` asserts the two quinn lines in `Cargo.lock`.

## Commands run (cwd = this directory) and exit codes

Initial pass:

| command | exit |
|---|---|
| `cargo generate-lockfile` | 0 |
| `cargo build` (aws-lc-sys compiled) | 0 |
| `cargo fmt` / `cargo fmt --check` | 0 / 0 |
| `cargo clippy --all-targets -- -D warnings` | 0 (no warnings) |
| `cargo test -- --nocapture --test-threads=1` | 0 (12 passed, 14.8 s) |
| `cargo test` x5 (flake check, default threads) | 0, 0, 0, 0, 0 (12 passed each, ~6.5 s) |

Corrective pass (tests/docs only, after two independent reviews):

| command | exit |
|---|---|
| `cargo fmt --all` / `cargo fmt --all -- --check` | 0 / 0 |
| `cargo clippy --all-targets -- -D warnings` | 0 (no warnings) |
| `cargo test -- --nocapture --test-threads=1` | 0 (13 passed, ~16 s) |
| `cargo test` (flake check, default threads) | 0 (13 passed, ~6.5 s) |
| `git diff --check` | 0 |

To reproduce from the repo root: `cargo test --manifest-path spikes/001-quinn-dcid/Cargo.toml -- --nocapture`.
There is no `cargo run` target: the tests print every observation with `--nocapture`.

Provenance: implemented by the `zoopa-builder` subagent (it ran, via the Agent tool) under chrono's approved takeover of
Kimi task `e16c3acf`. The corrective pass above (tests/docs only, race-free drop counter, 7-byte DCID control,
MLKEM-only handshake test, strengthened replay/loss assertions) was likewise implemented by the `zoopa-builder`
subagent under chrono-approved continuation; the parent session re-verified. The parent session then independently
re-ran the initial pass from the repo root:

| command | exit |
|---|---|
| `cargo test --manifest-path spikes/001-quinn-dcid/Cargo.toml` | 0 (12 passed, 6.46 s) |
| `cargo fmt --manifest-path spikes/001-quinn-dcid/Cargo.toml -- --check` | 0 |
| `cargo clippy --manifest-path spikes/001-quinn-dcid/Cargo.toml --all-targets -- -D warnings` | 0 |

## Source references (checked in the local cargo registry)

- quinn-proto-0.11.19 `src/config/mod.rs:592` `ClientConfig::initial_dst_cid_provider`; default is 20 random bytes (`:578`).
- quinn-proto-0.11.19 `src/endpoint.rs:355` calls the provider once per connect; Version Negotiation `:172-211` (only for
  datagrams >= 1200 B); validate()-before-reset drop branch `:259-263`; stateless reset fn `:275` onwards.
- quinn-proto `config/mod.rs:122` `supported_versions`, `:132` `grease_quic_bit`, `:77` `cid_generator`.
- quinn-0.11.12 `src/runtime.rs:42` `AsyncUdpSocket`; `src/endpoint.rs:133` `Endpoint::new_with_abstract_socket`;
  `src/incoming.rs:63` `ignore`, `:98` `orig_dst_cid`.

## Observations

**(a) Client-chosen Initial DCID.** `ClientConfig::initial_dst_cid_provider` set to `SYNTHETIC_DCID`; first datagrams captured on
a raw socket:

```
captured 2 client datagram(s) before first retransmission
  len=1200 first=c9 version=1 type=0 dcid_len=20 dcid=53594e5448455449432d4e4f542d412d4b455921
  len=1200 first=c1 version=1 type=0 dcid_len=20 dcid=53594e5448455449432d4e4f542d412d4b455921
```

Hex = ASCII `SYNTHETIC-NOT-A-KEY!`. Long header, version 1, Initial, DCID length 20, both datagrams padded to 1200.
On the filtered server, `Incoming::orig_dst_cid()` = `53594e5448455449432d4e4f542d412d4b455921` (the token).

**Key exchange.** quinn exposes no stable API for the negotiated group. The strong-form proof is
`mlkem_only_client_completes_handshake_through_filter`: the client's `CryptoProvider.kx_groups` is restricted to
X25519MLKEM768 only, and it completes a real quinn handshake through the filter — a completed handshake with a single
offered group proves that group by construction. Corroboration: `rustls_prefers_x25519mlkem768` runs an in-memory rustls
TLS 1.3 handshake with the same config: `negotiated group = Some(X25519MLKEM768)`, first client flight 1458 bytes. This is
also corroborated on the wire: *this* ClientHello (~1458 B) spans **2 Initial datagrams** at 1200 B MTU/padding in every
observed quinn handshake (not a universal constant; other ClientHellos may span more).

**(b) Zero response.** Probes from raw sockets to the filtered server (window 1.5 s each, `Binding` mode):

| probe | bytes received | server send counter for prober | control? |
|---|---|---|---|
| v1 Initial-looking, random 20 B DCID, 1200 B | 0 | 0 | no |
| unknown version 0x1a2a3a4a, 1200 B | 0 | 0 | yes |
| truncated long header (3 B) | 0 | 0 | no |
| long header, DCID len 255 beyond buffer | 0 | 0 | no |
| empty datagram | 0 | 0 (see note) | no |
| 1200 B short header, random 16 B CID | 0 | 0 | yes |
| token DCID but Handshake type | 0 | 0 | no |
| token DCID Initial < 1200 B | 0 | 0 | no |
| v1 Initial, wrong-length DCID (7 B, below RFC 9000 min 8 B) | 0 | 0 | yes |
| captured valid Initial replayed from another source addr after binding | 0 | 0 | no |

"control?" = an unfiltered control exists for this probe (below), so the filtered zero is attributable to the filter.
Replay row, strengthened evidence: replay **rejected by the filter** — `token_accepted` unchanged, no second `Incoming`,
0 responses, send counter 0.

Total datagrams sent by the endpoint during the probe test: **0**; quinn never produced an `Incoming`; `dropped=8` (the empty
datagram is skipped by the filter's own stride loop: `total == 0` never iterates, `w` stays 0, and the datagram is compacted
out, so it counts neither as dropped nor as accepted).

**Control (so the zeros mean something).** Same server config, unfiltered socket:

```
control unknown-version probe: 1 response(s), lens [35]      (Version Negotiation: versions 0a1a2a3a, 00000001)
control short-header, unknown CID: 1 response(s)             (stateless reset; 290 B this run, varies across runs)
control short-DCID Initial: 1 response(s), lens [77]         (v1 long-header CONNECTION_CLOSE(PROTOCOL_VIOLATION))
```

The short-DCID control: a v1 Initial with a 7-byte DCID is below RFC 9000's 8-byte minimum; unfiltered quinn-proto
0.11.19 answers with exactly one v1 long-header CONNECTION_CLOSE(PROTOCOL_VIOLATION) — `early_validate_first_packet`
(`endpoint.rs:706-723`) rejects it and `handle_first_packet` replies via `initial_close` (`:481-488`). The error code
itself sits inside the encrypted Initial payload and is identified from source, not decrypted.

Valid traffic: a real quinn client with the synthetic-DCID provider completes the handshake through the filtered server in
`Binding` mode and echoes `ping` on a bidi stream (`binding: token_dcid_seen=2 accepted=2 server_cid_accepted=4`; server sent
6 datagrams / 4141 bytes, all to the client). Junk flood: 100 junk v1 Initials, then a valid handshake completes in ~7 ms
(`dropped=92` of 100 sent; the ~8 unaccounted junk datagrams are plausibly lost to kernel receive-buffer overflow — 100
datagrams sent back-to-back faster than the endpoint drains them — plausible, not proven). The GRO stride-split/compaction
code path was written, but no test forces a batch and whether GRO was active on this loopback (or any batch occurred at
all) is **unknown / not measured** (see unsupported list).

**Replay-cache hypothesis (research claim: "'drop exact replays' breaks every PQ handshake").**

| scenario | NaiveReplay | Binding |
|---|---|---|
| clean loopback | **completes** (9-430 ms across runs); `token_seen=2 accepted=1` | completes; `seen=2 accepted=2` |
| one server `try_send` dropped (a `Transmit`, which may carry several coalesced/segmented datagrams) | **fails**: 5 s timeout, `token_seen=6 accepted=1`, endpoint send counter stays 0 | completes in 1.007 s, `seen=4 accepted=4` |

Why the clean case completes under the naive rule: the server ACKs the first Initial, which hands the client the server's SCID.
The client switches its DCID to the server CID and retransmits the dropped second Initial under it, and the filter accepts that
by CID. The naive rule only breaks when the client has to keep retransmitting under the token DCID. In the loss arm the
injected drop is consumed (asserted) and the endpoint send counter stays 0 (asserted) — one reply was attempted,
swallowed, and nothing was sent after. That the swallowed reply was an ACK-only Initial (which is never retransmitted)
is **INFERRED** from the deadlock plus the zero send counter, not directly observed. Losing/shedding it deadlocks the
handshake: the client keeps retransmitting under the token DCID and the naive filter drops every retransmission.

## Verdicts

| question | verdict | basis |
|---|---|---|
| (a) client can choose a 20-byte Initial DCID | **VALIDATED** | quinn 0.11.12 / quinn-proto 0.11.19 unpatched; DCID observed on the wire and in `orig_dst_cid()` |
| (b) userspace prefilter drops unauthenticated packets with zero response and lets valid traffic handshake | **PARTIAL** | Validated for A1 (off-path/scanner) on loopback **only for probes not using the server-CID prefix**: the probes above got zero response, with a control showing quinn would answer. Even a pure off-path prober who uses the public `SYNSRVID` prefix gets a stateless reset back (recorded: 1 response, 341-1176 B across runs). PARTIAL also because Retry, GRO, A2, `ignore()` gating and closed-CID reset are untested (below) |
| stateless-reset suppression for unknown/closed CIDs (§3.4 spike item 2) | **NOT RUN** (source-only) | quinn-proto 0.11.19 `Endpoint::handle_datagram` checks CID routing first; on routing failure, for a non-Initial short-header packet, `src/endpoint.rs:259-263` calls `self.local_cid_generator.validate(dst_cid)` and drops the packet **without** a stateless reset if `validate()` returns `Err` — so a CID generator whose `validate()` rejects unknown/retired CIDs could suppress resets with **no quinn patch**. But `SynthCidGen` keeps the trait default (accept-all, `src/cid_generator.rs:23` `Ok(())`), so this was NOT exercised by any test |
| replay-cache hypothesis | **PARTIAL** (as stated: INVALIDATED; weaker form: VALIDATED) | "breaks every PQ handshake" is false: a clean handshake completes. The rule does make the handshake fail whenever the client must retransmit under the token DCID (demonstrated), and the `Binding` fix handles it |

## Missing / unsupported tests

- **Retry path** (`Incoming::retry()`; second DCID = Retry SCID; `orig_dst_cid` after Retry): not run. Caveat for the RFC
  below (product-level, UNVERIFIED — source-only, the Retry path was never run in this spike): once Retry is enabled, "the
  edge accept loop MUST call `Incoming::ignore()`" is **insufficient** for darkness. quinn-proto 0.11.19 `handle_first_packet`
  (`src/endpoint.rs:512-525`) responds with CONNECTION_CLOSE(INVALID_TOKEN) via `initial_close` (`src/endpoint.rs:875`) when
  `IncomingToken::from_header` fails — **before** any `Incoming` exists, so no accept-loop gating can suppress it.
- **Stateless reset of a closed real CID**: only a *never-issued* prefix-valid unknown CID was tried. quinn-side
  `ConnectionIdGenerator::validate()` is not exercised (`SynthCidGen` keeps the default accept-all), so "unknown CID fails
  `validate()` and gets no reset" is **not** verified. Source: quinn-proto-0.11.19 `src/endpoint.rs:259-263` drops a short
  header without a reset only if `local_cid_generator.validate()` fails; the trait default (`src/cid_generator.rs:23`) is
  `Ok(())`. A production edge needs a MAC-checking `validate()` for this suppression to apply. Suppressing resets for closed
  CIDs (§3.4 spike item 2) is not verified either: that case (unknown CID that still passes `validate()`) has no switch in
  quinn 0.11.19, only `min_reset_interval`.
- **GRO batches**: the stride-split/compaction code path was written but no test forces a multi-segment batch. Whether GRO was
  active on this loopback was not checked. Unverified.
- **`FilterSocket::poll_recv` self-wake branch**: the `wake_by_ref()` + `Poll::Pending` path after 64 all-dropped
  iterations was never reached in any test run; whether it is reachable at all on this loopback setup is unknown.
- **A2 server-CID copy into a fresh Initial**: not run. `Incoming::ignore()` gating is coded in the accept loop but never
  triggered by any test (no non-token `Incoming` ever arrived).
- **Junk-flood robustness** beyond 100 datagrams; amplification limits; behaviour under real loss patterns; IPv6; multiple
  concurrent clients sharing one token.
- **Coalesced packets**: only the first packet's DCID is inspected.
- Real MAC'd tokens, `ts`/`nonce` window, `K_spa` epochs, `edge_id` binding: out of scope by design.
- X25519MLKEM768 group read back from the quinn connection API (no stable API exists); proven by construction instead via
  `mlkem_only_client_completes_handshake_through_filter` (client offers only that group; handshake completes).

## Design consequences

1. The client-side pieces of §3.4 (choosing the Initial DCID, and the prefilter plumbing demonstrated here) are feasible
   with released quinn and no patch. The §3.4 mechanism as a whole remains **PARTIAL/unverified** (Retry,
   `validate()`-based reset suppression, closed-CID behaviour, A2) and may still require quinn work or design changes.
2. A PQ ClientHello is ~1458 bytes and *this* one takes **2 client Initials** (both with the token DCID) at 1200 B
   MTU/padding — not a universal constant, but enough that any filter treating a token as single-use is fragile.
3. Retransmissions use the token DCID until the client receives the server's first Initial or Retry packet (RFC 9000
   §7.2: the client switches DCID on the first received Initial or Retry, not on any server packet), so the filter must
   tolerate repeats from the same client.
4. A first-sighting binding has a DoS hole the spike does not test: an on-path attacker who copies a token and sends it from
   another address first would bind it and starve the real client. Binding per token to a single address is therefore too
   weak against A2.
5. Quinn exposes no stable API for the negotiated key-exchange group. The cross-review referenced a cfg-gated internal
   rustls `__rustls-post-quantum-test` field; no such field exists in pinned rustls 0.23.46 (crate source grepped), and
   internal rustls test hooks would not be a stable API or reachable through quinn anyway. The proof route used instead:
   restrict the client's `CryptoProvider.kx_groups` to X25519MLKEM768 only and complete a real quinn handshake
   (`mlkem_only_client_completes_handshake_through_filter`).

DESIGN.md §3.4 currently says: *"The edge keeps a replay cache of `(ts, nonce)` for a ±90 s window. Exact replays are dropped."*
and the filter table accepts an Initial if *"DCID is a valid SPA token, or a valid server-issued CID"*. The first sentence
contradicts RFC 9000 §7.2 retransmission behaviour (demonstrated above: lost server reply => handshake never completes).

### PROPOSED RFC text (NOT approved; for zoopa-architect, replaces the replay-cache sentence in §3.4)

> **Token reuse.** A valid SPA token is *not* single-use. Within its ±90 s validity window the edge keeps, per token, a small
> table of at most K=4 distinct source addresses; each address may present the token on at most N=16 Initial datagrams. The
> first sighting from an address creates its entry. Datagrams beyond these limits, or Initials shorter than 1200 bytes, or
> non-Initial packets carrying a token DCID, are dropped without response. Source address is used only to bound reuse; it
> is never an authenticator (CGNAT and rebinding are expected to cost extra entries, not failures). This bounds replay
> cost; it does not make darkness hold against an observer who can copy a server CID (see below).

> **Darkness claim.** Darkness (zero response, no quinn parsing) holds against off-path scanners and A1. Against an on-path
> observer (A2), server CIDs are visible, so such an observer can reach quinn's Initial decoding. The edge accept loop MUST
> call `Incoming::ignore()` (never `refuse()`) unless `orig_dst_cid()` verifies as an SPA token. Note that this gating does
> not cover quinn's pre-`Incoming` responses (source-only, never run in this spike, except where marked): with Retry
> enabled, `handle_first_packet` (`src/endpoint.rs:512-525`) sends CONNECTION_CLOSE(INVALID_TOKEN) via `initial_close`
> (`src/endpoint.rs:875`) when `IncomingToken::from_header` fails, before any `Incoming` exists, so no accept-loop gating
> can suppress it. Further pre-`Incoming` leaks: dropping an `Incoming` without calling `ignore()` triggers `refuse()`,
> which sends CONNECTION_CLOSE; closing the endpoint makes it refuse new `Incoming`s; with no server config an Initial
> elicits a stateless reset (`endpoint.rs:445-449`); and an Initial with a DCID shorter than 8 bytes gets
> CONNECTION_CLOSE(PROTOCOL_VIOLATION) from `early_validate_first_packet` (`endpoint.rs:706-723`) — this last one
> demonstrated by the new control probe above.

Both paragraphs are PROPOSED only; the K and N values are placeholders from this spike, not measured.
