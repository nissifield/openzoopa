# Phase 0 spike 001 verdict: QUIC Initial DCID prefilter

**Status:** reviewed feasibility artifact; **not product code** and not merged into `main`.

- Tag: `spike/001-quinn-dcid`
- Commit: `2d5d3a7449fef4f103ad892941e36b38582da821`
- Branch at time of tagging: `phase0/quic-dcid-spike`
- Research note carried by this docs PR: `docs/research/phase0-quic-dcid-netsec.md`

## What was demonstrated

Using pinned `quinn 0.11.12` / `quinn-proto 0.11.19` on Linux loopback:

1. A client can choose a 20-byte Initial Destination Connection ID (DCID) through released Quinn APIs, with no Quinn patch.
2. A userspace UDP prefilter can silently drop the tested unauthenticated probes while allowing a valid QUIC handshake and bidirectional echo.
3. The design's original "drop exact replays" rule is unsafe as written: after a lost ACK-only server reply, the client retransmits under the token DCID and the naive rule deadlocks the handshake. A first-sighting binding mode completed the same loss scenario.
4. A client restricted to X25519MLKEM768 completed a handshake through the filter.
5. Independent verification after review passed `13/13` tests, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `git diff --check`.

## What was not demonstrated

This spike does **not** validate the full §3.4 dark-edge mechanism or approve the product protocol. In particular:

- no real MAC'd SPA tokens or server CID construction;
- reset suppression through `ConnectionIdGenerator::validate()` remains source-only/NOT RUN;
- Retry was disabled and the Retry path remains untested;
- darkness against an on-path observer (A2) remains unverified;
- GRO/coalescing, IPv6, realistic loss, sustained load, replay budgets, and anti-amplification remain unverified;
- no §8 Phase-0 exit criterion is met.

## Decision

Archive the spike by tag and do not merge the throwaway code. The synthetic token and prefix-only CID recognizer must not be reused in product crates.

Next implementation sequence:

1. Resolve the remaining name/trademark decision before product crates or releases.
2. Run spike 002 for real CID validation, reset behavior, Retry-off behavior, A2 forged packets, GRO, IPv4/IPv6 darkness, and loss behavior.
3. Run the required smoltcp throughput spike.
4. Write the §3.4 RFC amendment from spike 002 evidence and obtain owner sign-off.
5. Build only components that do not depend on §3.4 until that RFC is accepted: policy engine, protocol/types, CA, and enrollment.
