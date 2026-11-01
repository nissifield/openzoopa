# Phase 0 spike 002A verdict: MAC'd server CIDs and stateless-reset behaviour

**Status:** reviewed feasibility artifact; **not product code** and not merged into `main`.

- Tag: `spike/002-quinn-cid-reset`
- Commit: `d5133733b9514134e104fc23cbc0ffdbbd9b9602`
- Branch: `phase0/quic-cid-reset-spike`
- Full evidence table: `spikes/002-quinn-cid-reset/README.md` at the tag
- Reviews: Codex `gpt-6-astra` (first review), Claude Opus cross-review, and a focused Claude re-review of the fixes. Spike crate licensed Apache-2.0.

"Observed" below means seen on Linux loopback, on one host, with pinned `quinn 0.11.12` / `quinn-proto 0.11.19`. "Source-only" means read from the pinned Quinn source and not exercised by a test.

## What was demonstrated

1. **Shared CID validator.** A throwaway 16-byte MAC'd server CID (`kid || nonce || HMAC-SHA256 tag[0..8]`), checked by one function used by both the UDP filter and Quinn's `ConnectionIdGenerator::validate()`. Covered by unit tests: round-trip, self-generated known-answer vector, every-byte tamper, rejection by a different key instance.
2. **Short-header darkness from `validate()`.** For unrouted short-header packets whose CID fails the MAC check, `validate() == Err` makes Quinn drop the packet before it sends a stateless reset. This was observed with no userspace filter, and a control endpoint with an accept-all validator did send the reset.
3. **Long headers still need the filter.** Long-header packets never reach `validate()`. The unfiltered control endpoint answered an unsupported version with Version Negotiation and a short-DCID Initial with CONNECTION_CLOSE (observed). The Retry `INVALID_TOKEN` path is source-only.
4. **Reset oracle (recorded, not fixed).** A MAC-valid CID that is closed or was never issued gets exactly one stateless reset; that much is observed. Quinn's limiter is endpoint-wide: with a 1 s interval, two more probes got no response, and resets resumed once the interval had passed (observed). Anyone who has seen a CID can therefore tell a closed CID from a live one, assuming live CIDs stay silent (source-only). Reset tails can be linked per `reset_key`.
5. **Never-issued CID in an Initial.** An Initial carrying a never-issued, unrouted, MAC-valid DCID reached `Incoming`. Calling `ignore()` produced zero bytes over the observation window (observed). This does **not** cover live or copied CIDs, which Quinn routes before `Incoming` is created.
6. **Initial Token field.** With Retry never issued, a 64-byte garbage Initial Token was accepted and left the address unvalidated (observed). A NEW_TOKEN round trip validated the second connection from the same client endpoint (observed).
7. **Loopback silence and loss recovery.** IPv4 and IPv6 loopback probes got no response through the filter. The handshake recovered after one outgoing batch was dropped; the retransmission is inferred, not counted directly.
8. **Bounded parser checks.** A prefix and XOR sweep found no panics, 26 selected header mutations were all denied, and a positive control was accepted. This is not fuzzing.
9. **Verification.** The tagged commit passed 25/25 tests (5 unit, 20 integration), `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `git diff --check`.

## What was not demonstrated

- Product CID or SPA cryptography. `src/cid.rs` must never become production code.
- Live-CID probes: neither short headers nor Initials were sent to a live CID.
- Closing-endpoint refusal. Quinn refuses inside its driver before the application sees `Incoming`, so `ignore()` cannot prevent it (source-only).
- Retry-issued token cases; NEW_TOKEN from a different IP or port.
- Forced GRO, coalesced first flights, and mixed accept/drop batches.
- netns/veth runs, a real process restart, in-place key rotation, fuzz targets, an MSRV check, a dependency-license audit, realistic loss and load.
- Any §8 phase-0 exit criterion.

## Inputs for the §3.4 RFC

1. Keep the userspace filter for long headers. `validate()` covers only unrouted short headers.
2. Decide the reset oracle: accept the leak, add a stateful check of issued CIDs, and/or set a policy for sharing `reset_key` across edges.
3. CID key rotation needs overlapping key epochs. A filter that retires a key ID would cut off live connections that Quinn's routing would otherwise keep.
4. Product accept loops must call `ignore()` explicitly on rejection. Closing-endpoint refusal needs suppression at the filter or socket layer.
5. Do not treat the Initial Token field as an authentication channel while Retry is off.

## Decision

Archive spike 002A by tag. Do not merge the throwaway code. §3.4 remains **PARTIAL** until the RFC amendment, a second-maintainer review and owner sign-off. The next phase-0 items are the smoltcp throughput spike and the §3.4 RFC. Until the RFC is accepted, build only work that does not depend on §3.4: the policy engine, protocol/types, CA and enrollment.
