# openzoopa licensing

**Owner decision (2026-10-26):** use the split recommended in `docs/DESIGN.md` §5.4.

- Server-side roles and crates are licensed under **AGPL-3.0-only**. See `LICENSE-AGPL`.
- Client, connector, protocol, library, CLI, and other endpoint-side code is licensed under **Apache-2.0**. See `LICENSE-APACHE`.
- Contributions use the **Developer Certificate of Origin (DCO)**; there is no CLA. See `CONTRIBUTING.md`.

The boundary matters: Apache-2.0 crates must not depend on AGPL-3.0-only crates. The planned `xtask license-boundary` CI check must enforce this before product crates land.

Initial mapping from `docs/DESIGN.md` §5.2:

- AGPL-3.0-only: `zoopa-store`, `zoopa-pki`, `zoopa-idp`, `zoopa-scim`, `zoopa-control`, `zoopa-edge`, `zoopa-gateway`, `zoopa-pra`, and the `zoopa-server` binary.
- Apache-2.0: `zoopa-proto`, `zoopa-types`, `zoopa-crypto`, `zoopa-spa`, `zoopa-tunnel`, `zoopa-policy`, `zoopa-token`, `zoopa-telemetry`, `zoopa-config`, `zoopa-netstack`, `zoopa-dns`, `zoopa-posture`, `zoopa-client-core`, `zoopa-client-ffi`, `zoopa-connector`, the `zoopa-client` and `zoopactl` binaries, and UI/client-side assets unless a file header says otherwise.
- Unpublished test/build tooling (`zoopa-testkit`, `xtask`) is not a public API and should carry the license appropriate to where it is linked; it must not blur the Apache/AGPL dependency boundary.

If a future crate is not listed here, its `Cargo.toml` and file headers must state its license explicitly before it is committed.

The `openzoopa` name and trademark policy remain open owner decisions. The license decision does not clear the name for release use.
