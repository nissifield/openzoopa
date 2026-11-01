# openzoopa

A self-hosted Zero Trust Network Access (ZTNA) platform, written in Rust.

**Phase 0: design and feasibility spikes.** No runnable software, no release. **Not independently audited.** Do not deploy.

Start with [docs/DESIGN.md](docs/DESIGN.md), [docs/design-v0.2-self-host-amendment.md](docs/design-v0.2-self-host-amendment.md), [docs/phase0-spike-001-verdict.md](docs/phase0-spike-001-verdict.md) and [docs/phase0-spike-002-verdict.md](docs/phase0-spike-002-verdict.md).

## Contribute

Most phase-0 work is security-sensitive and done by the maintainer. Outside work starts from a task card ([the card flow](CONTRIBUTING.md#the-card-flow)).

1. Pick an open, unassigned `card:ready` issue and ask for it.
2. Give the starter prompt, [AGENTS.md](AGENTS.md) and the card's Prompt to your AI tool, or do it by hand.
3. Open a PR with `Closes #N`, the Done-when output and signed-off commits. Disclose AI help with `Assisted-by:`.

Crypto, wire-protocol and RFC work is not offered as cards. See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities through [SECURITY.md](SECURITY.md). Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licensing

openzoopa uses a split license: server-side roles/crates are AGPL-3.0-only, while client, connector, protocol, library, and CLI code is Apache-2.0. Contributions use the DCO; see [LICENSING.md](LICENSING.md) and [CONTRIBUTING.md](CONTRIBUTING.md).
