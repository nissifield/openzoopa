# Security policy

## Report a vulnerability

Use GitHub private vulnerability reporting:
<https://github.com/nissifield/openzoopa/security/advisories/new>

Never report a vulnerability in a public issue, pull request or Discussion.

- **Acknowledgement:** within 7 days, best effort. This is one maintainer.
- **Disclosure:** we aim for coordinated disclosure within 90 days of the report.

## Supported versions

None yet. The project is in phase 0 (design and feasibility spikes) and has no releases. Spike tags and branches are not product and get no fixes.

## Scope

In scope:

- the design documents in `docs/`;
- the contribution and CI pipeline: `.github/`, the `checks` gate and advisory review runner (`tools/`, `tests/ci/`, `tests/review/`) and [MAINTAINERS.md](MAINTAINERS.md);
- the agent instruction files (`.claude/`, `AGENTS.md`, `.agents/`) and the starter prompt in [CONTRIBUTING.md](CONTRIBUTING.md).

Out of scope: bugs in upstream dependencies (for example quinn, rustls, aws-lc-rs) go to those projects, and GitHub platform bugs go to GitHub.

Conduct concerns go through [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), not here.
