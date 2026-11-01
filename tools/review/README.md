<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Derived from nissifield/snes2DHD (same author), relicensed Apache-2.0. -->
# tools/review: advisory review runner

`review_queue.py` runs the [`.agents/reviewer.md`](../../.agents/reviewer.md) role over open outside PRs on a maintainer's machine.

- It posts **comment reviews only**. It never approves, requests changes or merges.
- A PR is reviewed only if `checks` is green and the deterministic checks (the same ones as the `checks` gate) pass. The agent never sees a PR that fails them.
- Maintainer PRs are skipped unless you ask with `--pr N`.
- The agent command comes after `--`. The prompt is piped to it on stdin. The reply must end with a strict `VERDICT:` line, or nothing is posted.

**Dry run by default**: it prints what it would post. `--live` posts, and refuses to start unless `GH_TOKEN` is a fine-grained token (`github_pat_...`).

## Examples

    python3 -I tools/review/review_queue.py -- claude -p --tools "" --strict-mcp-config
    python3 -I tools/review/review_queue.py --live -- claude -p --tools "" --strict-mcp-config
    python3 -I tools/review/review_queue.py --pr 12 -- claude -p --tools "" --strict-mcp-config

## Credentials

- Run it from an up-to-date `main` checkout whose `origin` is github.com/nissifield/openzoopa. It reads `MAINTAINERS.md` and the role file from that checkout.
- The runner's `gh` should use a **fine-grained personal access token scoped to this repository only**, with Pull requests: read and write (comment reviews) and Contents: read (Metadata read is automatic). Pass it as `GH_TOKEN` for the run. Never use the admin token or the stored login from `gh auth login`.
- The agent subprocess gets only `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TERM`, `TMPDIR` and `ANTHROPIC_API_KEY`, plus an empty `GH_CONFIG_DIR`. No `*_TOKEN` ever passes. A Claude login stored under `HOME` is how `claude -p` authenticates.
- Use a **no-tools agent only** (Claude `-p --tools "" --strict-mcp-config`). A tool-capable agent can read credential files (`~/.config/gh`, `~/.ssh`, `~/.codex`), and a read-only sandbox does not stop reads. Run one only as a separate OS user or in a container with no readable credentials.
- Agent output is stripped of control characters, posted inside a code fence, and dropped if it looks like a credential.
- Never point a tool-using agent at an unmerged outside branch ([ADR-0013](../../docs/adr/0013-contribution-model.md)).
- Nothing is checked out or built. PR heads land in `refs/review/<n>`.
