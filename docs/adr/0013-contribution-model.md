# ADR-0013: Contribution model

Status: Accepted (owner, 2026-11-01).

This is number 0013 because [DESIGN.md §6.4](../DESIGN.md#64-governance-and-contribution) reserves ADR-0001 to 0012 for the §0 seeds.

## Context

The project has one maintainer and is in phase 0. DESIGN [§5.3](../DESIGN.md#53-dependency-selection-rules), [§5.4](../DESIGN.md#54-licensing), [§6.3](../DESIGN.md#63-security-posture) and §6.4 already fix DCO (§5.4, §6.4), two-maintainer review of sensitive paths and BDFL governance. The model is adapted from nissifield/snes2DHD (same author).

## Decision

- **Task cards.** Types are `docs`, `code` and `test`. A card is trusted only if its author is listed in [MAINTAINERS.md](../../MAINTAINERS.md), read from the base branch. Only `card:ready` cards count.
- **`checks` gate (forthcoming).** A required `checks` job on `pull_request_target` reads the PR as data. It never checks the PR out and never runs cargo or rustup.
- **DCO.** Checked on every commit by the gate. The rules are in [CONTRIBUTING.md](../../CONTRIBUTING.md#developer-certificate-of-origin-dco).
- **AI disclosure.** `Assisted-by: <tool> <model>` is policy, not machine-checked.
- **Reviewer agents.** Advisory only. The agent has no credentials and no tools; the runner posts its output as a comment review.
- **Protected paths.** [.github/CODEOWNERS](../../.github/CODEOWNERS) lists them. Binary files and added `unsafe` are also protected and are held by the gate.
- **Squash message.** Stays `COMMIT_MESSAGES`, so sign-offs reach `main`.
- **Auto-merge.** Off for phase 0. It is turned on only when MAINTAINERS.md lists 2 or more humans and the DESIGN [§8](../DESIGN.md#8-feature-roadmap) phase-0 exit criteria pass in CI. Even then:
  - docs only, as a fail-closed allowlist: `docs/**` only, excluding DESIGN, `design-*`, BACKLOG, rfcs, adr, the threat model, the phase-0 verdicts and research, and refusing any diff that adds or changes a URL or email address;
  - code never auto-merges until an ADR revisits it;
  - §6.3 paths always need two humans, and an agent approval never counts.
- **Branch protection on `main`.** Phase 0: required `checks`, review count 0, code-owner reviews off, `enforce_admins=false`, linear history, no force-push, no deletion. When MAINTAINERS.md lists two humans, flip to 1 approval, code-owner reviews and last-push approval.
- **Two-human rule.** Branch protection cannot require two approvals per path. The forthcoming gate must enforce the §6.3 two-human rule (two approvals on the head SHA from distinct maintainers); until then the maintainer applies it by hand. Whether the PR author counts as one of the two is open.

### Owner decisions, 2026-11-01

- Security reporting uses GitHub private vulnerability reporting only. DESIGN §6.3's 72 h acknowledgement and `security@` mailbox are replaced by a 7-day best-effort acknowledgement. The 90-day disclosure target stays. See [SECURITY.md](../../SECURITY.md).
- The Code of Conduct contact is a placeholder until a dedicated alias exists.
- The README first line drops "Zscaler Private Access". DESIGN §1.3 is untouched.
- Ponytail provenance is upstream commit `09c434a`, approximate ([SOURCE](../../third_party/ponytail/SOURCE)).
- GOVERNANCE.md is deferred until there are 3 or more maintainers. BDFL is recorded in MAINTAINERS.md.

### Threat-model delta

Input to the owner's DESIGN [§9](../DESIGN.md#9-threat-model-stride-lite) review. New attack surface: the contribution pipeline. Actor: a fork author or commenter (A8, supply chain).

Planned mitigations: most take effect with the P2 gate and settings. Until then the control is the maintainer's manual merge.

| Threat | Mitigation |
|---|---|
| Code execution via `pull_request_target` | PR never checked out; values via `env:`; no cargo, rustup, caches, artifacts or `workflow_run`; read-only token; no repository secrets |
| Another job named `checks` spoofs the required check | `.github/` is protected; outside workflow runs need approval; verify the check origin before any auto-merge; never approve workflow runs on outside PRs that touch `.github/` |
| Prompt injection makes a reviewer agent approve a subtle auth bypass inside the allowlist | Advisory only; two humans on §6.3 paths; PR text tagged untrusted |
| PR body edited after review | `COMMIT_MESSAGES` squash; auto-merge off |
| The rules rewritten by a PR (CODEOWNERS, MAINTAINERS.md, gate code) | Protected paths; the gate runs the base-branch copy |
| Maintainer's machine runs PR code (`build.rs`, proc-macros, tests, nested `.cargo` or agent config) | Never build, test or point a tool-using agent at an unmerged outside branch on the maintainer machine; review with the no-tools agent |
| Commits pushed after review, before the merge click | Merge with `--match-head-commit <reviewed-sha>`; last-push approval after the flip |
| Forged maintainer identity | Maintainer status comes from the PR author (`pull_request.user`), never from commit or sign-off emails, which are self-asserted; re-registration of a renamed login is a residual risk (consider numeric IDs in P2) |
| Maintainer account takeover | 2FA with passkey and recovery codes, secret scanning; residual risk accepted |
| DCO is an attestation, not authentication | Residual risk accepted |

## Consequences

The two-maintainer rule cannot be met for §6.3 paths until a second human maintainer exists, so outside code work stays narrow.

## Deferred, with triggers

- PM agent: more than about 5 cards a week.
- Claim bot: two contributors collide. Fix first: no @-ping, expiring claims, one PR listing per run, `python3 -I`.
- PR-title lint: the first release.
- Fuzz-harness cards: phase 1.
