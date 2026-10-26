# Amendment to DESIGN.md: self-host edition (v0.2)

> Status: approved scope direction (owner, 2026-10-25); amends `docs/DESIGN.md` v0.1.
> Cuts live in `docs/BACKLOG.md`. Authored by Claude (design authority), reviewed by chrono.
> Owner update 2026-10-25: client scope is **Linux only** — Windows and macOS moved to BACKLOG #11/#12. Owner backlog addition: DNS domain blocklists (HaGeZi-style) as BACKLOG #13, gated on an RFC narrowing the §1.4 SWG non-goal.

## Header and §0

- **Header Status:** "Draft v0.2, self-host edition. Scope cuts recorded in `docs/BACKLOG.md`."
- **§0, Identity keys row:** keep P-256. Change the reason to "supported by TPM 2.0 and every platform keystore we might target". The mobile rationale now applies only to the backlog, but the choice stays correct.
- **§0, add row:** *Product shape*: "Self-hosted only. No vendor accounts and no project-run services in the release or runtime path. Cut scope lives in `docs/BACKLOG.md`."

## §1.2: Revised v1.0 bar

Retitle the section to **"What v1.0 must do"**. The ZPA comparison stays in §1.3 as a mapping, not as the release claim. Replace the 14-item list with:

1. **Brokered, inside-out connectivity.** *(unchanged)*
2. **Dark edges.** *(unchanged)*
3. **Identity-centric policy.** One or more **OIDC** IdPs, with groups and attributes taken from ID-token/userinfo claims (JIT). Deprovisioning works through admin disable and the periodic IdP re-check (§4.2). Ordered allow/deny rules over users, groups, attributes, segments, posture, client type, network location and time. Timeout and re-auth policies.
4. **App segments and connector groups with LB and failover.** *(unchanged)*
5. **Client** for Linux (GA; Windows and macOS are BACKLOG #11/#12). **Ordered edge failover** (primary + standby, plus private-edge preference), transparent roaming, TCP fallback. Distributed unsigned, with published checksums and provenance.
6. **Double encryption, on by default.** *(unchanged)*
7. **Device posture v1** (§4.3 facts, including EDR *process presence*). **Device certificates are required by default.** Device keys are hardware-bound where the platform allows it without vendor signing (TPM 2.0 on Linux). Elsewhere a software key is used and flagged in posture.
8. **App discovery.** *(unchanged)*
9. **Browser access.** *(unchanged)*
10. **Privileged remote access (SSH only):** SSH in the browser, credential injection via a built-in **SSH user CA**, and session recording.
11. **Log streaming** (syslog, HTTP/HEC, OTLP; OCSF-aligned) and built-in dashboards. *(unchanged)*
12. **Automation:** a stable, versioned REST API (OpenAPI 3.1), `zoopactl`, and a Helm chart for control, gateway, edge and connectors.
13. **Operations:** HA control plane, primary/standby edges, private edges, zero-downtime data-plane upgrades, signed connector auto-update.
14. **Verifiability** (replaces the third-party assessment):
    - a public ZTP/SPA specification with a public review record (findings tracked as issues);
    - artifacts signed with the project release key and carrying SLSA provenance and SBOM;
    - **bit-reproducible Linux binaries and container images**;
    - the README states plainly: **"not independently audited."**

## §1.4 Non-goals: additions

- **Vendor-account dependencies** (app stores, notarisation, paid signing) are not allowed in the release path. Signing is something a deploying organisation can add with its own certificate; we document re-signing.
- **Clientless RDP** is not a 1.0 goal. RDP through `zoopa-client` to a TCP/3389 segment is supported.

## §2 Architecture

- **§2.1 diagram:** remove "SCIM server" and "RDP (WASM)", and change `/scim` on the public listener to `/login, /enroll`.
- **§2.2 Control plane:** replace "OIDC RP and SAML SP" with "OIDC RP". Delete the SCIM bullet. Add: "SSH user CA (signs short-lived certs for PRA)."
- **§2.2 Client shells:** "Linux: Tauri v2 tray UI over the privileged daemon." Delete Windows/macOS/iOS/Android/uniffi mentions; those platforms are BACKLOG #11/#12/#3.
- **§2.2 Gateway:** the PRA portal is "SSH through russh to xterm.js". Delete RDP.
- **§2.4 table:** the control `public` row becomes "Login and enrollment only". The public attack surface shrinks.

## §3 Wire protocol & crypto

- **§3.3 device leaf:** key location becomes "TPM 2.0 (Linux); software key elsewhere, flagged `hw_key=false`". Delete "plus a platform attestation where available, phase 3" and the Android/`ASWebAuthenticationSession` mentions.
- **§3.6:** the `openssl` ban in cargo-deny becomes **absolute** (there is no longer an xmlsec exception). The FIPS bullet becomes "FIPS: backlog. aws-lc-rs keeps the option open."

## §4 Identity & policy

- **§4.1:** delete the SAML bullet. Keep one line: "IdPs without OIDC: use a self-hosted Keycloak or Dex bridge (documented)." Multiple IdPs stay (OIDC only).
- **§4.2:** rename to **"User and group lifecycle (no SCIM)"** and replace the section with:
  - **JIT:** users and groups are upserted from claims at every login and token refresh.
  - **IdP re-check:** the control plane keeps the IdP refresh token server-side (endpoints still never see it). It runs a refresh grant every `idp_recheck_interval` (default 15 min, aligned with access-token refresh).
    - If the grant fails, or the user is disabled, the session goes into the revocation set.
    - Changed group claims trigger `TokenRefreshRequired`.
  - **IdP unreachable:** existing sessions continue until `reauth_by`. This is the same static-stability stance as §2.3, and it is configurable to fail closed.
  - **Admin disable** (UI/API) revokes immediately.
  - **Unseen groups:** rule editors accept group identifiers that haven't been seen yet, as raw claim values, with a warning. Otherwise a policy can't be written before the first member logs in.
  - **Entra group overage:** documented. Use "groups assigned to the application" or app roles. Graph pull is in the backlog.
- **§4.3:** replace the "Phase 3" bullet with "Attestation and EDR APIs: backlog." The honest-limit line stays and now applies to every platform.
- **§4.4:**
  - The `Credential` entity becomes `SshPrincipalMapping` (user/group → target principal).
  - `PraRule` keeps "credential injection on/off" and adds a mode, `inject_ca | user_supplied`.
  - The `mobile` client-type value stays reserved in the schema.

## §5 Crates and layout

- **Remove:** `zoopa-scim`, `zoopa-operator`, the `ironrdp` and `samael` dependencies, `clients/windows`, `clients/apple`, `clients/android`, and the Terraform repo note.
- **`zoopa-pra`:** becomes "SSH proxying, SSH-CA injection, asciicast recording" (russh).
- **§5.1:** drop the mobile runtime note. `zoopa-client-core` stays free of platform assumptions; this is cheap insurance for backlog #3.

## §6 Hygiene

- **§6.2 fuzz targets:** remove the SCIM filter/PATCH and SAML targets. Add an SSH-CA cert template target.
- **§6.3 Releases:**
  - Replace "cosign keyless" with **"cosign with a project release key"**. This fixes an existing conflict with §10.5 ("pinned release key"), and it means air-gapped connectors can verify updates offline, with no dependency on Sigstore being reachable.
  - Change "reproducible builds as a tracked goal" to "reproducible Linux binaries and images: required for 1.0." (MSI/pkg packaging left 1.0 with BACKLOG #11/#12.)
  - Delete "An external audit is required before 1.0." Replace it with "Public spec review; the README carries the not-audited statement until an audit is funded (BACKLOG #9)."

## §7 Data plane

- **§7.1:** "connectors reach every pool edge" is now the permanent design, not a limit to be lifted. With 2 edges per pool it costs nothing.
- **§7.5:** replace the geo/RTT race with: "The signed steering config lists edges **in priority order** per pool (normally primary, standby). The client connects to the first one reachable. On failure it moves to the next after a 2 s head start. It returns to the primary on the next re-probe (network change, or every 30 min)." `prefer_private_edge` forwarding still puts a private edge first. Happy-eyeballs and roaming are unchanged. Edge coordinates and regions are removed from the steering config.
- **§7.8:** the drain and crash behaviour is unchanged, with `alternates` taken from the priority list. Delete the multi-node PoP / QUIC-LB bullet (backlog #8).
- **§7.10:**
  - Delete the mobile rows (the mobile throughput cell and the "mobile idle" row).
  - The revocation row becomes: "admin disable or failed IdP re-check → flows torn down: p99 < 10 s after detection. Detection ≤ `idp_recheck_interval`."

## §8 Roadmap (re-numbered 0–3)

**Phase 0: "Proof of tunnel" (MVP).** Unchanged. It was already OIDC-only with JIT groups.

**Phase 1: "Small team can run it" (alpha)**
- Features:
  - TCP/443 h2 fallback, proxy support;
  - UDP flows;
  - **primary/standby edge failover and drain**. *Simpler: no geo racing and no edge registry.*
  - connector groups with LB, failover and health checks;
  - control relay through edges;
  - **OIDC JIT lifecycle + IdP re-check + admin disable**. *Simpler: no SCIM conformance suite and no recorded Okta/Entra traffic.*
  - timeout/re-auth policies;
  - posture v1;
  - admin UI v1;
  - Log Receivers v1;
  - Helm chart (connector as StatefulSet with persisted identity);
  - deb/rpm packages.
  - *Simpler: no desktop clients beyond Linux (Windows/macOS are BACKLOG #11/#12) — the Wintun and utun spikes are gone from the critical path.*
- **Exit criteria:**
  - 30 days of dogfooding on the project's own infrastructure;
  - chaos suite passes the §2.3 invariants;
  - version-skew tests green;
  - ZTP/SPA spec published with an open review call, and every submitted finding triaged;
  - revocation-on-IdP-disable e2e test green against a fake IdP in `zoopa-testkit`.

**Phase 2: "Clientless" (beta)**
- Features:
  - browser access (ACME, custom domains, delegated tokens);
  - multiple OIDC IdPs;
  - app discovery;
  - private edges and forwarding rules;
  - continuous re-evaluation;
  - dashboards;
  - admin roles super-admin / read-only, plus API service accounts;
  - audit-log streaming;
  - signed connector auto-update (A/B with rollback);
  - **PRA SSH, moved here from phase 3**: russh, xterm.js, SSH-CA injection, `user_supplied` mode, admin-pinned host keys, asciicast v2 recordings (filesystem by default, S3-compatible optional, per-recording DEK under the existing KEK).
  - *Simpler: SAML, Terraform, the operator, mobile alpha and tiered RBAC are gone, which frees the capacity for PRA SSH.*
- **Exit criteria:**
  - a documented zero-data-plane-downtime upgrade from the previous minor;
  - the project's own SSH access goes through PRA, with recordings, for 30 days;
  - cookie-isolation and header-rewrite tests for browser access green;
  - a public beta announced and its issue intake triaged.

**Phase 3: "1.0"**
- Features:
  - device certificates required by default; hardware-key enforcement available where TPM exists;
  - PKCS#11 for the intermediate CA (file KEK stays the default);
  - §7.10 targets met;
  - API v1, ZTP/1 and the event schema v1 frozen;
  - reproducible Linux builds.
  - *Simpler: no RDP stack, no vault, no attestation, no mobile GA.*
- **Exit criteria:**
  - every §1.2 item demonstrably works;
  - upgrade, backup/restore and DR runbooks tested, including a KEK-loss drill;
  - SECURITY.md process exercised (tabletop);
  - all spec-review findings rated high or above fixed;
  - the not-audited statement published.
- **Highest-risk item:** with only a Linux client, no client-platform item remains on the critical path. The phase-0 protocol spikes (quinn DCID control, smoltcp throughput) stay the project's top technical risk; at phase 3 the watch item is meeting the §7.10 performance targets.

**Post-1.0:** see `docs/BACKLOG.md`.

## §9 Threat model

- **Admin takeover row:** "RBAC (super-admin / read-only). Audit log streamed off-box in real time. **The off-box receiver is the integrity anchor.** Hash-chaining is in the backlog." Operators who skip streaming get no tamper evidence, so the docs must say so.
- **Delete:** the SCIM bearer-token and SAML XSW rows.
- **Add:**
  - "Disabled IdP user keeps access until the next re-check (≤ 15 min default) unless an admin disables them in openzoopa."
  - "Gateway SSH CA key compromise lets an attacker mint certs for any mapped principal. Mitigations: short lifetimes (5 min), principals restricted per `SshPrincipalMapping`, key under the KEK, CA rotation runbook."
- **Gateway assets:** replace "vaulted credentials" with "SSH CA key".
- **Supply chain:** add "Unsigned clients: users verify checksums and provenance. Orgs may re-sign."

## §10 Deployment & operations

- **§10.1:** the connector ships as a static binary, deb/rpm, container image and Helm chart (the operator is removed).
- **§10.2 Kubernetes:** "Connectors via the Helm chart as a StatefulSet (identity key on a small PVC)." Standard topology: "a primary and a standby edge, plus private edges on-prem".
- **§10.5 Clients:** distribution through the operator's own deb/rpm repos (Linux is the only client platform; Windows/macOS tooling returns with BACKLOG #11/#12). Delete app stores and the notarised pkg. Minimum-version enforcement through the `client_version` posture fact matters more now, because there is no store auto-update.
- **§10.6:** delete "recordings… lifecycle"? No: keep it. Add the SSH CA key to the KEK-protected set.
- **§10.7 sizing:**
  - ≤ 500 users: 1 edge (+1 standby).
  - ≤ 10k users: a primary/standby pair, 8–16 vCPU each, plus a private edge per large site.
  - > 10k users: beyond 1.0 scope (backlog #8).

## §11 Decisions: updated

| # | Status |
|---|---|
| 1 Licensing | **Resolved** (owner, 2026-10-26): adopt DESIGN §5.4's split — AGPL-3.0-only server roles/crates, Apache-2.0 endpoint/protocol/library code, DCO, no CLA. See `LICENSING.md` |
| 2 Name/trademark | **Open.** The repo is already public; get a legal sanity check before releases or broader promotion |
| 3 1.0 scope (mobile, RDP) | **Resolved by cut** (BACKLOG #3, #5) |
| 4 SAML library risk | **Resolved by cut** (BACKLOG #1). The xmlsec C dependency is gone and the openssl ban is now absolute |
| 5 Postgres-only | **Confirmed** by this amendment |
| 6 Admin UI TS/React | **Open**, unchanged |
| 7 Double encryption default on | **Open**, unchanged |
| 8 Distribution accounts | **Resolved by cut** (BACKLOG #9). Remaining consequence: see new #10 |
| 9 Phase-0 spikes | **Open**, unchanged |
| **10** macOS client shape | **Resolved by cut** (owner, 2026-10-25): macOS is BACKLOG #12, so the utun-vs-NE question is moot until it returns |
| **11 (new)** IdP re-check on IdP outage | Accept "fail open until `reauth_by`" as the default, with fail-closed as an option |
| **12 (new)** Vault → SSH CA | Accept dropping the credential vault in favour of an SSH user CA plus `user_supplied` mode |
| **13 (new)** Client scope | **Resolved** (owner, 2026-10-25): Linux only for 1.0; Windows is BACKLOG #11, macOS #12, mobile #3 |

## Knock-on effects (checked, decision + reason)

1. **§4 identity without SCIM/SAML.** It changes. Revocation needs the IdP re-check because, without SCIM, a user disabled at the IdP would otherwise keep silent refresh until `reauth_by`, which can be hours.
2. **Groups from claims only.** It changes. Two additions: (a) unseen-group rule authoring, because the groups table fills lazily; (b) Entra overage documentation, because tokens carry at most ~200 groups.
3. **§1.2 item 5 wording.** It changes. Mobile goes, and "nearest-edge selection" becomes "ordered edge failover", or the bar would promise cut features.
4. **Apple account cut hits macOS, not just iOS.** *Superseded (owner, 2026-10-25): the whole macOS client is BACKLOG #12, so there is no utun-vs-NE choice to make until it returns.*
5. **Windows unsigned.** *Superseded (owner, 2026-10-25): the Windows client is BACKLOG #11. The re-signing documentation note applies when it returns.*
6. **SSH-only PRA and the vault.** The vault is no longer justified. SSH certificates remove stored secrets entirely, and `user_supplied` covers appliances. The gateway role is still justified by browser access (phase 2).
7. **When PRA SSH lands.** It moves earlier, to phase 2. It reuses the gateway, delegated tokens and the KEK, all built in phase 2, and phase 3 has nothing else it depends on.
8. **§7 edge discovery without nearest-edge.** No DNS-based discovery. The edge list stays in the signed steering config, because DNS answers are unsigned and edge identity is verified via SPIFFE anyway. Operators may still use DNS names in the list to re-home IPs during DR (as §10.6 already says).
9. **Removing hash-chaining.** Acceptable only because off-box streaming exists. The docs must make streaming the recommended default.
10. **cosign keyless vs. pinned key.** It changes: use a project key. "Verifiable builds" and air-gapped auto-update both need offline verification, and §6.3 and §10.5 contradicted each other.
11. **Helm instead of the operator.** It changes. The connector needs a persisted identity (StatefulSet + PVC). A pod restart must not re-enroll on a consumed provisioning key.
12. **Domain blocklists vs the SWG non-goal.** Owner-requested (BACKLOG #13). It collides with the §1.4 "Secure Web Gateway / URL filtering: permanent non-goal" line, so it cannot be built until an RFC narrows that non-goal to exclude DNS-name blocking from user-supplied feeds. Kept out of 1.0 either way.

## What self-hosting still makes hard (state this in `docs/ops/`)

- **TLS lifecycle:**
  - The gateway needs public certificates per app origin. Wildcards mean DNS-01 credentials live on an internet-facing gateway.
  - The offline-root ceremony and yearly intermediate rotation are the operator's job.
  - **Static stability is bounded by leaf lifetime.** Infra leafs are 24 h and renew at 50%, so a control-plane outage longer than about 12–24 h becomes a data-plane outage. Alert on cert seconds-to-expiry.
- **Upgrades:** skew policy is N-1 minor on an 8-week cadence, so operators must upgrade roughly every 16 weeks or do stepwise upgrades. The Linux client has no store auto-update; rollout is the operator's deb/rpm repo job.
- **Backup/KEK:** Postgres PITR is useless without the separately backed-up KEK. Losing the KEK means a new intermediate and re-enrolling every device, connector and edge. The SSH CA and recordings depend on the same KEK.
- **IdP availability:** new logins, enrollments and re-auth fail closed while the IdP is down. Break-glass WebAuthn admins are mandatory, not optional.
- **Postgres HA** (Patroni/CNPG) is real operational skill. The all-in-one compose is single-node.
- **Internet-facing edges and gateway:** patching cadence, DDoS and abuse handling are on the operator. There is no vendor PoP to hide behind.
- **Assurance:** with no third-party audit, the operator is trusting public spec review plus reproducible builds, and should treat the project accordingly.

Skipped/Not checked: §3.1–3.2, §3.4–3.5, §3.7, §6.1–6.2 and §9.1–9.2 were only grepped for cut-related terms, not re-read closely; the blocklist RFC (BACKLOG #13) does not exist yet.
Risk: Linux-only clients narrow who can dogfood phase 1; if chrono's own endpoints include Windows/macOS, BACKLOG #11/#12 will need to come back before the 30-day dogfood exit criterion is meaningful.
