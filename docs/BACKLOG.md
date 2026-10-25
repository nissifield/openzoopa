# Backlog

Cut from the 1.0 scope when openzoopa became a self-hosted project, not a
SaaS-vendor product. Nothing here is scheduled. An item comes back only
through an RFC, and only once its trigger has actually happened.
The protocol and schema stay tenant- and platform-aware, so none of
these needs a wire break later.

**Client scope for 1.0: Linux only.** Windows (#11) and macOS (#12) are
owner cuts from 2026-10-25; mobile was already #3. `zoopa-client-core`
stays free of platform assumptions so these return without a redesign.

| # | Item | Was | Pull back in when |
|---|---|---|---|
| 1 | SAML 2.0 SP (samael + xmlsec, XSW corpus) | P2 | A deployment's IdP has no OIDC and a Keycloak/Dex bridge isn't acceptable to it |
| 2 | SCIM 2.0 server (Okta/Entra PATCH + filter subset) | P1 | A deployment needs deprovisioning faster than the IdP re-check interval (§4.2), or groups that never appear in ID-token claims |
| 3 | iOS / Android clients (GA) | P2 alpha, P3 GA | Owner ruled out iOS explicitly (2026-10-25). Android returns only if a maintainer owns the platform |
| 4 | Posture v2: MDM/platform attestation, TPM quotes, EDR API plugins | P3 | A deployment needs posture to hold on rooted devices, and the attestation path needs no SaaS |
| 5 | RDP in the browser (IronRDP WASM, CredSSP injection, PDU recording) | P3 | A maintainer commits to the RDP stack. Clientless RDP is the requirement (RDP through `zoopa-client` already works as a plain TCP segment) |
| 6 | Terraform/OpenTofu provider (separate Go repo) | P2 | API v1 is frozen and someone will own the separate repo and registry |
| 7 | Kubernetes connector operator (CRDs `ConnectorGroup`, `AppSegment`) | P2 | Helm-managed connectors can't do the job (e.g. GitOps segments from annotated `Service`s) |
| 8 | Multi-edge PoP machinery: geo nearest-edge racing, edge relay mesh, on-demand connector tunnels, CID-routed (QUIC-LB) PoP load balancing | P1 / P4 | One deployment needs more than one edge region, or more than ~50 edges, or more than one edge node per PoP |
| 9 | Third-party pentest as a release gate; Apple Developer ID and Windows code-signing accounts | 1.0 gate / P1 | Funding exists (grant, sponsor). Signing also comes back if unsigned clients block adoption |
| 10a | FIPS 140-3 build variant (`--features fips`) | P4 | A deployment has a regulatory FIPS requirement |
| 10b | Admin RBAC beyond super-admin / read-only (policy-admin, helpdesk) | P2 | Several admin teams with separate duties run one deployment |
| 10c | Hash-chained audit-log entries | P2 | Off-box streaming (kept) isn't accepted as the integrity anchor, e.g. by an auditor |
| 10d | "3 external design partners" exit criterion | P2 exit | Not applicable to a self-hosted project. Replaced by dogfooding plus a public beta |
| 11 | Windows desktop client (Wintun, TPM/CNG keys, MSI/winget) | P1 | A maintainer owns Windows and users accept unsigned-MSI/SmartScreen friction (or org re-signs) |
| 12 | macOS desktop client, both variants (root `utun` daemon; Network Extension + Secure Enclave) | P1 | An Apple Developer ID is funded and a maintainer owns the platform |
| 13 | Domain blocklists (HaGeZi Pro/Pro++ style feeds) applied at the client's DNS stub, per-profile | n/a | Owner request (2026-10-25). First needs an RFC relaxing the §1.4 "Secure Web Gateway / URL filtering" permanent non-goal for DNS-name blocking only — no L7 inspection, no category engine; feeds are user-supplied URLs, cached locally |

## Cut as knock-on effects (see the DESIGN amendment, "Knock-on effects")

| Item | Was | Pull back in when |
|---|---|---|
| Static-credential vault (envelope-encrypted secrets, KMS/OpenBao Transit) | P3 | PRA targets that can trust neither an SSH CA nor typed-in credentials (e.g. automated injection into network appliances) |
| Reusable group-scoped connector enrollment token for stateless pods | n/a | Persisting connector identity in a StatefulSet PVC turns out to be impractical |

## Post-1.0 (was phase 4, unchanged)

Multi-tenant/MSP mode · workload-to-workload segmentation · JIT access
requests and approvals · PRA session sharing / live monitoring · inline
inspection for browser access · ML-DSA / hybrid certs · external CA
backends (SPIRE, OpenBao PKI) · pull directory connectors (Entra Graph,
Google, LDAP) · server-to-client flows.
Trigger for each: 1.0 has shipped, and a named user is asking for it.
