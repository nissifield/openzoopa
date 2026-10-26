# openzoopa: Design Document

> **Status:** Draft v0.1, for owner review before any code is written
> **Target path:** `docs/DESIGN.md`
> **Date:** 2026-10-25
> **Scope:** The founding architecture, protocol, security and project-governance decisions for openzoopa, a self-hosted, open-source Zero Trust Network Access (ZTNA) platform with feature parity to Zscaler Private Access (ZPA) as the goal.

---

## 0. Decision summary

Each row is a decision. The reasoning is in the referenced section. Anything that needs the owner's sign-off is listed again in §11.

| Area | Decision | § |
|---|---|---|
| Client↔edge / connector↔edge transport | **QUIC (quinn + rustls) on UDP/443**, with fallback to **HTTP/2 over TLS 1.3 on TCP/443**. No WireGuard, no DTLS. | 3.1 |
| Traffic capture on endpoints | TUN device + **userspace TCP/UDP termination**, DNS-driven **synthetic IPs**. Flows are carried as byte streams, never as L3 packets. | 7.2 |
| Crypto library | rustls 0.23.x with the **aws-lc-rs** provider. TLS 1.3 only. **X25519MLKEM768 hybrid key exchange by default.** | 3.6 |
| Identity keys | **ECDSA P-256** everywhere, because it is the only curve that TPM 2.0, Apple Secure Enclave and Android Keystore all support. | 3.3 |
| Workload identity | SPIFFE-format X.509 SVIDs from a **built-in CA**. SPIRE is optional, never required. | 3.3 |
| Pre-auth / "dark" edges | **SPA token carried in the client-chosen QUIC Initial DCID**. The edge drops every packet that fails verification before quinn sees it. | 3.4 |
| Double encryption | Per-flow **inner TLS 1.3 between client and connector**, which the edge cannot read. **On by default**, opt-out per segment. | 3.5 |
| Enforcement | The edge is a fast-path PEP and the **connector is the authoritative PEP**. Both run the same `zoopa-policy` evaluator over the same signed inputs. | 4.5, 9 |
| Session credential | Short-lived (15 min) **ES256 JWT, certificate-bound** (`cnf`), refreshed silently over mTLS. | 3.7 |
| Control-plane store | **PostgreSQL only**, with stateless control replicas. No embedded Raft and no SQLite. | 10.4 |
| Resilience | **Static stability:** the data plane keeps running on cached, signed bundles during a control-plane outage. | 2.3 |
| Tenancy | **Single-tenant per deployment through 1.0.** The schema, PKI and SPA format are tenant-aware so multi-tenancy can be added later without breaking anything. | 2.5 |
| Licensing | **AGPL-3.0-only for server roles, Apache-2.0 for client, connector, protocol and libraries.** DCO, no CLA. | 5.4 |
| Naming | `zoopa-*` crates. Binaries: `zoopa-server` (roles: control, edge, gateway, all-in-one), `zoopa-connector`, `zoopa-client`, `zoopactl`. | 5 |

---

## 1. Vision & scope

### 1.1 Problem

Organisations that want ZPA's model have no self-hostable, open-source option that does all of it as one coherent system. The model is: apps are invisible to the network, access is per user and per app, both sides dial out, and admins get browser access, privileged access and SIEM-grade logs. Open-source tools today each cover a slice. openzoopa's goal is the whole product, built from boring and auditable components.

### 1.2 What v1.0 must do to credibly claim "ZPA alternative"

v1.0 ships only when **all** of the following work, are documented, and are covered by end-to-end tests:

1. **Brokered, inside-out connectivity.** Connectors and clients only dial out. Connectors have zero listening ports. Apps never get a route from user networks.
2. **Dark edges.** A public edge sends no response to unauthenticated UDP traffic, and on TCP it does as little as possible before authentication (see §3.4 for the honest limits).
3. **Identity-centric policy.** OIDC and SAML IdPs, SCIM 2.0 provisioning (Okta and Entra ID tested), and ordered allow/deny rules over users, groups, attributes, app segments, posture, client type, network location and time. Timeout and re-auth policies.
4. **App segments** defined by FQDN, wildcard domain or CIDR, with TCP/UDP port ranges and most-specific-match semantics. Connector groups with load balancing and failover.
5. **Clients** for Windows, macOS and Linux (GA) and iOS and Android (GA, with reduced posture). Nearest-edge selection, transparent roaming, and TCP fallback.
6. **Double encryption** that holds even if the edge is compromised (§3.5).
7. **Device posture** v2: OS, disk encryption, firewall, EDR presence, hardware-bound device keys.
8. **App discovery** from wildcard segments.
9. **Browser access** (clientless HTTP(S) apps) on public or custom domains.
10. **Privileged remote access**: SSH and RDP in the browser, with credential injection and session recording.
11. **Log streaming** (the LSS equivalent) to syslog, HTTP (Splunk-HEC-compatible) and OTLP receivers using a stable, OCSF-aligned schema. Built-in health and usage dashboards.
12. **Automation**: a stable, versioned REST API (OpenAPI 3.1), a Terraform/OpenTofu provider, and a Kubernetes operator for connectors.
13. **Operations**: HA control plane, private edges, zero-downtime data-plane upgrades, and connector auto-update with signed artifacts.
14. **A published third-party security assessment** of the protocol and implementation.

### 1.3 ZPA concept mapping

| ZPA | openzoopa | Notes |
|---|---|---|
| ZPA Public Service Edge (broker) | **Edge** (`zoopa-server role=edge`) | Self-hosted PoPs. |
| ZPA Private Service Edge | **Private Edge** (same binary, `edge.kind=private`) | Deployed on-prem to avoid hairpinning. |
| App Connector / App Connector Group | **Connector / Connector Group** | |
| Server Group | *(dropped)* | Segments bind directly to connector groups. ZPA's server-group layer exists mostly as a toggle for dynamic discovery, which we make a segment option instead. |
| Application Segment / Segment Group | **App Segment / Segment Group** | |
| Access / Timeout / Client Forwarding Policy | **Access / Timeout / Forwarding rules** | Ordered, first match wins. |
| Client Connector (Z App) | **zoopa-client** | |
| Browser Access | **Gateway: Browser Access** | |
| Privileged Remote Access | **Gateway: PRA** | |
| LSS | **Log Receivers** | |
| Double Encryption | **Inner TLS** (default on) | ZPA defaults this to off. We default to on because it is what makes connector-side enforcement meaningful. |

### 1.4 Explicit non-goals

These are out of scope for 1.0. Some are permanent:

- **Secure Web Gateway / ZIA functions:** internet traffic inspection, URL filtering, CASB, DLP. Permanent non-goal for this repo.
- **L3 "network extension" / full-tunnel VPN mode.** Permanent. Its absence is the product.
- **Peer-to-peer client↔connector paths** (ICE/hole punching). Every flow goes through an edge, because the edge is the logging and enforcement chokepoint. Private edges solve the latency problem instead (§7.9).
- **Server-initiated flows to clients** (SCCM push, VoIP callbacks) and protocols that embed IPs (active FTP, SIP). Possible post-1.0 work.
- **Multi-user endpoints** (RDS / terminal servers with many users behind one client).
- **HTML/JS body rewriting** in browser access. We rewrite `Host`, `Location` and cookie scoping only (§4.8).
- **A managed SaaS offering** run by the project. Nothing in the product may depend on a project-operated service.
- **MDM functionality.** We consume MDM signals but do not manage devices.
- **Windows kernel drivers of our own.** We use Wintun, which is signed and redistributable.
- **Volumetric DDoS protection.** That belongs upstream.

### 1.5 Prior art and why this is a new project

- **OpenZiti** (Go, Apache-2.0): the closest in spirit (overlay plus edge routers), but SDK-first, with its own concepts and its own identity model. Its target users are app developers who embed ZT, not ZPA administrators.
- **Firezone** (Rust connlib, Apache-2.0) and **NetBird / Headscale / Tailscale**: WireGuard plus ICE peer-to-peer designs with per-resource policy. Their data path is L3 and peer-to-peer by design, which conflicts with brokering, double encryption and edge enforcement as described here.
- **Pomerium:** an excellent identity-aware HTTP proxy. It does not cover arbitrary TCP/UDP client capture with connectors.
- **Teleport / Warpgate:** infrastructure access (SSH, DB, Kubernetes) and bastions. Warpgate (Rust, russh) is a useful reference for our PRA recorder.

openzoopa differs on purpose: it uses ZPA's operator model (segments, connector groups, ordered policy, browser access, PRA, LSS), a brokered-only data path, and two enforcement points.

---

## 2. Architecture

### 2.1 Component topology

```
     ENDPOINTS                  PUBLIC EDGE PoPs                 PRIVATE NETWORKS
                                                                 (no inbound ports)
 ┌─────────────────┐  QUIC/UDP443  ┌──────────────────────┐  QUIC/UDP443  ┌─────────────────────┐
 │ zoopa-client    ├──────────────▶│ zoopa-server         │◀──────────────┤ zoopa-connector     │
 │  DNS stub       │ (h2/TLS/TCP443│   role=edge          │ (dialed OUT   │  authoritative PEP  ├─▶ apps
 │  TUN + netstack │   fallback)   │  SPA pre-filter      │  by connector)│  DNS resolution     │
 │  posture        │               │  fast-path PEP       │               │  health / discovery │
 └───────┬─────────┘               │  stream splice       │               └──────────▲──────────┘
         │                         │  flow events         │                          │
         │                         └──────────▲───────────┘                          │
         │  inner TLS 1.3 per flow (end-to-end, the edge cannot read it)             │
         └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
                                             │
 ┌─────────────────┐   HTTPS   ┌─────────────┴────┐   the gateway is "just another client"
 │ Browser         ├──────────▶│ zoopa-server     │   (own SVID + delegated user token)
 │ web apps, SSH,  │           │   role=gateway   │
 │ RDP (WASM)      │           │ ACME · OIDC · PRA│
 └─────────────────┘           │ recorder         │
                               └──────────────────┘
                                             ▲  gRPC over mTLS: edges dial in. Connector and
                                             │  client control traffic is RELAYED by edges as
                                             │  an end-to-end TLS byte pipe.
 ┌───────────────────────────────────────────┴──────────────────────────────────────────┐
 │ CONTROL PLANE (private network)      zoopa-server role=control  × N (stateless)      │
 │  admin API + UI · policy compiler · CA/enrollment · IdP SSO · token service          │
 │  SCIM server · registry/health · discovery aggregation · dashboard ingest            │
 │                 │                                                                    │
 │          PostgreSQL (HA)          public listener: /login, /enroll, /scim            │
 │                                   (the only internet-facing control-plane surface)   │
 └──────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Components

**Control plane** (`zoopa-control`, run as `zoopa-server --role control`)
- Admin REST API (axum, OpenAPI 3.1 via utoipa) and the embedded admin UI.
- Identity: OIDC RP and SAML SP toward IdPs. It also acts as the authorization server toward our own clients: IdP tokens never reach endpoints.
- SCIM 2.0 server. JIT provisioning from IdP claims.
- PKI: an online intermediate CA, enrollment of devices, connectors, edges and gateways, renewal, and revocation.
- Token service: mints access tokens, refreshes them, and evaluates posture.
- Policy compiler: turns the database state into signed **Policy Bundles** and serves them over gRPC watch streams.
- Registry and health: edge and connector status, app health, discovery aggregation.
- Dashboard ingest: aggregated flow and auth statistics into time-partitioned Postgres tables.
- Two listeners:
  - `internal`: admin API, gRPC for edges, and relayed client/connector control traffic. Never exposed to the internet.
  - `public`: login redirects, enrollment and SCIM. Minimal, rate-limited, separately deployable.

**Edge** (`zoopa-edge`, run as `--role edge`)
- Terminates outer QUIC/TLS from clients, gateways and connectors.
- SPA pre-filter in front of quinn (§3.4).
- Validates sessions (token plus certificate binding plus revocation).
- Fast-path policy evaluation, then connector selection.
- Splices client flow streams onto connector flow streams.
- Emits flow events.
- Relays control-plane traffic for clients and connectors as an end-to-end TLS pipe.
- Its only state is a cache: bundles on disk, signed. An edge can be destroyed and recreated at will.

**Connector** (`zoopa-connector`, its own small binary)
- Holds QUIC tunnels to every edge in its assigned edge pool.
- Re-evaluates policy authoritatively for every flow.
- Terminates inner TLS, resolves DNS in the app network, and opens TCP/UDP to apps.
- Probes app health and reports discovery data.
- Never listens on a non-loopback port.
- Separate binary for footprint and attack surface: it runs inside customer app networks and gets the most scrutiny from security reviewers.

**Client** (`zoopa-client` daemon plus platform shells)
- Rust core (`zoopa-client-core`): tunnel, DNS stub, synthetic IP pool, userspace netstack, posture collection, edge selection.
- Platform shells:
  - Windows, macOS and Linux: Tauri v2 tray UI.
  - macOS Network Extension, iOS and Android: native shells calling the core through uniffi.

**Gateway** (`zoopa-gateway` and `zoopa-pra`, run as `--role gateway`)
- Public HTTPS (ACME or uploaded certs).
- Browser access reverse proxy.
- PRA portal: SSH through russh to xterm.js, RDP through the IronRDP WASM client.
- Recorder.
- Reaches apps exactly like a client does, through an edge to a connector, with a **delegated** user token (§4.8). There is no back door into app networks.

**Telemetry pipeline** (`zoopa-telemetry`, a library inside every component)
- *Ops telemetry:* OTel traces, metrics and logs over OTLP, plus a Prometheus scrape endpoint.
- *Product events:* flow, auth, audit, status, browser and PRA events in a versioned schema with an OCSF mapping. Delivered directly from the emitting component to configured **Log Receivers**, with a bounded on-disk spool. Rollups also go to the control plane for dashboards.

### 2.3 Control/data plane separation: invariants

These are written as testable rules. CI chaos tests check them.

1. **The flow path never calls the control plane synchronously.** Flow setup uses only local state: session token, bundle and revocation set.
2. **Static stability.** If the control plane is unreachable:
   - Established device sessions continue.
   - Edges and connectors accept access tokens that expired up to `control_outage_grace` ago (default 2 h, configurable, can be 0) *only* for sessions established before the outage.
   - New logins and enrollments fail closed.
   - The edge exposes `zoopa_control_degraded=1`.
3. **Every enforcement input is signed and verifiable by the enforcer:**
   - Tokens are ES256-signed by the token service.
   - Bundles are signed by the bundle key.
   - Certificates are signed by the CA.
   - The edge and the connector reach identical decisions from identical inputs.
4. **Edges and connectors store nothing authoritative.** Their disk cache is signed and can be thrown away.
5. **The control plane is not internet-exposed** except for the `public` listener (§2.4).

### 2.4 Network exposure

| Component | Listens | Exposure | Pre-auth behaviour |
|---|---|---|---|
| Edge | UDP/443 (QUIC) | Internet | Silent unless the SPA token is valid |
| Edge | TCP/443 (TLS, h2) | Internet | TCP handshake completes. Connection closed without sending any byte if the SPA token in the ALPN entry is invalid |
| Control `public` | TCP/443 (HTTPS) | Internet (or behind a reverse proxy / the gateway) | Login, enrollment and SCIM only. Rate-limited |
| Control `internal` | TCP/8443 (HTTPS + gRPC) | Private. Reached by edges and admins only | mTLS required for gRPC |
| Gateway | TCP/443 | Internet | Normal HTTPS. Unauthenticated users are redirected to login |
| Connector | none (loopback metrics only) | — | — |
| Client | none (loopback DNS stub) | — | — |

Admins reach the admin UI **through openzoopa itself**: it is an app segment. There is a documented break-glass path (local admin with WebAuthn on the internal listener).

### 2.5 Multi-tenancy

**Decision:** one tenant per deployment through 1.0, with tenant-aware foundations from day one:
- Every table has `tenant_id`, and row-level filtering is enforced in the `zoopa-store` query layer.
- One SPIFFE trust domain and one intermediate CA per tenant.
- The SPA token header and the bundle carry a tenant discriminator.

**Rationale:** multi-tenant shared edges (the MSP use case) add tenant routing at the edge, noisy-neighbour isolation and per-tenant key separation. That is a lot of complexity before we have a single happy self-hoster. Making the formats tenant-aware now means a post-1.0 multi-tenant mode needs no breaking change to the wire or the schema.

---

## 3. Wire protocol & crypto

### 3.1 Transport choice

| Criterion | **QUIC (quinn + rustls)** | DTLS | WireGuard (boringtun) |
|---|---|---|---|
| Rust maturity | quinn is mature, widely used, with GSO/GRO, PMTUD and datagrams | No mature pure-Rust DTLS 1.3. We would need OpenSSL FFI | boringtun is solid |
| Identity | TLS 1.3 + X.509: SPIFFE fits, hardware keys, PQ hybrid KEX available | X.509, same as TLS | Static Curve25519 keys. No certificates. PQ only through a PSK add-on |
| Per-app flows | Native streams + RFC 9221 datagrams | Must build our own multiplexing | L3 packets. Pushes toward network-level access |
| Roaming | Connection migration: flows survive Wi-Fi→LTE | No | Yes |
| Middleboxes | UDP/443 is commonly allowed. TCP fallback keeps the same TLS identity | Arbitrary UDP | Arbitrary UDP, no TCP mode |
| Silence when unauthenticated | Needs our pre-filter (§3.4) | Same | Native |

**Decision: QUIC.** The deciding factors:
- It carries per-flow streams.
- It uses certificates and so fits our identity model.
- It roams.
- Its TCP fallback (HTTP/2 over TLS 1.3) uses the same identities and the same framing semantics.

WireGuard's one real advantage, silence to unauthenticated packets, we recreate with the DCID SPA design.

### 3.2 Zoopa Tunnel Protocol v1 (ZTP/1)

**ALPN values:**
- `ztp1-client`: client or gateway to edge.
- `ztp1-conn`: connector to edge.
- Over TCP fallback: `h2`, plus one opaque SPA entry (§3.4).

**Control stream.** The first bidirectional stream opened by the dialer carries length-prefixed protobuf messages:
- `Hello{proto_version, capabilities, client_build}` / `HelloAck{edge_id, server_time}`
- `Authenticate{access_token}` / `SessionResult{ok | reason}`
- `TokenRefreshRequired`, `SessionRevoked{reason}`
- `Drain{deadline, alternate_edges[]}` (GOAWAY)
- `Load{flows, cpu, mem, seg_health[]}` (connector to edge)
- `ControlRelayOpen`: opens a byte pipe to the control plane's internal listener. The dialer then runs **its own mTLS session through it**, so the edge cannot impersonate it (no confused deputy).

**Flow streams.** One bidirectional QUIC stream per TCP flow:
- The opener sends: `varint len || FlowOpen{flow_id, dst{fqdn|ip}, port, proto, segment_id, traceparent?, inner_tls: bool}`, immediately followed by the inner TLS ClientHello bytes (pipelined).
- On the edge→connector leg, `FlowOpen` additionally carries the session's access token and the edge's decision (rule ID, edge ID).
- The response is `FlowResult{accepted | rejected(code, rule_id)}`, then opaque bytes in both directions.
- Stream FIN maps to TCP FIN. `RESET_STREAM` with ZTP error codes maps to TCP RST, connect timeout, connection refused, and policy denial.

**Datagrams.** `varint flow_ctx || payload` for UDP flows (§7.4).

**TCP fallback.**
- TLS 1.3 over TCP/443 carrying HTTP/2 (`h2` crate).
- The control stream is a long-lived extended-CONNECT stream with `:protocol = ztp-control`.
- Each flow is an extended-CONNECT stream with `:protocol = ztp-flow`.
- UDP payloads ride in RFC 9297-style capsules on their flow stream.
- Head-of-line blocking across flows is an accepted fallback cost. There is no TCP-over-TCP meltdown because app TCP is terminated at both ends.
- Through an explicit HTTP proxy (PAC or system proxy), the client issues `CONNECT edge:443` first.

**Versioning.**
- A major protocol change means a new ALPN.
- Minor features are negotiated through `capabilities`.
- Both edge and connector support ALPN versions N and N-1 for at least one product minor release.

**Encodings.**
- Protobuf (prost) for every structured message, including gRPC.
- No JSON on hot paths.

### 3.3 Identities & PKI

**SPIFFE IDs** (in the URI SAN):
```
spiffe://<td>/edge/<edge-id>
spiffe://<td>/connector/<group-id>/<connector-id>
spiffe://<td>/device/<device-id>
spiffe://<td>/gateway/<gateway-id>
spiffe://<td>/control/<replica-id>
```
Users are **never** in certificates. User identity lives in short-lived access tokens bound to the device certificate.

**Decision: built-in CA, SPIFFE format, no SPIRE dependency.** SPIRE is a whole extra distributed system for self-hosters to run. Using the SPIFFE format means we keep the option of integrating SPIRE, Vault or OpenBao PKI later (phase 4) via an "external CA" backend.

**Hierarchy and lifetimes:**

| Certificate | Key location | Lifetime | Renewal |
|---|---|---|---|
| Root | **Offline** (generated by `zoopactl ca init`, exported, never stored on the server). PKCS#11/HSM later | 10 y | Manual ceremony |
| Tenant intermediate | Online in the control plane, encrypted at rest with a KEK (file or env in v1, KMS/PKCS#11 in phase 3) | 1 y | Overlapping rotation. The trust bundle carries both |
| Edge / connector / gateway / control leaf | Host key (TPM if present) | **24 h** | At 50% of lifetime, over mTLS with the current key |
| Device leaf | **Hardware-bound, non-exportable** (TPM 2.0, Secure Enclave, Android Keystore/StrongBox). Software fallback flagged in posture | 30 d | At 50%, with proof of possession. Long enough to survive a laptop being offline during a holiday |

**Revocation.**
- Short lifetimes mean no CRL or OCSP infrastructure.
- Immediate kill is handled by a **revocation set** (device IDs, connector IDs, session IDs) pushed on the watch stream separately from bundles. Its target latency is under 5 s.

**Enrollment:**
- **Connector:** the admin creates a *provisioning key* scoped to a connector group, with expiry, a maximum use count, and optional admin approval. The connector generates a key, posts a CSR plus the provisioning key to `/enroll`, and receives its SVID, trust bundle, edge pool and SPA key.
- **Device:** the user logs in through the system browser (RFC 8252 + PKCE, loopback redirect, `ASWebAuthenticationSession` on Apple, Custom Tabs on Android). The client generates a hardware key, posts a CSR plus a one-time enrollment code (plus a platform attestation where available, phase 3), and receives its device SVID, trust bundle, edge list, SPA key and initial access token.
- **Edge / gateway:** a bootstrap token issued by `zoopactl` at deploy time, then the same CSR flow.

**Verifiers.** These are custom `rustls` verifiers in `zoopa-crypto`. They wrap `rustls-webpki` with private roots and then enforce SPIFFE path rules. For example, a client accepts only `/edge/*` on the outer TLS and only `/connector/<group ∈ segment.groups>/*` on the inner TLS (§3.5). WebPKI roots are never trusted for internal links.

### 3.4 Single Packet Authorization: "dark QUIC"

**Goal:** a scanner (zmap/nmap QUIC probes, version-negotiation probes, random short-header packets) gets **no response at all**. Our TLS and QUIC stacks are not reachable by anyone without a current SPA key.

**Mechanism.** A QUIC client chooses the destination connection ID (8–20 bytes) of its first Initial packet. We make that DCID an authenticator:

```
DCID (20 bytes) = hdr(1) || ts(4) || nonce(7) || tag(8)
  hdr   = version(4 bits) | role(2: client/connector/gateway) | key-epoch parity(2)
  ts    = unix seconds (client time corrected by the server_time offset learned at enrollment/Hello)
  nonce = random
  tag   = HMAC-SHA256(K_spa[role][epoch], hdr || ts || nonce || edge_id)[0..8]
```

- `K_spa` is a **per-tenant, per-role key rotated daily**. Two epochs are valid at a time. It is distributed in signed config to enrolled principals. A revoked device stops receiving new epochs, so a leaked key stays useful for at most about 48 hours.
- `edge_id` is part of the MAC input but is not transmitted. This stops a token observed at one edge being replayed at another.
- The edge keeps a replay cache of `(ts, nonce)` for a ±90 s window. Exact replays are dropped.
- **Why tenant-wide keys rather than per-device keys:** a per-device key would put a stable principal handle on the wire, which lets on-path observers link a user's connections, or would require a home-grown encryption layer to hide it. A tenant/role key is boring, unlinkable, and revoked by rotation. The cost: one compromised device can get past SPA until the next epoch. It still faces mTLS. SPA reduces attack surface. It is not an authentication layer, and we do not treat it as one.

**Pre-filter rules.** Implemented as a custom quinn `AsyncUdpSocket` wrapper (`Endpoint::new_with_abstract_socket`), so packets are dropped *before* quinn:

| Packet | Accept if |
|---|---|
| Long header, Initial or 0-RTT | DCID is a valid SPA token, or a valid server-issued CID |
| Long header, Handshake | DCID is a valid server-issued CID |
| Short header | DCID is a valid server-issued CID |
| Anything else (including unknown versions) | Never. No Version Negotiation and no stateless reset is ever sent for a dropped packet |

Server-issued CIDs come from a keyed `ConnectionIdGenerator` (MAC-validated), so validation needs no table lookup. 0-RTT is disabled.

**Phase-0 spike (blocking).** Verify:
- that quinn's client config allows supplying the initial DCID (`initial_dst_cid_provider` or equivalent), and
- that the edge can suppress stateless resets for unknown CIDs.

If either is missing, we carry a small patch and work to upstream it. The CI gate runs zmap/nmap QUIC probes against an edge and asserts zero bytes come back.

**TCP fallback limit, stated plainly.** SYN-ACK cannot be hidden without a kernel-level knock, and UDP knocks are useless in exactly the networks that force TCP. On TCP/443:
- The ClientHello carries the same 20-byte token as an extra ALPN entry (`"zspa" || token`).
- The edge inspects it with rustls's `Acceptor` / tokio-rustls `LazyConfigAcceptor` before choosing a server config.
- On failure it closes without sending a single byte. No alert, no certificate.
- The pre-auth attack surface is therefore rustls ClientHello parsing only.
- Operators can put the TCP fallback on a separate IP.

The gateway and the control `public` listener are necessarily not dark.

### 3.5 Double encryption

**Outer layer:** QUIC/TLS 1.3 on two hops, client↔edge and edge↔connector.

**Inner layer:** one **TLS 1.3 session per flow, end to end between client and connector**, carried as opaque bytes through the edge.
- The client presents its device SVID. The connector presents its connector SVID.
- The client verifies that the connector's group is listed for the segment in the client's *own signed steering config*. Edge-supplied hints are not trusted.
- The connector verifies that the device SVID's key thumbprint equals the access token's `cnf.x5t#S256`, and that the `device_id` matches.
- Cost: one ECDHE+ML-KEM handshake per flow, which is cheap relative to an app TCP connect. Session resumption is enabled to cut that further. The inner ClientHello is pipelined with `FlowOpen` (§7.3).

**Why default on:** the inner layer is what turns the connector into an *authoritative* enforcement point. Without it, a compromised edge can mint flows using any session token it has seen, because the connector cannot check that the requester actually holds the device key (§9). Admins can turn it off per segment for bulk-throughput apps. The UI labels that choice "edge-trusted mode".

**UDP:** the flow's setup stream carries the inner handshake. Datagram payload keys come from the TLS exporter (RFC 8446 §7.5, label `EXPORTER-zoopa-udp-v1`) and are used with AES-256-GCM. Each direction has its own key, and the nonce is a 64-bit counter, giving replay protection within a sliding window.

### 3.6 Crypto provider and post-quantum posture

- **Provider:** `rustls` with `aws-lc-rs` for every TLS use. HMAC, AEAD and HKDF also come from aws-lc-rs. No `openssl` crate anywhere in the dependency graph (cargo-deny bans it) except through the optional SAML `xmlsec` feature (§4.1).
- **TLS 1.3 only.** Cipher suites: AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305.
- **Key exchange:** hybrid **X25519MLKEM768 is preferred everywhere** (outer, inner, gateway↔edge, control). Plain X25519 is accepted only on the gateway's public listener, for browser compatibility.
  - This defends against harvest-now-decrypt-later for all internal traffic from day 1.
  - Note: with an ML-KEM key share the ClientHello spans two QUIC Initials. That is handled by QUIC and covered by tests against the anti-amplification limit.
- **Signatures:** ECDSA P-256 now. Every bundle carries algorithm identifiers (crypto agility). Because certificates live 24 h, moving to ML-DSA (or a hybrid) is a CA rotation plus one day, not a migration project. We adopt it when rustls-webpki and the hardware key stores support it.
- **SPA and exporter-derived keys** are symmetric and therefore already PQ-safe.
- **FIPS:** the aws-lc-rs FIPS module gives us a credible FIPS 140-3 build variant (`--features fips`, phase 4). This is a real reason to pick aws-lc-rs over `ring`.

### 3.7 Access tokens

- Compact **JWT, ES256**, via the `jsonwebtoken` crate.
  - The algorithm allowlist is pinned to `[ES256]`.
  - `typ = zoopa-at+jwt`.
  - `aud` is per component class: `edge`, `connector`.
  - `kid` rotation with overlap. Public keys ship in bundles.
  - JWT was chosen over PASETO for tooling familiarity. The well-known JWT pitfalls are removed by strict pinned validation.
- **Claims:**
  - `sub` (user), `sid` (session), `did` (device), `cnf.x5t#S256`.
  - `grp`: **only the groups referenced by at least one rule**, computed by the control plane, which keeps tokens small for users with hundreds of groups.
  - `attr` (referenced attributes only), `pst` (posture profile results), `ct` (client type), `idp`, `auth_time`, `reauth_by`, `exp` (15 min).
  - For the gateway only: `act` (actor = gateway SVID).
- **Refresh:**
  - The client calls `RefreshAccess` over the edge's control relay. mTLS with the device key *is* the refresh credential, so there are no bearer refresh tokens on endpoints.
  - The control plane re-checks user status, group membership, posture facts and the re-auth deadline.
  - Where the IdP issued an `offline_access` refresh token, the control plane uses it periodically as an IdP-side liveness check. This catches deprovisioning in setups without SCIM.

---

## 4. Identity & policy

### 4.1 IdP integration

- **OIDC** (`openidconnect` crate): authorization code + PKCE, discovery, JWKS rotation, claims mapping (`groups`, `email`, custom).
- **SAML 2.0 SP** (`samael` with xmlsec). This is the riskiest dependency in the project, because XML signature wrapping is a well-known attack class. Mitigations:
  - isolated in `zoopa-idp` behind feature `saml`;
  - strict profile: signed assertions required, exactly one assertion, the signature reference must resolve to that assertion's ID, audience/recipient/NotOnOrAfter enforced, replay cache of assertion IDs;
  - dedicated fuzz targets and a corpus of known XSW test vectors.
  - Fallback if samael proves unmaintainable: a documented OIDC bridge (Keycloak, Dex). Self-hosted and optional.
- **Multiple IdPs:** routed by login-hint email domain (for example, employees on Entra ID and contractors on Okta).
- **Admin login:** OIDC SSO with an admin-role claim mapping, plus **local break-glass accounts** (argon2id password + WebAuthn via `webauthn-rs`, mandatory).
- **The control plane is the authorization server for our own clients.** Endpoints never hold IdP tokens.

### 4.2 Directory sync

- **SCIM 2.0 server** (`/scim/v2/Users`, `/Groups`; per-IdP bearer tokens).
  - Supports the PATCH semantics Okta and Entra actually send.
  - Supports only the filter subset they use (`eq` on `userName`, `externalId`, `displayName`), parsed with `winnow` and fuzzed.
  - Conformance tests replay recorded Okta and Entra request sequences.
- **JIT provisioning** from OIDC/SAML claims for deployments without SCIM.
- **Deprovisioning** (SCIM `active=false` or DELETE): within seconds the user's sessions go into the revocation set, edges drop their sessions, and active flows are torn down.
- **Group change:** a `TokenRefreshRequired` push goes to that user's live sessions. Clients refresh silently.
- Pull connectors (Entra Graph, Google Workspace, LDAP) are phase 4, only if demand exists.

### 4.3 Devices and posture

- Each device has an enrolled hardware key and a single owning user at a time.
- **The client collects facts. The control plane evaluates them.** The control plane sends a *collection spec* (which facts to gather). The client returns signed facts every 5 minutes and immediately when something changes. Posture profiles (for example, "corp-laptop-windows") are evaluated on the server, and the boolean results go into `pst` in the token. Profile definitions never leave the server.
- **v1 facts:**
  - OS and version
  - disk encryption (BitLocker, FileVault, LUKS)
  - firewall on
  - screen lock
  - named process or service running (EDR presence)
  - file or registry key present
  - corporate certificate present in the OS store
  - domain-joined or MDM-enrolled
  - device key is hardware-backed
- **Phase 3:** TPM-quote and platform attestation where available without SaaS dependencies (Apple Managed Device Attestation through MDM; Android Key Attestation, verified locally against Google's published roots). EDR API integrations (CrowdStrike ZTA, Defender) as optional plugins. Play Integrity is optional because it requires Google's service.
- **Honest limit:** self-reported posture on a rooted or jailbroken device is advisory unless backed by attestation (§9).

### 4.4 Policy model

**Entities:** `IdentityProvider`, `User`, `Group`, `Device`, `PostureProfile`, `ConnectorGroup`, `Connector`, `EdgePool`, `Edge`, `AppSegment`, `SegmentGroup`, `BrowserApp`, `PraConsole`, `Credential`, `AccessRule`, `TimeoutRule`, `ForwardingRule`, `PraRule`.

**AppSegment fields:**
- `domains[]`: exact FQDN or `*.suffix`.
- `cidrs[]`.
- `tcp_ports[]`, `udp_ports[]` (ranges).
- `connector_groups[]` (ordered by preference).
- `double_encryption` (default `true`).
- `health_check`: `continuous | on_access | none`.
- `resolve_mode`: `synthetic_fast | through_connector`, defaulted per §7.2.
- `resolved_address_allow[]`: optional CIDRs the connector's DNS result must fall within.
- `discovery`: bool.
- `icmp`: bool.

**Segment matching** (used by both client steering and edge evaluation), **most specific wins**:
1. Exact FQDN.
2. Longest wildcard suffix.
3. Longest-prefix CIDR.

Ties are broken by the narrower port range, then by segment ID. Overlaps are flagged at compile time and shown in the UI.

**AccessRule** (ordered, first match wins, implicit final **deny**). `action ∈ {allow, deny}`. Conditions are **OR within a category and AND across categories**:

| Category | Values | Evaluated from |
|---|---|---|
| Subject | users, groups, attribute predicates, IdP | token `sub`, `grp`, `attr`, `idp` |
| Application | segments, segment groups | flow destination → segment |
| Posture | profile = true/false | token `pst` |
| Client type | desktop, mobile, browser access, PRA | token `ct` |
| Network location | edge pool / private edge that the flow **arrived on** | Server-side fact. Never a client claim |
| Time | schedules with time zones | edge/connector clock |
| Geo (optional) | country of the edge-observed public IP | GeoIP database (user-supplied, e.g. DB-IP Lite) |

- **TimeoutRule** (ordered): `reauth_interval` (interactive IdP login deadline → `reauth_by`) and `flow_idle_timeout`.
- **ForwardingRule** (client): per trusted-network detection result, one of `intercept | bypass | prefer_private_edge`. Trusted-network detection for *forwarding* may use weak signals (DNS probe). For *access decisions* only the server-side "arrived on private edge" fact counts.
- **PraRule:** who may use which console, credential injection on or off, recording mandatory or optional.

### 4.5 Evaluation engine (`zoopa-policy`)

- A pure library: no I/O, no async, deterministic. Shared by edge, connector, client steering, gateway and `zoopactl policy explain`.
- **Compile** (control plane):
  - domains go into a reversed-label trie, CIDRs into prefix tries (v4/v6), ports into interval sets;
  - each rule gets a `segment → rule` bitset;
  - each rule's subject, posture and client-type predicates are pre-compiled.
- **Per session** (once at authentication and on bundle or token change): compute `S = bitset of rules whose session-static conditions match`.
- **Per flow:**
  1. `seg = match(dst, port, proto)`
  2. `candidates = seg_rules[seg] & S`
  3. walk the set bits in order, checking only the dynamic conditions (time, geo)
  4. first match wins → `(action, rule_id, timeouts, obligations)`

  This costs O(rules/64) word operations plus a trie lookup. The target is p99 < 10 µs with 10k segments and 2k rules.
- **Differential testing:** the compiled evaluator is property-tested (`proptest`) against a deliberately naive reference evaluator in the same crate.
- **Explainability:** every decision carries `rule_id` into flow events. `zoopactl policy explain --user alice --device d_… --dst git.corp.example:443` replays the decision with a trace.
- **Rejected alternatives:**
  - *Cedar* (Rust, formally verified): its forbid-overrides-permit, unordered semantics don't fit the first-match ordered model admins expect from ZPA, and we need a purpose-built hot path. We may revisit it as an "advanced condition" extension.
  - *OPA/Rego*: Go, heavyweight, and a poor fit for the hot path.

### 4.6 Policy distribution

- On any relevant change the control plane recompiles (serialised by a Postgres advisory lock). It stores the result as an immutable, monotonically numbered **Policy Bundle** row (protobuf, zstd, Ed25519-free: **ES256-signed** with a dedicated bundle key, separate from the CA and token keys) and fires `NOTIFY`.
- Every replica's gRPC `WatchBundle` streams push the new generation. Receivers ack the generation, and lag is exported as a metric per edge and connector.
- **Scoping:**
  - Edges get the full bundle.
  - Connectors get only rules and segments for their groups.
  - Clients get a **steering config** containing only segments the user could be allowed by subject conditions (ignoring posture and time), so the internal app inventory is not leaked to every endpoint.
- **v1 sends full snapshots.** At 10k segments that is a few MB compressed, which is fine. Deltas come later, only if measurements show they are needed.
- **The revocation set is a separate, small, high-frequency stream** and needs no recompile.
- Edges and connectors persist the last bundle on disk (signed) and start from it if the control plane is unreachable.

### 4.7 Session lifecycle and re-auth

1. **Interactive login** (IdP) creates a user session with `reauth_by = now + reauth_interval`, taken from the matched TimeoutRule.
2. Access tokens (15 min) are refreshed silently until `reauth_by`. Then the client prompts. Silent IdP SSO is used where the IdP session is still alive.
3. **Continuous evaluation:** on every new bundle, revocation update or token refresh, the edge recomputes session bitsets and **re-evaluates every active flow**. Flows that are now denied are reset with `ZTP_POLICY_REVOKED`. This is configurable per rule (`terminate_existing`, default `true`).
4. At `reauth_by`, new flows are denied and existing flows survive until `flow_idle_timeout`, or are cut immediately if the rule says `hard_reauth`.

### 4.8 Browser access identity

- One central login host (`auth.<access-domain>`), then a one-time code redirect to each app host. Each app host sets its own `__Host-` cookie (`SameSite=Lax`, `Secure`, `HttpOnly`, 8 h max).
- Every app gets a distinct origin, so a malicious app cannot read another app's session.
- The gateway obtains a **delegated access token** (token exchange: user session + gateway SVID; `act` = gateway, `ct` = browser) and opens flows exactly like a client. Connectors therefore see the real user. Policy can treat browser access separately through the `client type` condition.
- Rewriting is limited to `Host`, `Location`, `Set-Cookie` domain/path and `Origin`/`Referer`. **Recommended mode:** use the same hostname internally and externally (split-horizon) with a public certificate. That gives the highest fidelity and needs no rewriting.

---

## 5. Crate / workspace layout

### 5.1 Workspace conventions

- **Edition 2024**, resolver 3. One `[workspace.package]` version: the product is versioned in lockstep.
- **MSRV:** pinned at project start to *stable minus 2*. It moves forward only in minor releases and is checked in CI. `rust-toolchain.toml` pins the exact build toolchain.
- `[workspace.dependencies]` is the single source of versions. `[workspace.lints]`: `unsafe_code = "deny"` (overridden only in `zoopa-netstack`, `zoopa-client-ffi` and `zoopa-posture`, each with a `SAFETY:` comment required by clippy `undocumented_unsafe_blocks`), plus `clippy::all` and a curated pedantic subset, with `-D warnings` in CI.
- Every crate is `publish = false` until it has a real external consumer.
- **IDs:** UUIDv7 in the database. The API shows them with type prefixes (`seg_…`, `usr_…`, `con_…`) so logs are self-describing.
- **Runtimes:** tokio multi-thread on servers. Current-thread runtime plus bounded buffers in mobile Network Extensions (the iOS NE memory limit is about 50 MB).
- **Allocator:** jemalloc (`tikv-jemallocator`) for the Linux builds of edge and connector, kept only if benchmarks justify it.

### 5.2 Crates

| Crate | License | Responsibility | Key dependencies |
|---|---|---|---|
| `zoopa-proto` | Apache-2.0 | `.proto` → Rust: gRPC APIs, bundle, ZTP headers | prost, tonic (codegen) |
| `zoopa-types` | Apache-2.0 | IDs, SPIFFE ID type, domain enums, error codes | serde, uuid, ipnet |
| `zoopa-crypto` | Apache-2.0 | rustls config factories, SPIFFE-aware verifiers, key backends (file / TPM / Secure Enclave / Keystore / PKCS#11), TLS exporters | rustls, aws-lc-rs, rustls-webpki, zeroize, secrecy |
| `zoopa-spa` | Apache-2.0 | SPA token mint/verify, QUIC & TLS pre-filter, replay cache | aws-lc-rs |
| `zoopa-tunnel` | Apache-2.0 | ZTP/1: QUIC and h2 transports behind one `Transport` trait, flows, datagrams, inner TLS, drain | quinn, h2, tokio-rustls, bytes |
| `zoopa-policy` | Apache-2.0 | Policy model, compiler, evaluator, explain (pure) | ipnet, (own tries/bitsets) |
| `zoopa-token` | Apache-2.0 | Access-token mint/verify, `cnf` binding | jsonwebtoken |
| `zoopa-telemetry` | Apache-2.0 | OTel setup, event schema + OCSF mapping, disk spool, log receivers | tracing, opentelemetry, opentelemetry-otlp |
| `zoopa-config` | Apache-2.0 | Layered TOML + env config with validation | serde, toml |
| `zoopa-netstack` | Apache-2.0 | TUN per OS, userspace TCP/UDP termination, held-SYN logic | smoltcp, tun-rs, wintun |
| `zoopa-dns` | Apache-2.0 | DNS stub, synthetic IP pool, OS resolver integration (systemd-resolved, NRPT, NEDNSSettings) | hickory-proto |
| `zoopa-posture` | Apache-2.0 | Posture fact collectors | windows, objc2, zbus |
| `zoopa-client-core` | Apache-2.0 | Client engine: session, steering, edge selection, refresh | the crates above |
| `zoopa-client-ffi` | Apache-2.0 | uniffi bindings for Swift/Kotlin | uniffi |
| `zoopa-connector` | Apache-2.0 | Connector lib + bin | hickory-resolver, zoopa-tunnel |
| `zoopa-store` | AGPL-3.0 | Postgres access layer, migrations, tenant scoping | sqlx |
| `zoopa-pki` | AGPL-3.0 | CA operations, CSR validation, issuance | rcgen, x509-parser |
| `zoopa-idp` | AGPL-3.0 | OIDC RP, SAML SP (feature) | openidconnect, samael |
| `zoopa-scim` | AGPL-3.0 | SCIM 2.0 server | axum, winnow |
| `zoopa-control` | AGPL-3.0 | Control plane service | axum, tonic, utoipa, arc-swap |
| `zoopa-edge` | AGPL-3.0 | Edge service | quinn, zoopa-tunnel, zoopa-policy |
| `zoopa-gateway` | AGPL-3.0 | Browser access proxy, ACME, sessions | hyper 1, hyper-util, instant-acme |
| `zoopa-pra` | AGPL-3.0 | SSH/RDP proxying, credential injection, recording | russh, ironrdp |
| `zoopa-server` (bin) | AGPL-3.0 | Multi-role server binary; embeds the admin UI | clap, rust-embed |
| `zoopa-client` (bin) | Apache-2.0 | Desktop daemon + local CLI | clap |
| `zoopactl` (bin) | Apache-2.0 | Admin CLI (generated OpenAPI client) | reqwest, progenitor |
| `zoopa-operator` (bin) | Apache-2.0 | Kubernetes operator | kube, k8s-openapi |
| `zoopa-testkit` | (unpublished) | In-process cluster, netns harness, fake IdP/SCIM, fault injection | — |
| `xtask` | (unpublished) | Codegen, e2e runner, license-boundary check, release helpers | — |

**Outside the Rust workspace:**
- `ui/admin` and `ui/portal`: TypeScript + React + Vite. **Decision:** the UI is a pure API client with no business logic, so the largest contributor pool beats keeping everything in one language. Leptos was considered and rejected for now.
- `clients/desktop` (Tauri v2), `clients/apple` (Xcode: macOS system extension and iOS), `clients/android` (Gradle).
- The Terraform/OpenTofu provider lives in a **separate repo, `terraform-provider-openzoopa`** (Go, terraform-plugin-framework). Registry naming requires this. It is generated against the OpenAPI spec.

### 5.3 Dependency selection rules

- A dependency must be maintained (release in the last 12 months or clearly feature-complete), have more than one maintainer or an institutional owner, and pass cargo-deny and cargo-vet.
- **Crypto comes only from rustls and aws-lc-rs.** No hand-written primitives. Every new construction (the SPA token, the UDP exporter keys) is a composition of standard primitives, specified in an RFC doc and reviewed by someone with cryptographic expertise before 1.0.
- New dependencies in `zoopa-crypto`, `zoopa-spa`, `zoopa-tunnel`, `zoopa-policy`, `zoopa-pki`, `zoopa-token` or `zoopa-idp` need two maintainer approvals (CODEOWNERS).

### 5.4 Licensing

| Option | For | Against |
|---|---|---|
| Apache-2.0 / MIT for everything | Maximum adoption, Rust ecosystem norm, no legal friction | A vendor (or ZPA's competitors) can ship a hosted, proprietary fork with no contribution back. Our only protection would be the trademark. |
| AGPL-3.0 for everything | Strongest protection against closed SaaS forks | Many enterprise legal teams ban AGPL **on endpoints**, which is exactly where security review is hardest. It also blocks embedding the client in other products. |
| **Split: AGPL server, Apache endpoint/protocol** | Endpoints, connectors, protocol and libraries stay permissive (easy security approval, embeddable, and alternative implementations remain possible). Server roles, where the "host it as SaaS" risk sits, are protected. Precedent: NetBird moved its server components to AGPLv3 in 2025 while keeping clients permissive. | Two licenses to explain. Permissive crates must never depend on AGPL crates. |

**Decision (owner, 2026-10-26): the split.**
- **AGPL-3.0-only** for `zoopa-server` and its server-role crates.
- **Apache-2.0** (patent grant included; no MIT dual license, since there is no GPLv2 consumer to satisfy) for everything else.
- An `xtask license-boundary` CI check fails if an Apache crate depends on an AGPL crate.

**DCO, not CLA.** With AGPL and no CLA, nobody, the founders included, can relicense the server to a proprietary license later. That is a deliberate trust signal to contributors. **This forecloses a dual-license business model.** If the owner wants that option, a CLA must be in place before the first external contribution. That decision is listed in §11.

**Trademark.** Register or claim "openzoopa" and adopt a trademark policy: forks are allowed, confusing branding is not.

**Legal risk to raise now:** the name echoes Zscaler's "ZPA" mark. Get a quick legal sanity check before launch. Use "ZPA" only nominatively in comparisons. Do clean-room design from public documentation only.

---

## 6. Repository & project hygiene

### 6.1 Monorepo layout

```
openzoopa/
├── Cargo.toml  rust-toolchain.toml  deny.toml  .cargo/config.toml
├── crates/            # all library crates (§5.2)
├── bin/               # zoopa-server, zoopa-connector, zoopa-client, zoopactl, zoopa-operator
├── proto/             # .proto sources (zoopa.control.v1, zoopa.tunnel.v1, zoopa.bundle.v1)
├── ui/{admin,portal}/
├── clients/{desktop,apple,android}/
├── deploy/{compose,helm,systemd,packaging,grafana}/
├── fuzz/              # cargo-fuzz targets
├── tests/e2e/         # netns- and kind-based end-to-end suites
├── supply-chain/      # cargo-vet audits & imports
├── xtask/
├── docs/{DESIGN.md, rfcs/, adr/, threat-model.md, ops/}
├── .github/{workflows/, ISSUE_TEMPLATE/, CODEOWNERS, renovate.json}
├── SECURITY.md  CONTRIBUTING.md  GOVERNANCE.md  MAINTAINERS.md  CODE_OF_CONDUCT.md
└── LICENSE-APACHE  LICENSE-AGPL  LICENSING.md   # LICENSING.md maps crates to licenses
```

### 6.2 CI (GitHub Actions)

**On every PR:**

| Job | Matrix / notes |
|---|---|
| fmt, clippy (`--all-targets --all-features -D warnings`) | ubuntu x86_64 |
| test (`cargo nextest`) | ubuntu x86_64, **ubuntu arm64** (native runner), macOS arm64, Windows x86_64 |
| MSRV build | ubuntu |
| cargo-deny: advisories, licenses (with the AGPL/Apache boundary), bans (`openssl`, duplicate crypto crates), sources | ubuntu |
| cargo-vet | ubuntu |
| e2e-netns: client / edge / connector / app in Linux network namespaces with a fake IdP | ubuntu (sudo) |
| darkness test: zmap/nmap QUIC probes assert zero response | ubuntu |
| fuzz smoke (60 s per target) | ubuntu nightly toolchain |
| cargo-semver-checks | published crates only (none at first) |
| UI lint, typecheck, unit tests; OpenAPI diff (breaking changes need a label) | ubuntu |
| xtask license-boundary | ubuntu |

**Nightly:**
- long fuzzing (also applying to OSS-Fuzz once public);
- Miri on unsafe-containing crates;
- the chaos suite (kill or partition edges, connectors and Postgres; check the §2.3 invariants);
- version-skew tests (N-1 connector and client against N edge and control);
- Helm on kind;
- performance benchmarks on a fixed self-hosted runner, which open an issue on a >5% regression.

**Fuzz targets (initial):**
- SPA packet pre-filter
- ZTP frame and `FlowOpen` decoding
- bundle decoding
- policy compiler input
- SCIM filter and PATCH
- SAML response parsing
- DNS stub parsing
- CSR parsing
- token parsing
- gateway HTTP header rewriting

### 6.3 Security posture

- **SECURITY.md:** private reporting via GitHub Security Advisories plus `security@` (PGP optional). Acknowledgement within 72 h. Coordinated disclosure target of 90 days. A supported-versions table.
- **Security-sensitive paths** (crypto, spa, tunnel, policy, pki, token, idp, pra): two-maintainer review, changes need an RFC, and each has fuzz coverage.
- **Releases:**
  - built on native runners per architecture (no cross-compiling where avoidable);
  - **CycloneDX SBOM** (`cargo-cyclonedx`) per artifact;
  - **SLSA build provenance** through GitHub artifact attestations;
  - **cosign keyless signatures** on binaries and images;
  - minimal container images (static or distroless) with non-root UID;
  - reproducible builds as a tracked goal.
- Renovate for dependencies, grouped weekly. Security updates go out immediately.
- An external audit is required before 1.0. The report is published.

### 6.4 Governance and contribution

- **Phase-in model:** the owner is BDFL until there are 3 or more active maintainers, then a maintainer council with lazy consensus. GOVERNANCE.md documents the transition.
- **RFC process** (`docs/rfcs/NNNN-*.md`), required for: wire protocol, crypto, policy semantics, public API breaking changes, new sensitive-path dependencies, and licensing.
- **ADRs** for smaller decisions. This document seeds ADR-0001 to 0012 from §0.
- DCO sign-off is enforced. Conventional Commits drive changelogs (git-cliff). Contributor Covenant code of conduct.

### 6.5 Versioning and releases

- **Product SemVer**, lockstep across all binaries. 0.x until the §1.2 criteria are met.
- **Independently versioned contracts:** REST API (`/api/v1`, deprecations announced 2 minors ahead), gRPC packages (`zoopa.*.v1`), ZTP ALPN, bundle schema, event schema (`schema_version` field).
- **Version skew policy** (like Kubernetes):
  - control ≥ edge ≥ connector/client;
  - edge, connector, gateway and client may trail control by **one minor**;
  - control and edge support the N-1 protocol.
- **Cadence:** a minor release roughly every 8 weeks from a `release/x.y` branch with RC tags. Patches are backported to the latest two minors. An LTS line is considered after 1.0.

---

## 7. Data plane deep-dive

### 7.1 Steady state

- Each connector holds 1 to N QUIC connections to **every edge in its edge pool**. That is several connections per edge, so flows are hashed across them and no single connection becomes a bottleneck on one core.
- Each connector also sends `Load` and segment health every 5 s.
- Each client holds one QUIC connection to its selected edge: keepalive every 15 s on desktop, adaptive 25–60 s on mobile, idle timeout 45 s.

The v1 rule "connectors reach every pool edge" removes the need for edge-to-edge signalling and a global registry. It is fine up to about 50 edges × a few thousand connectors. The edge relay mesh (§8, phase 4) removes this limit later.

### 7.2 Client traffic capture

- **DNS.**
  - The client registers itself as resolver **only for steered suffixes**: per-link routing domains in systemd-resolved, NRPT rules on Windows, `NEDNSSettings.matchDomains` on Apple, `VpnService` DNS plus a fallthrough on Android.
  - **Explicit-FQDN segments** (`resolve_mode=synthetic_fast`): the client answers immediately with a synthetic IP from `100.64.0.0/10` (and `fd7a:7a00::/48` for AAAA if IPv6 is enabled) with a short TTL, and keeps a synthetic→FQDN mapping.
  - **Wildcard segments** default to `through_connector`: the query goes over a short flow to a connector, which resolves in the app network. NXDOMAIN then propagates correctly, which matters because software probes many names under `*.corp` that don't exist. Results are cached by TTL, and the observations feed discovery.
- **CIDR segments:** routes for those CIDRs point into the TUN device. The real destination IP is forwarded.
- **TUN plus userspace termination** (`zoopa-netstack`, built on smoltcp) on every platform as the **single primary code path**. Platform flow APIs (macOS `NETransparentProxyProvider`, Linux TPROXY) are possible later optimisations, not v1.
  - The TUN MTU is independent of the outer path because packets never leave the host as-is. It defaults to 1500 and can be raised on Linux for throughput.
- **Held SYN:**
  - The client does **not** finish the local TCP handshake until the connector reports success.
  - When a SYN for a new 4-tuple arrives, it is held and `FlowOpen` is sent.
  - On `FlowResult::accepted`, the SYN is injected into a per-tuple listening socket.
  - On reject or timeout (10 s), the client synthesises an RST or ICMP unreachable.
  - Result: "connection refused", timeouts and policy denials look to the app exactly like they would on a direct network.
- **Risk:** smoltcp throughput for desktop-class TCP termination. Phase 0 includes a benchmark gate (§7.10). The fallback plan, if needed, is to contribute performance work upstream or use a different userspace stack behind the same `zoopa-netstack` trait.

**Platform matrix:**

| Platform | Capture | Device key | Packaging |
|---|---|---|---|
| Linux | TUN + resolved | TPM 2.0 (tss-esapi) or file | deb/rpm, systemd |
| Windows | Wintun + NRPT | TPM (CNG Platform Crypto Provider) | MSI, Windows service. Code signing via SignPath Foundation (free for OSS) or the owner's certificate |
| macOS | NEPacketTunnelProvider (system extension) | Secure Enclave | Developer ID, notarised pkg. **Needs an Apple developer account** |
| iOS | NEPacketTunnelProvider | Secure Enclave | App Store; server URL set through MDM app config or QR enrollment |
| Android | VpnService (always-on capable) | Keystore/StrongBox | Play Store + F-Droid/APK |

### 7.3 Flow establishment, step by step

```
Client(C)                      Edge(E)                         Connector(K)               App
  │ [once] QUIC Initial, DCID=SPA token ─▶ pre-filter ok        │                          │
  │◀═════ outer TLS1.3 mTLS (device SVID ↔ edge SVID) ═════▶    │                          │
  │── ctl: Hello, Authenticate(access token) ─▶                 │                          │
  │◀─ ctl: SessionResult(ok); E computes session rule bitset    │                          │
  │                                                             │                          │
  │ app: DNS git.corp.example → stub → 100.64.3.7               │                          │
  │ app: SYN 100.64.3.7:443 → TUN → held                        │                          │
  │── stream n: FlowOpen{fqdn,443,tcp} ‖ inner ClientHello ─▶   │                          │
  │                    segment match → evaluate → allow (r17)   │                          │
  │                    pick connector (§7.7)                    │                          │
  │                    stream m: FlowOpen{…, token, r17} ‖ CH ─▶│                          │
  │                                                             │ verify token, re-evaluate│
  │                                                             │ DNS resolve (+addr allow)│
  │                                                             │── SYN ───────────────────▶│
  │◀────────── inner ServerHello … Finished ───────────────────│  (in parallel)           │
  │── inner client Certificate/Verify/Finished ────────────────▶│ cnf == device key? ok    │
  │                                                             │◀── SYN/ACK ──────────────│
  │◀────────── FlowResult(accepted) ────────────────────────────│                          │
  │ inject SYN → local handshake completes for the app          │                          │
  │◀═══════════ app bytes inside inner TLS (E only splices) ═══▶│◀════════ plaintext ═════▶│
  │  FIN/RST ↔ stream FIN/RESET; E and K emit flow events       │                          │
```

**Setup latency:** roughly 1.5 × RTT(C↔K via E) + RTT(K↔app). The app connect overlaps with the inner handshake. The connector speculatively sends the SYN to the app but writes no app data until inner client authentication completes.

**Edge rejects early.** A denied flow never reaches a connector. The edge returns `FlowResult(rejected, rule_id)` and the client RSTs.

**Connector-side extra checks:**
- **Connector-wide deny CIDRs**, on by default: `169.254.0.0/16` (metadata), the connector's own addresses, and loopback.
- Optional per-segment `resolved_address_allow`. This defends against "someone who can create DNS records under `*.corp.example` can pivot to any internal IP".

### 7.4 UDP flows

- The first datagram to a synthetic or CIDR destination creates a UDP flow. A setup stream carries `FlowOpen{proto=udp}` and the inner handshake. Exporter-derived keys then protect datagrams (§3.5).
- Datagrams that don't fit the current QUIC datagram MTU fall back to length-prefixed framing on the flow's stream (reliable and ordered, which is an acceptable degradation).
- Idle timeouts: 60 s default; 5 s for DNS ports.
- ICMP echo to synthetic IPs is answered locally by the client when the segment has `icmp=true` and any connector reports the target healthy. This is a convenience for ping-based monitoring, not real ICMP forwarding.

### 7.5 Edge and transport selection

- The steering config lists candidate edges with region and coordinates.
- The client races QUIC handshakes to the 3 nearest (by geo) and keeps the lowest-RTT one. It re-probes on network change and every 30 min.
- **Transport happy-eyeballs:**
  - QUIC first, with a 250 ms head start over TCP/443 h2.
  - The outcome is cached per network fingerprint (default-gateway MAC + SSID / interface type) so known-blocked networks go straight to TCP.
  - Explicit proxies are honoured on TCP.
- **Roaming:** QUIC connection migration keeps the session and its flows across address changes. On TCP fallback, a network change means reconnecting, and in-flight flows break.

### 7.6 NAT traversal and network realities

- **No NAT traversal is needed by design.** Every party dials out to an edge.
- Keepalives stay below common UDP NAT timeouts (about 30 s).
- PMTUD is enabled (quinn) with a 1200-byte floor.
- On CGNAT: SPA does not bind to source IP for exactly this reason (§3.4).
- **Known limitation:** overlapping IP space across sites works for **FQDN** segments (resolution happens at the right connector group) but is ambiguous for **CIDR** segments. CIDR segments must not overlap, and the compiler enforces it.

### 7.7 Connector selection, load balancing, failover

1. Candidates are connectors in the segment's groups, in the segment's group preference order, that hold a live tunnel to this edge.
2. Filter by app health (if `health_check != none` and recent probes failed, exclude), and by connector state (draining or overloaded).
3. **Power-of-two-choices** on `active_flows` weighted by reported CPU within the top-preference group that has any healthy member. Spill to the next group only when the preferred group is empty.
4. Optional **stickiness** per (user, segment) via a rendezvous hash, for apps that dislike source-IP changes.
5. Failure handling:
   - **Connector dies:** the tunnel idles out within 5–15 s or closes. Flows through it break; TCP state cannot migrate, and we don't pretend otherwise. New flows avoid it immediately.
   - **Connect failure at the connector:** the edge retries once on a different connector if no bytes have been sent yet.

### 7.8 Edge failure and drain

- **Planned drain:** the edge sends `Drain{deadline, alternates}`. Clients pre-connect to an alternate and move *new* flows there. Existing flows are allowed to finish until the deadline (default 10 min).
- **Crash:** the client detects it via the idle timeout and reconnects to the next-best edge. In-flight flows break.
- **Multi-node PoPs:** v1 uses one public IP per edge node, listed separately. Phase 4 adds QUIC-LB-style server IDs in our CIDs so an L4 load balancer or eBPF reuseport program can route migrated connections.

### 7.9 Private edges

- A private edge is the same binary with `kind=private`, deployed on-prem. Connectors in that site also tunnel to it.
- Forwarding rules make on-network clients prefer it, so traffic stays local instead of hairpinning to a public PoP.
- "Arrived on private edge X" is the only network-location fact policy trusts (§4.4).

### 7.10 Performance targets

These are design targets enforced by nightly benchmarks. They are not marketing claims.

| Metric | v1.0 target |
|---|---|
| Edge node (16 vCPU, 25 GbE): aggregate relayed throughput | ≥ 5 Gbps (2 outer AEAD operations per byte; the inner layer passes through) |
| Edge: concurrent client sessions / flows | 50k / 200k |
| Edge: flow setups per second | ≥ 5k/s |
| Edge added latency (relay) | p50 < 1 ms, p99 < 5 ms |
| Policy evaluation (10k segments, 2k rules) | p99 < 10 µs |
| Connector (4 vCPU): aggregate / flow setups (incl. inner TLS) | ≥ 2 Gbps / ≥ 2k/s |
| Single TCP flow end-to-end, 10 ms RTT | ≥ 1 Gbps (Linux client), ≥ 500 Mbps (Windows/macOS), ≥ 300 Mbps (mobile) |
| Policy push: change → acked by all edges | p99 < 5 s |
| Revocation: SCIM deprovision → flows torn down | p99 < 10 s |
| Mobile idle | ≤ 1 radio wake per keepalive interval; no busy timers |

**Design levers:**
- quinn with GSO/GRO;
- multiple connector↔edge connections, sharded across cores;
- `bytes`-based zero-copy splicing in the edge;
- bounded memory: connection-level flow-control windows cap memory per session, and a global edge memory budget triggers backpressure before OOM;
- BBR evaluated against Cubic in benchmarks before choosing a default.

---

## 8. Feature roadmap

**Phase 0: "Proof of tunnel" (MVP)**
- Features:
  - Linux client (daemon + CLI), one edge, connector;
  - control plane with Postgres, OIDC only, JIT groups from claims;
  - FQDN, wildcard and CIDR segments, TCP only;
  - ordered allow/deny rules on users and groups;
  - QUIC transport, built-in CA, device and connector enrollment;
  - **SPA pre-filter**, **double encryption**, held-SYN netstack;
  - flow events to stdout/OTLP;
  - `zoopa-server --role all-in-one` + docker-compose; `zoopactl` covering the API.
- Spikes: quinn DCID/stateless-reset control (§3.4) and smoltcp throughput.
- **Exit criteria:**
  - e2e netns suite (SSH, HTTPS, Postgres, git over the tunnel) green in CI;
  - darkness test passes;
  - single flow ≥ 1 Gbps on LAN with Linux;
  - policy differential tests in place;
  - all initial fuzz targets running;
  - threat model (§9) reviewed by the owner.

**Phase 1: "Small team can run it" (alpha)**
- Features:
  - Windows and macOS clients with the Tauri UI;
  - TCP/443 h2 fallback, proxy support;
  - UDP flows;
  - multi-edge with nearest-edge selection and drain;
  - connector groups with load balancing, failover and health checks;
  - control relay through edges, so the control plane is no longer internet-exposed;
  - SCIM 2.0 (Okta and Entra conformance);
  - timeout and re-auth policies;
  - posture v1 facts;
  - admin UI v1;
  - Log Receivers v1 (syslog/TLS, HTTP JSON, OTLP);
  - Helm chart; deb/rpm packages.
- **Exit criteria:**
  - the project dogfoods it for 30 days for its own infrastructure;
  - chaos suite (edge, connector and Postgres kills) passes the §2.3 invariants;
  - version-skew tests green;
  - external review of the ZTP/SPA specification (crypto-focused).

**Phase 2: "Enterprise identity & clientless" (beta)**
- Features:
  - **Browser access** (ACME, custom domains, delegated tokens);
  - **SAML** (hardened);
  - multiple IdPs;
  - **app discovery** (wildcard observation, then a "promote to segment" UI);
  - **private edges** and forwarding rules;
  - continuous re-evaluation of active flows;
  - dashboards (health, usage, denies, discovery);
  - admin RBAC (super-admin, policy-admin, helpdesk, read-only) and API service accounts;
  - audit-log streaming;
  - **Terraform/OpenTofu provider**;
  - **Kubernetes operator** (CRDs: `ConnectorGroup`, which deploys connectors and handles provisioning automatically, and `AppSegment`, for GitOps-managed segments, optionally derived from annotated `Service`s);
  - connector auto-update (signed, A/B with rollback);
  - iOS and Android clients (alpha).
- **Exit criteria:**
  - at least 3 external design-partner deployments;
  - a documented zero-data-plane-downtime upgrade from the previous minor;
  - Terraform acceptance tests green against a live cluster;
  - SAML XSW test corpus passes.

**Phase 3: "1.0: credible ZPA alternative"**
- Features:
  - **PRA SSH** (russh, xterm.js, asciicast v2 recordings, credential injection from the vault, admin-pinned host keys);
  - **PRA RDP** (IronRDP WASM client; gateway-side RDP proxy with CredSSP credential injection; recording of decrypted PDUs plus input events, replayed by the same WASM client);
  - credential vault (envelope-encrypted; KEK from file, KMS or OpenBao Transit);
  - recordings stored in S3-compatible storage (Garage, MinIO, AWS S3) or the filesystem, encrypted with per-recording DEKs;
  - **posture v2**: hardware-key enforcement, MDM and platform attestation, EDR plugins;
  - device certificates required for access by default;
  - mobile GA;
  - KMS/PKCS#11 for the intermediate CA;
  - performance targets (§7.10) met;
  - API v1, ZTP/1 and the event schema v1 frozen.
- **Exit criteria:**
  - every §1.2 item demonstrably works;
  - published third-party pentest/audit with all high and critical findings fixed;
  - upgrade, backup and restore, and DR runbooks tested;
  - SECURITY.md process exercised at least once (tabletop).
- **Highest-risk item: RDP recording.** Contingency: ship 1.0 with RDP access plus credential injection and mark recording as beta. Do **not** add a second RDP stack such as Guacamole.

**Phase 4: "Parity+ and scale" (post-1.0)**
- **Multi-tenant** mode (MSP; shared edges routed by the SPA tenant discriminator).
- **Edge relay mesh** and on-demand connector tunnels, removing the "connectors reach every edge" limit.
- Multi-node PoPs with CID-routed load balancing.
- **Workload-to-workload segmentation:** connectors act as clients with workload SVIDs, so server-to-server flows cross the fabric under policy.
- Just-in-time access requests and approvals.
- PRA session sharing and live monitoring.
- Inline inspection for browser access (WAF-style, AppProtection-like).
- FIPS build variant.
- ML-DSA / hybrid certificates.
- External CA backends (SPIRE, OpenBao PKI).
- Pull-based directory connectors.
- Server-to-client flows.

---

## 9. Threat model (STRIDE-lite)

### 9.1 Assets and actors

**Assets:**
- access to private apps
- device and connector private keys
- CA and token/bundle signing keys
- user sessions
- policy integrity
- flow and audit logs (which contain PII)
- PRA recordings and vaulted credentials

**Actors:**
- A1: internet attacker / scanner
- A2: on-path network attacker
- A3: malicious or compromised endpoint holding a valid user session
- A4: compromised connector host
- A5: compromised edge host or PoP provider
- A6: malicious or compromised admin
- A7: compromised IdP
- A8: supply-chain attacker

### 9.2 Main flows

**Client ↔ edge**

| STRIDE | Threat | Mitigation |
|---|---|---|
| S | Stolen device credentials | Hardware-bound non-exportable keys. Token bound to the certificate (`cnf`). 15-min tokens. Device revocation in under 5 s |
| T | Tampering with flows in transit | Outer TLS 1.3; inner TLS end-to-end |
| I | Traffic and metadata observation (A2) | Hybrid PQ KEX. SPA tokens are unlinkable across connections. Residual risk: traffic analysis |
| D | Handshake floods (A1) | SPA drops before any crypto. Per-source rate limits. QUIC Retry under load. Volumetric DDoS is out of scope |
| E | Scanner exploits a TLS/QUIC parser bug (A1) | Unreachable without the SPA key on UDP. On TCP only rustls ClientHello parsing is exposed. Fuzzing |

**Edge (A5 compromised)**

| STRIDE | Threat | Mitigation |
|---|---|---|
| I | Reads app payloads | Impossible when double encryption is on (default). With it off, plaintext is exposed: documented, labelled in the UI |
| S/E | Forges flows to apps | The connector re-evaluates policy and requires inner TLS proof of the device key matching the token's `cnf`. **An edge compromise does not grant app access** when double encryption is on. With it off, an edge can replay seen tokens until they expire |
| T | Alters policy | Bundles are signed. The connector evaluates its own copy |
| R | Drops or falsifies flow logs | Connectors emit flow events independently. Mismatches between the two can be detected |
| D | Denies service | Out of scope, mitigated by multiple edges and client failover |
| I | Learns metadata (who accesses what) | Accepted. The edge is the logging point by design |

**Connector (A4 compromised, or rogue enrollment)**

| STRIDE | Threat | Mitigation |
|---|---|---|
| S | Rogue connector enrolled with a stolen provisioning key, then MITMs segment traffic | Provisioning keys are group-scoped, expiring and use-limited. Optional admin approval. New-connector alerts in the audit stream. A connector receives traffic only for its own groups' segments. Clients check group membership in the connector's inner certificate |
| E | Pivot within the app network | Out of our control. Connector deny-CIDRs and `resolved_address_allow` limit misuse of the fabric itself |
| I | Sees plaintext app traffic | Inherent: it is the app-side endpoint |

**Control plane**

| STRIDE | Threat | Mitigation |
|---|---|---|
| S/E | Admin account takeover (A6) | SSO + MFA. Break-glass requires WebAuthn. RBAC. Internal listener not exposed. Audit log streamed off-box in real time (hash-chained entries, phase 2) |
| I | CA key theft | Offline root. Intermediate encrypted with a KEK (KMS/HSM in phase 3). 24 h leaf certificates limit the blast radius. A rotation runbook exists |
| T | Database tampering | Postgres access restricted. Bundles signed at compile time. Admin changes audited |
| D | Control plane outage | Static stability (§2.3) |

**Enrollment & login**
- Authorization-code interception: PKCE plus loopback redirect.
- Enrollment codes are one-time and expire in 5 minutes.
- SCIM bearer tokens are per-IdP, hashed at rest and rotatable.
- SAML XSW: strict profile plus fuzzing (§4.1).

**Gateway** (by design it sees plaintext of browser and PRA sessions)
- Internet-facing HTTP parsing: hyper, fuzzing, request limits.
- Session theft: `__Host-` cookies, per-app origins, 8 h maximum.
- CSRF on the login flow: state and nonce.
- Recordings and vaulted credentials: encrypted with per-object DEKs and access-audited.
- Credential injection means users never see target passwords.

**Supply chain (A8)**
- cargo-vet, cargo-deny, pinned toolchain.
- Signed artifacts, provenance, SBOM.
- Connector auto-update verifies a pinned release key and supports rollback. Admins can disable it or point it at a self-hosted mirror.

### 9.3 What we protect against

- Unauthenticated network exposure of apps and edges.
- Lateral movement through the access layer (no network-level access).
- Credential replay from another device.
- Compromise of an edge leading to app access or payload disclosure (when double encryption is on).
- Harvest-now-decrypt-later attacks on fabric traffic.
- Stale access after deprovisioning.
- Control-plane outages taking down access.

### 9.4 What we explicitly do not protect against

- **Malware on an endpoint that already holds a valid session.** It can use what that user is allowed to use. Least privilege and posture reduce the blast radius but do not prevent this.
- **Posture spoofing** on rooted or jailbroken devices without attestation.
- **A compromised IdP** (A7). It can mint users. We trust it by definition. Mitigation is limited to anomaly visibility in auth logs.
- **A malicious super-admin.** Mitigated only by audit-log export and, later, two-person approval.
- **Compromised app servers, or apps that are vulnerable themselves.**
- **Data exfiltration by authorised users** (no DLP).
- **Traffic analysis and metadata at edges.**
- **Volumetric DDoS.**
- **Side channels on shared edge hosts.**

---

## 10. Deployment & operations

### 10.1 Packaging

**Decision: one server binary as the unit.** Docker Compose and Helm both wrap it.
- `zoopa-server --role {control|edge|gateway|all-in-one}`. The admin UI is embedded.
- `zoopa-connector` ships as a static binary, deb/rpm with systemd unit, container image, Helm chart and operator. VM images (OVA/AMI) come later.
- Container images are multi-arch (amd64/arm64), signed, with SBOM attached.

### 10.2 Topologies

| Topology | For | Shape |
|---|---|---|
| **All-in-one** | Evaluation, homelab, under ~200 users | One VM: `all-in-one` + Postgres (compose). Connectors at sites |
| **Standard** | Production | 2–3 control replicas + HA Postgres in one region (private). Edges as VMs in K PoPs (packages + systemd; best UDP performance). Gateways co-located with edges or separate. Private edges on-prem |
| **Kubernetes** | Teams that want K8s | Helm: control (Deployment), gateway (Deployment), edges (Deployment with a UDP+TCP LoadBalancer per pod, or `hostNetwork` DaemonSet on edge nodes). Postgres via CloudNativePG or a managed service. Connectors via the operator |

### 10.3 Observability

- **OTel everywhere** (`zoopa-telemetry`): OTLP export of traces, metrics and logs, plus a Prometheus `/metrics` endpoint. Health endpoints `/livez` and `/readyz`.
- **Key SLIs:**
  - flow setup latency and failure counts by reason;
  - active sessions and flows;
  - bytes;
  - connector and app health;
  - bundle generation lag per edge/connector;
  - revocation propagation latency;
  - token validation failures;
  - SPA drop counters (counts only; source IPs sampled and rate-limited);
  - certificate seconds-to-expiry;
  - log-receiver spool depth;
  - `control_degraded`.
- **Trace context:** `traceparent` is carried in `FlowOpen` (sampled) so one flow setup can be traced across client, edge and connector. Endpoint tracing is off by default and turned on only in an explicit diagnostics mode, which also produces a redacted support bundle.
- **Product events** (separate from ops logs) have a versioned schema with OCSF mapping:

  | Event type | OCSF class |
  |---|---|
  | `flow` | Network Activity |
  | `auth` | Authentication |
  | `audit` | API Activity |
  | `browser` | HTTP Activity |
  | `pra_session` | — |
  | `connector_status`, `edge_status` | — |
  | `posture` | — |

  Delivery is at-least-once with event IDs for de-duplication.
- Grafana dashboards ship in `deploy/grafana`. Built-in dashboards use Postgres rollups (default retention: 7 days of flow detail, 13 months of rollups). Large deployments use Log Receivers into ClickHouse, OpenSearch or Splunk.

### 10.4 Control-plane HA: Postgres, not embedded Raft

**Decision: stateless control replicas over external PostgreSQL.**
- Operators already know how to run, back up, restore and fail over Postgres (Patroni, CloudNativePG, RDS, Cloud SQL).
- `LISTEN/NOTIFY` gives cross-replica change fan-out.
- Advisory locks handle singleton work: bundle compile, CA rotation, job scheduling. The job queue is `SKIP LOCKED`.
- **Embedded Raft (openraft) rejected:** we would own a consensus implementation, its snapshotting, its membership changes and its disaster recovery, all to save self-hosters one dependency they already understand. The data plane's static stability means control-plane failover time is not on the critical path anyway.
- **SQLite rejected** even for all-in-one: two SQL dialects means two test matrices. The compose file bundles Postgres.

### 10.5 Upgrades

- **Control plane:**
  - rolling restart;
  - **expand/contract migrations only**: every migration must work with the N-1 binary, and destructive steps ship one minor later;
  - `zoopa-server migrate` runs explicitly or automatically under an advisory lock.
- **Edges:** rolling drain (§7.8). The control plane can orchestrate this per pool (`max_unavailable=1`).
- **Connectors:**
  - the control plane publishes a target version per group with a maintenance window;
  - connectors fetch artifacts (served by the control plane or a configured mirror), verify the cosign signature against the pinned release key, and swap A/B;
  - automatic rollback if health checks fail within 5 minutes;
  - one connector per group at a time;
  - can be disabled per group.
- **Clients:** platform-native channels (MDM/Intune/Jamf, MSI/winget, signed pkg, app stores, deb/rpm repos). The control plane reports the version distribution and can enforce a minimum version through policy (a `client_version` posture fact).
- The skew policy is in §6.5.

### 10.6 Keys, backup and DR

- **Postgres PITR** backups contain all state. The CA intermediate inside them is encrypted under the KEK, so **the KEK must be backed up separately**. This is documented prominently.
- The offline root is needed only to re-issue intermediates. The ceremony runbook lives in `docs/ops/`.
- Recordings are in object storage with their own retention and lifecycle settings.
- **DR drill** (required for 1.0): restore Postgres and the KEK into a fresh region. Edges and connectors re-home by DNS/config while serving cached bundles throughout.

### 10.7 Sizing guidance (initial, to be validated by benchmarks)

| Scale | Control | Postgres | Edges | Connectors |
|---|---|---|---|---|
| ≤ 500 users | all-in-one, 4 vCPU | same host | 1 (+1 for HA) | 2 per site |
| ≤ 10k users | 3 × 4 vCPU | HA pair, 8 vCPU | 2 per region × 3 regions, 8–16 vCPU | 2–4 per site, 4 vCPU |
| > 10k users | 3–5 replicas | HA, 16 vCPU | scale by throughput and session targets (§7.10) | scale out horizontally |

---

## 11. Decisions requested from the owner

1. **Licensing:** resolved by the owner (2026-10-26): AGPL-3.0-only server / Apache-2.0 endpoint split with DCO and **no CLA**. This rules out a future dual-license business.
2. **Name and trademark:** the repository is already public; get a legal sanity check of "openzoopa" against Zscaler's "ZPA" mark before releases or broader promotion.
3. **Scope of 1.0:** confirm that **mobile GA** and **RDP via browser** are 1.0 requirements, with RDP *recording* allowed to slip to beta as the contingency.
4. **SAML library risk:** accept samael + xmlsec (C dependency, isolated behind a feature) as the SAML path, with an IdP bridge as the documented fallback.
5. **Postgres-only:** confirm there will be no SQLite and no embedded Raft.
6. **Admin UI in TypeScript/React** rather than Rust/Leptos.
7. **Double encryption on by default:** accept the per-flow handshake cost in exchange for edge-compromise resistance.
8. **Distribution accounts:** an Apple Developer Program account and a Windows code-signing route (SignPath Foundation or owned) are needed by phase 1. They don't affect runtime, but they are project dependencies.
9. **Phase-0 spikes that could change this document:** quinn initial-DCID and stateless-reset control (§3.4), and smoltcp throughput (§7.2). If either fails, this document gets an RFC'd amendment before we build on it.