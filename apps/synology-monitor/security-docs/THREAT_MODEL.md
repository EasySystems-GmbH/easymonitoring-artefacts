# Synology Monitor Threat and Trust Model

## Document Scope

This document describes the threat model and trust model for the current implementation of `synology-monitor` based on:

- `synology-monitor.py`
- `community-package/package/conf/privilege`
- `community-package/package/scripts/*`
- `ARCHITECTURE.md`

Status labels used below:

- `Implemented`: explicit control exists in code/scripts.
- `Partially Implemented`: some controls exist, but important gaps remain.
- `Not Implemented`: no control found.
- `Not Documented`: cannot be confirmed from repo content alone.

## 1.1 Formal Threat Model

Current state: `Partially Implemented`

There is no standalone formal STRIDE/LINDDUN-style threat model file in the repository. A practical threat model can be derived from implementation behavior.

### In-scope attacker classes

- External attacker with network access to port `8787`.
- Authenticated UI user (single-admin model; no separate roles).
- Compromised agent node in peering mode.
- Local attacker with DSM shell access (package user or root).

### Primary attack surfaces

- Web UI endpoints and authentication flow.
- Peer API (`/api/peer/*`) with bearer token and optional mTLS enforcement.
- Runtime files under `/var/packages/synology-monitor/var/`.
- Cron-installed helper scripts and schedules.
- TLS/mTLS certificates under `certs/`.

## 1.2 Critical Assets

Current state: `Implemented` (asset existence), `Not Documented` (asset classification policy)

Critical assets identified from code and package scripts:

- `synology-auth.json` (password hash, TOTP secret, session secret, recovery hashes).
- `synology-monitor.json` (monitor config, peer URLs, peering token).
- `certs/ca.key` (master trust anchor private key).
- Peer/client private keys (`*.key`).
- `peering_token` used for peer API authorization.
- Monitor state/history and cache files used for monitoring decisions.

## 1.3 Trust Boundaries

Current state: `Partially Implemented`

Defined by implementation behavior:

- **Boundary A**: Browser client to UI service over HTTP/HTTPS.
- **Boundary B**: Package user process (`run-as: package`) to root cron helpers.
- **Boundary C**: Local instance to remote peers (`/api/peer/*`) over TLS or token-encrypted HTTP payload.
- **Boundary D**: Application process to runtime filesystem (`/var/packages/.../var`).
- **Boundary E**: Application to external target hosts (Kuma URL, ping/port/DNS probes).

No explicit written trust-boundary document exists in repository.

## 1.4 Abuse-Case Analysis Availability

Current state: `Not Documented`

No dedicated abuse-case analysis document is present in current source tree. Abuse-case analysis is provided in `ABUSE_CASE_MITIGATION_ANALYSIS.md`.

## Threat Assumptions and Non-Goals

- DSM package runtime and host OS hardening are trusted baseline controls.
- Reverse proxy/TLS termination and firewall policy are deployment-dependent.
- Physical host compromise or root compromise can fully defeat file-based secrets.
- This implementation does not provide multi-tenant isolation.

