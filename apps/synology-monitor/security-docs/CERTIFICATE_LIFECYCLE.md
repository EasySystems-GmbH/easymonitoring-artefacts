# Synology Monitor Certificate Lifecycle Documentation

## 4. Cryptography and mTLS Peering

## 4.1 Master CA Generation

Current state: `Implemented`

- Master CA is generated via OpenSSL CLI in `_generate_ca()`:
  - `openssl req -x509 -newkey rsa:2048 -nodes ... -days 3650`
- Subject CN used: `SynologyMonitorCA`.

## 4.2 CA Private Key Storage

Current state: `Implemented` (filesystem storage), `Partially Implemented` (hardening depth)

- Stored at `get_runtime_data_dir()/certs/ca.key`.
- Runtime data dir preference: `/var/packages/synology-monitor/var`, then script dir, then `~/.config/synology-monitor`.
- Key is file-based and not HSM-backed.

## 4.3 Private Key File Permissions

Current state: `Implemented`

- CA and instance private keys are set to `0600`.
- Cert directory is created with mode `0700` in package post-install.

## 4.4 Client Certificate Properties

Current state: `Partially Implemented`

- Unique-per-agent intent: yes (`agent-<sanitized_instance_id>.crt` naming model).
- Revocable: partially, by deleting cert/key/csr files with `_revoke_agent_cert()`.
- Time-limited: yes, but very long (`3650` days).

## 4.5 Revocation Mechanism (CRL/OCSP)

Current state: `Not Implemented`

- No CRL generation/distribution.
- No OCSP responder/integration.
- Revocation is local file deletion only.

## 4.6 Compromised Agent Isolation

Current state: `Partially Implemented`

- Authentication gates:
  - bearer token verification (`peering_token`)
  - mTLS client cert check for most peer endpoints when mTLS is active
- Gaps:
  - shared token model (not per-endpoint scoped)
  - no fine-grained authorization per agent capability
  - `/api/peer/diag` supports token-only access mode

## 4.7 Hostname Validation

Current state: `Not Implemented`

- Client TLS context explicitly sets `check_hostname = False`.
- Trust is CA/cert-chain based, not hostname/SAN enforced.

## Certificate Lifecycle (Implemented Flow)

1. Master generates CA.
2. Master/instance certs are generated and signed by CA.
3. Agent creates CSR and submits to master (`/api/peer/register`).
4. Master signs CSR and returns signed cert and CA cert.
5. Agent stores key/cert/CA locally and uses mTLS for peer traffic.
6. Revocation action deletes local `agent-<id>.*` files.

## Rotation Strategy

Current state: `Not Implemented` (automatic), `Partially Implemented` (manual)

Implemented today:

- Manual regeneration via UI actions (`generate CA`, `generate server cert`, `request cert`).

Recommended operational strategy:

- Rotate CA on compromise or defined lifecycle event.
- Rotate all instance/agent certificates after CA rotation.
- Re-issue per-agent certs, then decommission old certs.
- Force service restart after key/cert changes.
- Track certificate issue/expiry metadata in audit log.

## Backup and Recovery Notes (Crypto Materials)

- Backup includes cert/key files only if runtime data directory is backed up.
- Backup must treat `ca.key` and `*.key` as high-sensitivity secrets.
- If `ca.key` is exfiltrated, full trust reset is required:
  - generate new CA
  - re-issue all certs
  - revoke/decommission old certs and tokens

