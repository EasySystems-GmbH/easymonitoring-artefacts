# Synology Monitor Abuse-Case Mitigation Analysis

## 10. Abuse Case Review

This analysis focuses on current implementation controls and operational mitigations.

## A. Attacker Gains Web UI Access

### Impact

- Full control of monitor definitions, credentials in config paths, peer settings, and dangerous actions (restart/reset).
- Ability to manipulate monitoring outputs and push state.

### Detection Capability

- `synology-monitor-ui.log` records many admin/security operations.
- Helper and scheduler logs provide additional context.
- No dedicated SIEM integration or tamper-evident audit trail.

### Mitigation

- Password + TOTP + recovery flow and login lockout.
- Session cookies are signed and `HttpOnly`.
- Recommended: enable reverse proxy HTTPS, add CSRF controls, add IP restrictions.

### Recovery Process

1. Rotate UI password and TOTP secret.
2. Regenerate recovery codes.
3. Rotate peering token.
4. Review logs for malicious actions and restore known-good config backup.
5. Re-issue peer certs if compromise spread suspected.

## B. Attacker Gains Limited DSM Shell Access

### Impact

- If attacker can read `synology-auth.json`, they can obtain TOTP secret/session secret.
- If attacker can modify config/state files, they can alter monitor and peer behavior.

### Detection Capability

- Some abnormal behavior appears in UI/helper logs.
- No file-integrity monitoring for runtime files.

### Mitigation

- Restrictive file permissions (`0600` on config/auth and keys).
- Keep package user privileges minimal.
- Recommended: host hardening, file integrity monitoring, immutable/protected backups.

### Recovery Process

1. Assume local secrets exposed.
2. Rotate password, TOTP secret, recovery codes, peering token.
3. Revoke and re-issue certificates.
4. Restore runtime files from trusted backup.

## C. Agent Node Compromise

### Impact

- Compromised agent can push falsified status to master if valid token/cert retained.
- Potential lateral data exposure through peer APIs depending on deployed trust settings.

### Detection Capability

- Peer sync and push events are logged.
- Manual diagnostics can compare expected vs observed agent behavior.
- No built-in anomaly detection.

### Mitigation

- Token verification and optional mTLS client cert checks.
- Manual certificate revocation support.
- Recommended: per-agent scoped tokens/permissions, strict mTLS requirement for all peer APIs.

### Recovery Process

1. Revoke compromised agent certificate.
2. Rotate peering token (global) and issue new agent cert.
3. Remove/disable compromised agent entry from master until rebuilt.
4. Re-baseline trust after forensic review.

## D. JSON State Files Are Modified

### Impact

- False health states, altered monitor settings, manipulated peer metadata.
- Potential operational blindness or alert suppression.

### Detection Capability

- Indirect detection via inconsistent UI output and logs.
- No cryptographic integrity or tamper detection on JSON files.

### Mitigation

- Atomic writes reduce corruption risk but not malicious tampering.
- File permission controls reduce write surface.
- Recommended: add signatures/HMAC, filesystem integrity monitoring, restricted ownership model.

### Recovery Process

1. Stop service and preserve artifacts for review.
2. Restore config/auth/state from trusted backup snapshot.
3. Rotate sensitive secrets if auth/config files were touched.
4. Restart service and validate expected monitor behavior.

## E. CA Private Key Is Exfiltrated

### Impact

- Complete mTLS trust compromise: attacker can mint trusted peer certs.
- Potential long-lived unauthorized peer access due to 10-year cert defaults.

### Detection Capability

- No direct key exfiltration detection in app.
- Detection depends on host monitoring and anomaly review.

### Mitigation

- File mode `0600` and cert directory `0700`.
- Recommended: key custody hardening, shorter cert lifetimes, formal key-rotation playbook, optional HSM/secure enclave.

### Recovery Process

1. Generate a new CA immediately.
2. Re-issue all instance and agent certificates.
3. Revoke/decommission old certs and rotate peer tokens.
4. Validate all peer trust relationships before resuming normal sync.

