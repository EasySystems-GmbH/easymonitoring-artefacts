# Synology Monitor Backup and Recovery Guidance

## 11. Backup and Recovery

## 11.1 Are Cryptographic Materials Backed Up?

Current state: `Not Documented` (policy), `Partially Implemented` (technical possibility)

- Cryptographic assets are file-based in runtime storage (`certs/`, auth/config JSON).
- They are backup-capable if runtime directories are included in system backup scope.
- No explicit backup policy file in repository defines mandatory inclusion/exclusion.

## 11.2 How Are Crypto Materials Protected in Backup?

Current state: `Not Documented`

- Repository does not define backup encryption, key wrapping, or secret segregation policy.
- Operational recommendation:
  - encrypt backups at rest and in transit
  - restrict restore permissions
  - segment backup access from runtime operators

## 11.3 Recovery Process After Key Compromise

Current state: `Partially Implemented` (manual controls exist)

Available controls:

- CA and cert regeneration functions in UI and backend.
- Agent certificate revocation by file removal.
- Token and auth secret updates through settings/auth actions.

Recommended formal runbook:

1. Contain incident (disable peer sync if needed, isolate affected nodes).
2. Generate new CA and server/instance certs.
3. Re-issue all agent certificates.
4. Rotate peering token and invalidate old credentials.
5. Rotate admin password, TOTP secret, recovery codes.
6. Restore trusted configuration/state from known-good backup where needed.
7. Validate peer trust, monitor outputs, and audit logs before return to normal operation.

## Backup Scope Recommendation

Include:

- `synology-monitor.json`
- `synology-auth.json` (treat as highly sensitive)
- `certs/` (including `ca.key` and private keys)
- selected state/history files if operationally required

Exclude or separately protect:

- helper logs and UI logs unless needed for forensic retention

## Recovery Validation Checklist

- UI login and TOTP enrollment verified.
- Peer endpoints reject old certs/tokens.
- New cert chain and fingerprints documented.
- Monitor checks and Kuma push behavior validated.

