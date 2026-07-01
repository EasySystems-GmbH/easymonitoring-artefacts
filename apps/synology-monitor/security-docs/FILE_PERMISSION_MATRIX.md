# Synology Monitor File Permission Matrix

## Scope

Matrix based on `synology-monitor.py` and package install scripts.

## File/Directory Permission Table

| Path / Pattern | Purpose | Mode in Code/Scripts | Writable By | Notes |
|---|---|---|---|---|
| `/var/packages/synology-monitor/var/synology-monitor.json` | Main config | `0600` | service user (`package`) | Enforced by `CONFIG_FILE_MODE`. |
| `/var/packages/synology-monitor/var/synology-auth.json` | Auth state | `0600` | service user (`package`) | Includes password hash, TOTP secret, session secret. |
| `/var/packages/synology-monitor/var/synology-monitor-ui.log` | UI operational log | `0600` (runtime enforcement) | service user (`package`) | No dedicated rotation logic in code. |
| `/var/packages/synology-monitor/var/synology-smart-cache.json` | SMART cache | `0644` | root helper and service user | Root helper writes; UI/scheduler reads. |
| `/var/packages/synology-monitor/var/synology-backup-cache.json` | Backup cache | `0644` | root helper and service user | Root helper writes; UI/scheduler reads. |
| `/var/packages/synology-monitor/var/synology-system-log-cache.json` | System log cache | `0644` | root helper and service user | Root helper writes; UI reads. |
| `/var/packages/synology-monitor/var/synology-monitor-state.json` | Last monitor state | `0644` | service user (and root if run as root path) | Atomic replace pattern used. |
| `/var/packages/synology-monitor/var/synology-monitor-history.json` | Monitor history | `0644` | service user (and root if run as root path) | Atomic replace pattern used. |
| `/var/packages/synology-monitor/var/synology-task-status.json` | Task status | `0644` | service user/root path | Diagnostic data. |
| `/var/packages/synology-monitor/var/synology-schedule-state.json` | Scheduler timing state | `0644` | service user/root path | Diagnostic/scheduling state. |
| `/var/packages/synology-monitor/var/peers/*.json` | Cached peer snapshots | `0644` | service user | Contains remote monitor data. |
| `/var/packages/synology-monitor/var/certs/` | Certificate store directory | `0700` (postinst) | package install/runtime owner | Created in `postinst`. |
| `/var/packages/synology-monitor/var/certs/ca.key` | Master CA private key | `0600` | service user with file access | High-value secret. |
| `/var/packages/synology-monitor/var/certs/*.key` | Instance/agent private keys | `0600` | service user with file access | Key compromise impacts mTLS trust. |
| `/var/packages/synology-monitor/var/certs/*.crt` | CA and cert chain files | `0644` | service user | Public cert material. |
| `/var/packages/synology-monitor/target/smart-helper.sh` | Root helper launcher | `0700` | root (postinst sets mode) | No immutability/integrity check. |
| `/var/packages/synology-monitor/target/backup-helper.sh` | Root helper launcher | `0700` | root (postinst sets mode) | No immutability/integrity check. |
| `/var/packages/synology-monitor/target/system-log-helper.sh` | Root helper launcher | `0700` | root (postinst sets mode) | No immutability/integrity check. |
| `/var/packages/synology-monitor/target/monitor-scheduler.sh` | Scheduled monitor launcher | `0700` | root (postinst sets mode) | Runs one-shot scheduled checks. |
| `/var/packages/synology-monitor/target/*.log` | Helper/service logs | `0644` | root or service user depending writer | Includes helper and scheduler logs. |

## Storage Integrity Controls

Current state: `Partially Implemented`

- Atomic write pattern (`tmp` + `os.replace`) is used for config/auth/state/cache files.
- No file locking (`flock`) is used around write/read operations.
- No HMAC/signature/checksum validation for local JSON state files.
- No immutable bit or startup integrity attestations for helper scripts or config files.

## Sensitive Data at Rest

Current state: `Partially Implemented`

- Passwords are hashed, not plaintext.
- TOTP secret and session secret are stored in plaintext JSON (file-level protection only).
- Peering token is stored in config JSON (file-level protection only).
- mTLS private keys are plaintext key files protected by filesystem mode.

