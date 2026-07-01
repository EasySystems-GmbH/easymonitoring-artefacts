# Synology Monitor Storage, Network, Input, and Logging Security

## 5. Data Storage and Integrity

### 5.1 JSON under `/var/packages/...`

Current state: `Implemented` (paths and modes), `Partially Implemented` (ownership documentation)

- Runtime JSON files are stored under `get_runtime_data_dir()`; package-first target is `/var/packages/synology-monitor/var`.
- Config/auth files are set to `0600`.
- State/cache/peer JSON files are set to `0644`.
- Root helpers write cache files; package process reads them.

### 5.2 Sensitive Files Encrypted at Rest

Current state: `Partially Implemented`

- `synology-auth.json`: not encrypted at rest (password hash protected, TOTP/session secrets plaintext).
- Push tokens and peering token in config JSON: not encrypted at rest.
- Certificate private keys: stored as plaintext key files, filesystem mode protected.

### 5.3 Atomic File Writes

Current state: `Implemented`

- Most writes use temporary file + `os.replace`.
- No file locking is implemented.

### 5.4 Integrity Validation

Current state: `Not Implemented`

- No HMAC/signature/checksum protection for local JSON config/state files.

### 5.5 Unauthorized Monitor State Modification

Current state: `Partially Implemented`

- UI mutations require authenticated session.
- Any local user/process with sufficient filesystem write access can still modify JSON state directly.

## 6. Network Exposure

### 6.1 Web UI Bind Interface

Current state: `Implemented`

- Default bind is `0.0.0.0`.
- Package service script starts UI with `--host 0.0.0.0 --port 8787`.

### 6.2 TLS Termination Model

Current state: `Partially Implemented`

- App can run with its own TLS when certs are present.
- Documentation also expects DSM reverse proxy for browser HTTPS in many deployments.

### 6.3 Plaintext HTTP

Current state: `Partially Implemented`

- Dual protocol listener accepts HTTP and HTTPS on same port.
- HTTP requests are redirected to HTTPS when TLS active, with specific exceptions.

### 6.4 Application Rate Limits

Current state: `Partially Implemented`

- Login lockout exists.
- No broad per-IP/per-endpoint rate limiter for entire application or peer API.

### 6.5 SSRF, Host Header Injection, Open Redirect

Current state: `Partially Implemented`

- **SSRF**: no allowlist/blocklist for outbound targets (`probe_host`, `dns_server`, peer URL, Kuma URL).
- **Host header injection/open redirect**: HTTP->HTTPS redirect uses request `Host` header to construct redirect URL.
- **Open redirects**: no generic user-controlled redirect parameter flow, but host-based redirect behavior exists.

### 6.6 Internal Network Scanning via Monitor Definitions

Current state: `Implemented` (feature behavior), `Not Implemented` (restrictive policy)

- Ping/port/dns checks can target user-provided internal hosts and ports.
- No policy-level restrictions preventing internal network probing by authorized users.

## Network Security Posture Description

- Exposed service defaults to all interfaces (`0.0.0.0:8787`).
- Security relies on strong local auth, optional TLS, optional reverse proxy, and network segmentation/firewall.
- Peer APIs use token and optional mTLS client cert checks but lack granular authorization and hostname validation.

## 7. Input Validation and Injection Safety

### 7.1 Hostname Validation

Current state: `Partially Implemented`

- Required/non-empty checks for relevant fields.
- No strict hostname/IP allowlist, denylist, or canonicalization policy.

### 7.2 Port Range Validation

Current state: `Implemented`

- Port probes enforce valid range `1..65535` in UI save path and probe function.

### 7.3 Shell Argument Safety

Current state: `Partially Implemented`

- Most subprocess calls are list-based and avoid shell parsing.
- One explicit shell call exists for restart operation (`sh -c`).

### 7.4 DNS Check Injection Safety

Current state: `Implemented` (command invocation style), `Partially Implemented` (input policy)

- `nslookup` invoked with list args, not shell interpolation.
- No strict domain-format or resolver-target policy.

### 7.5 Centralized Validation Logic

Current state: `Partially Implemented`

- Some reusable validation exists (e.g., Kuma URL validation).
- Validation is not fully centralized across all input classes.

## Code-Level Mitigation Summary

- Positive controls:
  - list-based subprocess calls for most operations
  - URL scheme/path validation for Kuma push URL
  - port bounds enforcement
  - auth gating for UI mutating endpoints
- Gaps:
  - missing CSRF
  - partial input normalization and SSRF hardening
  - one shell invocation path

## 8. Logging and Information Disclosure

### 8.1 What is Logged

- `synology-monitor-ui.log` records auth events, monitor actions, peer sync events, helper status lines, and errors.
- Helper logs under `target/*.log` contain helper execution output.

### 8.2 Secret Logging

Current state: `Partially Implemented`

- Public export endpoint intentionally excludes sensitive auth fields.
- No formal redaction framework is present; log content depends on emitted messages.

### 8.3 Stack Traces in Web UI

Current state: `Partially Implemented`

- Many exceptions are caught and converted to error messages.
- Some error responses include exception type/message strings, but full Python tracebacks are not intentionally rendered.

### 8.4 Log Read Access

Current state: `Partially Implemented`

- UI diagnostics are session-auth protected.
- File-level read access depends on OS ownership/permissions and where logs are stored.

### 8.5 Log Rotation

Current state: `Not Implemented`

- No dedicated rotation/retention mechanism for UI/helper logs in current code.

## Logging Policy (Current + Recommended)

Current implementation policy (inferred):

- Operational and security-significant events are appended to local logs.
- Logs are used for diagnostics and troubleshooting.

Recommended enhancements:

- Define max retention and rotation policy.
- Add sensitive-field redaction guardrails.
- Add explicit audit event categories and severity tagging.

