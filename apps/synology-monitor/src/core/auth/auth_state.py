"""Authentication state / session / lockout / recovery helpers.

Extracted verbatim (behavior-preserving) from the legacy ``synology-monitor.py``
monolith during Phase 4 Slice C, mirroring the unix-monitor ``auth_state`` module
boundary. These functions cover the persisted auth state file
(``synology-auth.json``), pending-setup handling, login lockout, recovery codes,
and the HMAC-signed session/challenge payloads.

The monolith owns a few runtime values these helpers depend on
(``get_runtime_data_dir``, ``PRODUCT_NAME`` and the auth tuning constants).
Rather than change every call site, the entry script injects them once via
:func:`configure` at startup; the public function signatures are identical to
the monolith versions so all existing call sites keep working unchanged.

Synology-specific deltas versus unix (preserved on purpose):
- the auth state file is ``synology-auth.json`` (tmp ``.synology-auth.json.tmp``);
- ``_load_auth_state`` keeps the lighter synology behavior (no default-key
  backfill loop) and only repairs a missing ``session_secret``;
- ``_append_login_event`` is retained (synology tracks login history here).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .totp import _build_totp_uri, _generate_totp_secret

try:
    import qrcode  # type: ignore[import-not-found]
except Exception:
    qrcode = None

DEFAULT_PRODUCT_NAME = "Kuma Monitor Addon"

# Synology-specific auth state filename (kept identical to the monolith).
AUTH_STATE_FILENAME = "synology-auth.json"

# Tuning constants; defaults mirror the monolith. ``configure()`` overrides
# these with the entry script's canonical values at startup.
AUTH_FILE_MODE = 0o600
AUTH_MAX_LOGIN_ATTEMPTS = 5
AUTH_LOCKOUT_DURATION_SEC = 15 * 60
PRODUCT_NAME = DEFAULT_PRODUCT_NAME

# Injected by the entry script so the auth state file resolves to the same
# runtime data directory the monolith uses.
_runtime_data_dir_provider: Optional[Callable[[], Path]] = None


def configure(
    *,
    runtime_data_dir_provider: Callable[[], Path],
    product_name: str = DEFAULT_PRODUCT_NAME,
    auth_file_mode: int = 0o600,
    max_login_attempts: int = 5,
    lockout_duration_sec: int = 15 * 60,
) -> None:
    """Wire the entry-script runtime dependencies into this module.

    Must be called once before any auth-state helper is invoked. The entry
    script passes its own ``get_runtime_data_dir``, ``PRODUCT_NAME`` and
    ``AUTH_*`` constants so behavior is identical to the monolith.
    """
    global _runtime_data_dir_provider, PRODUCT_NAME
    global AUTH_FILE_MODE, AUTH_MAX_LOGIN_ATTEMPTS, AUTH_LOCKOUT_DURATION_SEC
    _runtime_data_dir_provider = runtime_data_dir_provider
    PRODUCT_NAME = product_name
    AUTH_FILE_MODE = auth_file_mode
    AUTH_MAX_LOGIN_ATTEMPTS = max_login_attempts
    AUTH_LOCKOUT_DURATION_SEC = lockout_duration_sec


def get_auth_state_path() -> Path:
    if _runtime_data_dir_provider is None:
        raise RuntimeError("auth_state.configure() must be called before use")
    return _runtime_data_dir_provider() / AUTH_STATE_FILENAME


def _default_auth_state() -> Dict[str, Any]:
    return {
        "auth_initialized": False,
        "password_hash": "",
        "totp_secret": "",
        "recovery_hashes": [],
        "failed_attempts": 0,
        "lockout_until": 0,
        "session_secret": secrets.token_hex(32),
        "last_login_ip": "",
        "last_login_at": 0,
        "login_history": [],
    }


def _load_auth_state() -> Dict[str, Any]:
    p = get_auth_state_path()
    if not p.exists():
        data = _default_auth_state()
        _save_auth_state(data)
        return data
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("auth state invalid")
    except Exception:
        data = _default_auth_state()
        _save_auth_state(data)
    if "session_secret" not in data or not str(data.get("session_secret", "")).strip():
        data["session_secret"] = secrets.token_hex(32)
        _save_auth_state(data)
    return data


def _save_auth_state(data: Dict[str, Any]) -> None:
    p = get_auth_state_path()
    tmp = p.parent / ".synology-auth.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, AUTH_FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(str(tmp), str(p))
        p.chmod(AUTH_FILE_MODE)
    except OSError:
        pass


def _hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode("utf-8")).hexdigest()


def _generate_recovery_codes(count: int = 10) -> List[str]:
    out = []
    for _ in range(count):
        raw = secrets.token_hex(4).upper()
        out.append(f"{raw[:4]}-{raw[4:]}")
    return out


def _issue_recovery_hashes(codes: List[str]) -> List[Dict[str, Any]]:
    return [{"hash": _hash_recovery_code(c), "used": False} for c in codes]


def _build_qr_data_uri(uri: str) -> str:
    if not uri or qrcode is None:
        return ""
    qr = qrcode.QRCode(version=1, box_size=8, border=3)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


_PENDING_AUTH_SETUPS: Dict[str, Dict[str, Any]] = {}
_PENDING_SETUP_TTL_SEC = 600


def _purge_pending_setups() -> None:
    now = int(time.time())
    stale = [key for key, row in _PENDING_AUTH_SETUPS.items() if int(row.get("exp", 0) or 0) < now]
    for key in stale:
        _PENDING_AUTH_SETUPS.pop(key, None)


def _create_pending_setup(password: str) -> Dict[str, Any]:
    _purge_pending_setups()
    setup_id = secrets.token_urlsafe(16)
    totp_secret = _generate_totp_secret()
    recovery_codes = _generate_recovery_codes()
    uri = _build_totp_uri(totp_secret, issuer_name=PRODUCT_NAME)
    qr_data_uri = _build_qr_data_uri(uri)
    _PENDING_AUTH_SETUPS[setup_id] = {
        "exp": int(time.time()) + _PENDING_SETUP_TTL_SEC,
        "password": password,
        "totp_secret": totp_secret,
        "recovery_codes": recovery_codes,
        "qr_data_uri": qr_data_uri,
    }
    return {
        "setup_id": setup_id,
        "totp_secret": totp_secret,
        "qr_data_uri": qr_data_uri,
    }


def _get_pending_setup(setup_id: str) -> Optional[Dict[str, Any]]:
    _purge_pending_setups()
    key = str(setup_id or "").strip()
    if not key:
        return None
    row = _PENDING_AUTH_SETUPS.get(key)
    if not row:
        return None
    if int(row.get("exp", 0) or 0) < int(time.time()):
        _PENDING_AUTH_SETUPS.pop(key, None)
        return None
    return row


def _pop_pending_setup(setup_id: str) -> Optional[Dict[str, Any]]:
    row = _get_pending_setup(setup_id)
    if row:
        _PENDING_AUTH_SETUPS.pop(str(setup_id).strip(), None)
    return row


def _is_locked(auth: Dict[str, Any]) -> Tuple[bool, int]:
    now = int(time.time())
    until = int(auth.get("lockout_until", 0) or 0)
    if until > now:
        return True, max(0, until - now)
    return False, 0


def _register_auth_failure(auth: Dict[str, Any]) -> None:
    attempts = int(auth.get("failed_attempts", 0) or 0) + 1
    auth["failed_attempts"] = attempts
    if attempts >= AUTH_MAX_LOGIN_ATTEMPTS:
        auth["lockout_until"] = int(time.time()) + AUTH_LOCKOUT_DURATION_SEC
        auth["failed_attempts"] = 0
    _save_auth_state(auth)


def _format_lock_wait(wait_sec: int) -> str:
    total = max(0, int(wait_sec or 0))
    mins, secs = divmod(total, 60)
    return f"{mins}m {secs}s" if mins > 0 else f"{max(1, secs)}s"


def _lockout_message(wait_sec: int) -> str:
    until_ts = int(time.time()) + max(0, int(wait_sec or 0))
    until_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(until_ts))
    return (
        f"Account temporarily locked after repeated failed sign-in attempts. "
        f"Try again in {_format_lock_wait(wait_sec)} (until about {until_text})."
    )


def _invalid_password_message(auth: Dict[str, Any]) -> str:
    attempts = int(auth.get("failed_attempts", 0) or 0)
    remaining = max(0, int(AUTH_MAX_LOGIN_ATTEMPTS) - attempts)
    if remaining <= 0:
        locked, wait_sec = _is_locked(auth)
        if locked:
            return _lockout_message(wait_sec)
        return "Account temporarily locked after repeated failed sign-in attempts."
    return (
        f"Invalid password. {remaining} attempt(s) remaining before a "
        f"{int(AUTH_LOCKOUT_DURATION_SEC // 60)}-minute lock."
    )


def _register_auth_success(auth: Dict[str, Any]) -> None:
    auth["failed_attempts"] = 0
    auth["lockout_until"] = 0
    _save_auth_state(auth)


def _append_login_event(auth: Dict[str, Any], ip: str, state: str) -> None:
    events = auth.get("login_history", [])
    if not isinstance(events, list):
        events = []
    events.append({"ts": int(time.time()), "ip": str(ip or "unknown"), "state": str(state or "unknown")})
    auth["login_history"] = events[-20:]


def _sign_payload(payload: Dict[str, Any], secret: str) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    sig = hmac.new(secret.encode("utf-8"), b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def _verify_signed_payload(token: str, secret: str) -> Optional[Dict[str, Any]]:
    try:
        b64, sig = token.split(".", 1)
    except ValueError:
        return None
    expected = hmac.new(secret.encode("utf-8"), b64.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        padded = b64 + "=" * (-len(b64) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    exp = int(data.get("exp", 0) or 0)
    if exp and exp < int(time.time()):
        return None
    return data


def _auth_initialized(auth: Optional[Dict[str, Any]] = None) -> bool:
    state = auth or _load_auth_state()
    return bool(state.get("auth_initialized")) and bool(state.get("password_hash")) and bool(state.get("totp_secret"))


def _consume_recovery_code(auth: Dict[str, Any], code: str) -> bool:
    target = _hash_recovery_code(code)
    hashes = auth.get("recovery_hashes", [])
    if not isinstance(hashes, list):
        return False
    for row in hashes:
        if not isinstance(row, dict):
            continue
        if bool(row.get("used")):
            continue
        if hmac.compare_digest(str(row.get("hash", "")), target):
            row["used"] = True
            _save_auth_state(auth)
            return True
    return False


def _count_unused_recovery(auth: Dict[str, Any]) -> int:
    hashes = auth.get("recovery_hashes", [])
    if not isinstance(hashes, list):
        return 0
    return len([x for x in hashes if isinstance(x, dict) and not bool(x.get("used"))])
