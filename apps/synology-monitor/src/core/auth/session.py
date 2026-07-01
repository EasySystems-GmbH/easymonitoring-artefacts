"""Auth session/state persistence + lockout helpers for synology-monitor.

Extracted verbatim (behavior-preserving) from the legacy ``synology-monitor.py``
monolith during Phase 4 Slice C, mirroring the unix-monitor auth-state boundary
(``get_auth_state_path`` / ``_load_auth_state`` / ``_save_auth_state`` /
``_register_auth_*`` / lockout messaging / ``_append_login_event`` /
``_auth_initialized``).

These helpers depend on a few values that live in the entry script: the runtime
data directory, the auth-file permission mode, and the login lockout policy
constants. Rather than thread them through every (many) call site and change
public signatures, the entry script calls :func:`configure` once at import time.
The function names and signatures are therefore identical to the monolith
originals, so existing call sites are unchanged.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

# Synology-specific auth state filename (kept identical to the monolith).
AUTH_STATE_FILENAME = "synology-auth.json"

# --- injected configuration (set once via configure()) ---------------------
_RUNTIME_DATA_DIR_PROVIDER: Optional[Callable[[], Path]] = None
_AUTH_FILE_MODE = 0o600
_AUTH_MAX_LOGIN_ATTEMPTS = 5
_AUTH_LOCKOUT_DURATION_SEC = 15 * 60


def configure(
    *,
    runtime_data_dir_provider: Callable[[], Path],
    auth_file_mode: int,
    max_login_attempts: int,
    lockout_duration_sec: int,
) -> None:
    """Wire the entry-script runtime dependencies into this module.

    Must be called once before any auth-state helper is invoked. The entry
    script passes its own ``get_runtime_data_dir`` and ``AUTH_*`` constants so
    behavior is identical to the monolith.
    """
    global _RUNTIME_DATA_DIR_PROVIDER, _AUTH_FILE_MODE
    global _AUTH_MAX_LOGIN_ATTEMPTS, _AUTH_LOCKOUT_DURATION_SEC
    _RUNTIME_DATA_DIR_PROVIDER = runtime_data_dir_provider
    _AUTH_FILE_MODE = auth_file_mode
    _AUTH_MAX_LOGIN_ATTEMPTS = max_login_attempts
    _AUTH_LOCKOUT_DURATION_SEC = lockout_duration_sec


def get_auth_state_path() -> Path:
    if _RUNTIME_DATA_DIR_PROVIDER is None:
        raise RuntimeError("session.configure() must be called before use")
    return _RUNTIME_DATA_DIR_PROVIDER() / AUTH_STATE_FILENAME


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
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _AUTH_FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(str(tmp), str(p))
        p.chmod(_AUTH_FILE_MODE)
    except OSError:
        pass


def _register_auth_failure(auth: Dict[str, Any]) -> None:
    attempts = int(auth.get("failed_attempts", 0) or 0) + 1
    auth["failed_attempts"] = attempts
    if attempts >= _AUTH_MAX_LOGIN_ATTEMPTS:
        auth["lockout_until"] = int(time.time()) + _AUTH_LOCKOUT_DURATION_SEC
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


def _auth_initialized(auth: Optional[Dict[str, Any]] = None) -> bool:
    state = auth or _load_auth_state()
    return bool(state.get("auth_initialized")) and bool(state.get("password_hash")) and bool(state.get("totp_secret"))
