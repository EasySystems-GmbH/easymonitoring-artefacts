"""TOTP primitives for synology-monitor.

Extracted verbatim (behavior-preserving) from the legacy ``synology-monitor.py``
monolith during Phase 4 Slice C. ``pyotp`` is used when available, with an
internal fallback so DSM deployments do not require an extra pip install.

The only call-site-facing change versus the monolith is that
``_build_totp_uri`` now accepts an ``issuer_name`` argument instead of reading a
module-global ``PRODUCT_NAME``; the entry script passes its ``PRODUCT_NAME`` so
the generated provisioning URI is identical to before.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from typing import Optional, Tuple
from urllib.parse import quote

try:
    import pyotp  # type: ignore[import-not-found]
except Exception:
    pyotp = None

DEFAULT_ISSUER_NAME = "Kuma Monitor Addon"


def _totp_available() -> Tuple[bool, str]:
    # TOTP works with pyotp when available, but we keep an internal fallback
    # so DSM deployments do not require extra pip installation.
    return True, ""


def _generate_totp_secret() -> str:
    if pyotp is not None:
        return str(pyotp.random_base32())
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(alphabet) for _ in range(32))


def _build_totp_uri(
    secret: str,
    account_name: str = "synology-admin",
    issuer_name: str = DEFAULT_ISSUER_NAME,
) -> str:
    if not secret:
        return ""
    if pyotp is not None:
        return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer_name)
    label = quote(f"{issuer_name}:{account_name}")
    issuer = quote(issuer_name)
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def _totp_code_at(secret: str, timestamp: int, period: int = 30) -> Optional[str]:
    try:
        padded = secret.strip().upper() + "=" * (-len(secret.strip()) % 8)
        key = base64.b32decode(padded, casefold=True)
    except Exception:
        return None
    counter = int(timestamp // period)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code_int = (
        ((digest[off] & 0x7F) << 24)
        | ((digest[off + 1] & 0xFF) << 16)
        | ((digest[off + 2] & 0xFF) << 8)
        | (digest[off + 3] & 0xFF)
    )
    return f"{code_int % 1000000:06d}"


def _verify_totp_token(secret: str, token: str) -> bool:
    if not secret:
        return False
    tok = re.sub(r"\s+", "", token or "")
    if not re.match(r"^\d{6}$", tok):
        return False
    if pyotp is not None:
        return bool(pyotp.TOTP(secret).verify(tok, valid_window=1))
    now = int(time.time())
    for window in (-1, 0, 1):
        code = _totp_code_at(secret, now + (window * 30))
        if code and hmac.compare_digest(code, tok):
            return True
    return False
