"""Password hashing helpers.

Extracted verbatim (behavior-preserving) from the legacy ``synology-monitor.py``
monolith during Phase 4 Slice C. Prefers ``werkzeug.security`` when available
and otherwise falls back to a self-contained PBKDF2-SHA256 implementation so the
monitor keeps working without the optional dependency.

The public names (:func:`generate_password_hash`, :func:`check_password_hash`)
match the monolith's exactly, so existing call sites keep working unchanged.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

try:
    from werkzeug.security import (  # type: ignore[import-not-found]
        check_password_hash,
        generate_password_hash,
    )
except Exception:
    def generate_password_hash(password: str) -> str:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200000).hex()
        return f"pbkdf2_sha256${salt}${digest}"

    def check_password_hash(stored: str, password: str) -> bool:
        try:
            alg, salt, digest = stored.split("$", 2)
            if alg != "pbkdf2_sha256":
                return False
            test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200000).hex()
            return hmac.compare_digest(test, digest)
        except Exception:
            return False


__all__ = [
    "generate_password_hash",
    "check_password_hash",
]
