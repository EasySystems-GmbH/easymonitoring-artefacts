"""Signed session / 2FA-challenge token helpers.

Extracted verbatim (behavior-preserving) from the legacy ``unix-monitor.py``
monolith during Phase 4 Slice C. These functions build and validate the
HMAC-signed browser cookies that gate the operator UI:

* the post-login **session** token (``{"auth": True, "exp": ...}``), and
* the interstitial **2FA challenge** token (``{"step": "2fa", "exp": ...}``).

The signing/verification primitives and the per-install ``session_secret`` live
in :mod:`src.core.auth.auth_state`; the cookie TTLs live in
:mod:`src.core.auth.cookies`. These helpers are pure: they take the session
secret (and, for issuance, an optional clock) as arguments and never touch the
request handler, module globals, or persisted state. The request-handler
methods (``_is_authenticated`` / ``_has_valid_challenge``) read the cookie from
the live request and delegate here, so their signatures are unchanged.
"""

from __future__ import annotations

import time
from typing import Optional

from .auth_state import _sign_payload, _verify_signed_payload
from .cookies import AUTH_SESSION_TTL_SEC, AUTH_CHALLENGE_TTL_SEC


def issue_session_token(
    session_secret: str,
    ttl_sec: int = AUTH_SESSION_TTL_SEC,
    now: Optional[int] = None,
) -> str:
    """Return a signed authenticated-session token (``{"auth": True}``)."""
    issued_at = int(time.time()) if now is None else int(now)
    return _sign_payload({"auth": True, "exp": issued_at + ttl_sec}, session_secret)


def issue_challenge_token(
    session_secret: str,
    ttl_sec: int = AUTH_CHALLENGE_TTL_SEC,
    now: Optional[int] = None,
) -> str:
    """Return a signed pending-2FA challenge token (``{"step": "2fa"}``)."""
    issued_at = int(time.time()) if now is None else int(now)
    return _sign_payload({"step": "2fa", "exp": issued_at + ttl_sec}, session_secret)


def session_token_valid(token: str, session_secret: str) -> bool:
    """True iff ``token`` is a valid, unexpired authenticated-session token."""
    if not token:
        return False
    payload = _verify_signed_payload(token, session_secret)
    if not payload:
        return False
    return bool(payload.get("auth") is True)


def challenge_token_valid(token: str, session_secret: str) -> bool:
    """True iff ``token`` is a valid, unexpired pending-2FA challenge token."""
    if not token:
        return False
    payload = _verify_signed_payload(token, session_secret)
    if not payload:
        return False
    return payload.get("step") == "2fa"
