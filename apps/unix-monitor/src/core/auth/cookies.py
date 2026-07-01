"""Auth session cookie helpers.

Extracted verbatim (behavior-preserving) from the legacy ``unix-monitor.py``
monolith during Phase 4 Slice C. These helpers build, clear, and parse the HTTP
cookies that carry the HMAC-signed auth session / 2FA-challenge tokens.

They are pure leaf helpers: they depend only on the stdlib ``http.cookies``
module and take the TLS flag explicitly via ``secure=``, so the monolith's
request handler keeps its ``isinstance(self.connection, ssl.SSLSocket)`` check
unchanged at the call site. The cookie/session-TTL protocol constants live here
as the single source of truth and are re-imported by the entry script, so all
existing references keep working unchanged.
"""

from __future__ import annotations

from http import cookies as _http_cookies
from typing import Dict

# Cookie / session-token protocol constants (single source of truth;
# re-imported by the entry script so existing call sites are unchanged).
AUTH_COOKIE_NAME = "unix_auth"
AUTH_CHALLENGE_COOKIE_NAME = "unix_auth_challenge"
AUTH_SESSION_TTL_SEC = 1800
AUTH_CHALLENGE_TTL_SEC = 300


def build_cookie_header(name: str, value: str, max_age: int, *, secure: bool = False) -> str:
    morsel = _http_cookies.SimpleCookie()
    morsel[name] = value
    morsel[name]["path"] = "/"
    morsel[name]["httponly"] = True
    morsel[name]["samesite"] = "Lax"
    morsel[name]["max-age"] = str(max_age)
    if secure:
        morsel[name]["secure"] = True
    return morsel.output(header="").strip()


def clear_cookie_header(name: str, *, secure: bool = False) -> str:
    return build_cookie_header(name, "", 0, secure=secure)


def parse_cookie_header(raw: str) -> Dict[str, str]:
    if not raw:
        return {}
    parsed = _http_cookies.SimpleCookie()
    try:
        parsed.load(raw)
    except Exception:
        return {}
    out: Dict[str, str] = {}
    for k, m in parsed.items():
        out[k] = m.value
    return out


__all__ = [
    "AUTH_COOKIE_NAME",
    "AUTH_CHALLENGE_COOKIE_NAME",
    "AUTH_SESSION_TTL_SEC",
    "AUTH_CHALLENGE_TTL_SEC",
    "build_cookie_header",
    "clear_cookie_header",
    "parse_cookie_header",
]
