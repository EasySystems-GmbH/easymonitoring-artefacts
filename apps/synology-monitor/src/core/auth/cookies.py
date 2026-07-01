"""Auth session-cookie helpers for synology-monitor.

Extracted (behavior-preserving) from the legacy ``synology-monitor.py``
monolith during Phase 4 Slice C. The cookie build/clear/parse logic previously
lived inline on the HTTP request-handler class (``_cookie_header`` /
``_clear_cookie_header`` / ``_parse_cookies``). Those methods now delegate to
the pure helpers below; the only per-request value they still own is the
``secure`` flag (derived from the live TLS socket), which is passed in here so
this module stays free of request/handler state.

The unix-monitor monolith carries the same inline cookie methods but has no
``cookies.py`` boundary yet, so there is no existing peer module to mirror; this
slice establishes the boundary on synology first and unix can mirror it later.
"""

from __future__ import annotations

from http import cookies as _http_cookies
from typing import Dict

# Cookie / session-token protocol constants (single source of truth;
# re-imported by the entry script so existing call sites are unchanged).
AUTH_COOKIE_NAME = "synology_auth"
AUTH_CHALLENGE_COOKIE_NAME = "synology_auth_challenge"
AUTH_SESSION_TTL_SEC = 1800
AUTH_CHALLENGE_TTL_SEC = 300


def build_cookie_header(name: str, value: str, max_age: int, *, secure: bool = False) -> str:
    """Return a ``Set-Cookie`` header value for a session cookie.

    Mirrors the monolith's ``_cookie_header``: HttpOnly, ``SameSite=Lax``,
    path ``/``, explicit ``Max-Age``, and ``Secure`` only when served over TLS.
    """
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
    """Return a ``Set-Cookie`` header value that expires the named cookie."""
    return build_cookie_header(name, "", 0, secure=secure)


def parse_cookie_header(raw: str) -> Dict[str, str]:
    """Parse a raw ``Cookie`` request header into a ``name -> value`` mapping.

    Returns an empty dict for missing or malformed headers, matching the
    monolith's ``_parse_cookies`` behavior.
    """
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
