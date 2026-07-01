"""Pure peer-HTTP request/response helpers (no mTLS).

Extracted verbatim (behavior-preserving) from the legacy ``unix-monitor.py``
monolith during Phase 4 Slice C. These helpers build the request *path* for a
peer call and classify it, and parse a peer/master HTTP *error* response body.
They operate only on plain strings and the standard library: no network I/O,
no TLS/mTLS context, no config persistence, and no module-global runtime
state.

The mTLS-aware transport itself (``_peer_http_request`` — TLS context, cert
loading, token-payload encryption) and the network-touching resolvers
(``_resolve_peer_url`` / ``_peer_master_base_url``) intentionally stay in the
monolith until that network layer is itself extractable. Call-site signatures
are unchanged versus the monolith.
"""

from __future__ import annotations

import json
from typing import Tuple
from urllib.parse import urlparse


def _peer_request_path(url: str, path_override: str = "") -> str:
    """Build the request path (incl. query) for a peer HTTP call.

    Joins the base ``url`` with ``path_override`` (defaulting to the peer
    health endpoint), parses it, and re-appends the query string. Mirrors the
    path logic embedded in the monolith's ``_peer_http_request``.
    """
    url = url.strip().rstrip("/")
    endpoint = url + (path_override or "/api/peer/health")
    parsed = urlparse(endpoint)
    req_path = parsed.path or path_override or "/api/peer/health"
    if parsed.query:
        req_path += "?" + parsed.query
    return req_path


def _is_peer_register_path(req_path: str) -> bool:
    return req_path.startswith("/api/peer/register")


def _is_peer_api_path(req_path: str) -> bool:
    return req_path.startswith("/api/peer/")


def _peer_error_detail(body: str) -> Tuple[str, str]:
    try:
        data = json.loads(body)
        detail = data.get("detail")
        if isinstance(detail, dict):
            return str(detail.get("errorCode", "") or ""), str(detail.get("message", "") or "")
        if isinstance(detail, str):
            return "", detail
    except (json.JSONDecodeError, ValueError, TypeError):
        pass
    return "", str(body or "")[:300]
