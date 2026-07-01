"""mTLS-aware peer HTTP transport (``_peer_http_request``).

Extracted verbatim (behavior-preserving) from the legacy ``unix-monitor.py``
monolith during Phase 4 Slice C. This is the low-level peer transport: it
builds the request path, selects an HTTP/HTTPS connection, loads the local
mTLS cert chain (client-auth) when present, applies the token-payload
encryption safety net over plain HTTP, and decrypts wrapped responses.

It composes the already-extracted pure peering leaves:

* path build / classify — :mod:`.http`
  (``_peer_request_path`` / ``_is_peer_register_path`` / ``_is_peer_api_path``)
* mTLS cert *paths* — :mod:`.certs` (``_get_mtls_cert_paths``)
* payload crypto — :mod:`.crypto` (``_encrypt_payload`` / ``_decrypt_payload``)

Two monolith-owned dependencies are not pure leaves: ``load_config`` (config
persistence) and ``append_ui_log`` (UI log append). Rather than change every
call site, the entry script injects them once via :func:`configure` at
startup; the public ``_peer_http_request`` signature is identical to the
monolith version so all existing call sites keep working unchanged.

The network-touching resolvers that *call* this transport
(``_resolve_peer_url`` / ``_resolve_peer_url_from_stored`` /
``_peer_master_base_url``) live in :mod:`.resolvers`; they consume
``_peer_http_request`` from here (single source).
"""

from __future__ import annotations

import http.client
import json
import ssl
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse

from .certs import _get_mtls_cert_paths
from .crypto import _decrypt_payload, _encrypt_payload
from .http import _is_peer_api_path, _is_peer_register_path, _peer_request_path

# Injected by the entry script so the transport reads config and appends to the
# UI log exactly like the monolith does.
_load_config_provider: Optional[Callable[[], Dict[str, Any]]] = None
_append_ui_log_provider: Optional[Callable[[str], None]] = None


def configure(
    *,
    load_config: Callable[[], Dict[str, Any]],
    append_ui_log: Callable[[str], None],
) -> None:
    """Inject the monolith-owned config loader + UI logger. Call once at startup."""
    global _load_config_provider, _append_ui_log_provider
    _load_config_provider = load_config
    _append_ui_log_provider = append_ui_log


def _peer_http_request(url: str, token: str, method: str = "GET",
                       path_override: str = "", payload: Optional[Dict[str, Any]] = None,
                       timeout: int = 10) -> Tuple[int, str]:
    """Low-level HTTP request to a peer instance. Returns (status_code, body_text)."""
    if _load_config_provider is None or _append_ui_log_provider is None:
        raise RuntimeError("peering.transport.configure() must be called before use")
    load_config = _load_config_provider
    append_ui_log = _append_ui_log_provider
    url = url.strip().rstrip("/")
    endpoint = url + (path_override or "/api/peer/health")
    parsed = urlparse(endpoint)
    req_path = _peer_request_path(url, path_override)
    is_register = _is_peer_register_path(req_path)
    is_peer_api = _is_peer_api_path(req_path)
    if parsed.scheme == "https":
        cfg = load_config()
        cert_path, key_path, ca_path = _get_mtls_cert_paths(cfg)
        if cert_path and key_path and ca_path:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ctx.load_verify_locations(ca_path)
            ctx.load_cert_chain(cert_path, key_path)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            # Bootstrap path before certificates exist.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if not is_register:
                append_ui_log("mtls | HTTPS request without local certs (token fallback)")
        conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=timeout)
    headers: Dict[str, str] = {"Authorization": f"Bearer {token}"}
    body_bytes: Optional[bytes] = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        if parsed.scheme != "https" and is_peer_api:
            plaintext = json.dumps(payload)
            body_bytes = json.dumps({"enc": _encrypt_payload(plaintext, token)}).encode("utf-8")
            headers["X-Peer-Encrypted"] = "1"
        else:
            body_bytes = json.dumps(payload).encode("utf-8")
    conn.request(method, req_path, body=body_bytes, headers=headers)
    resp = conn.getresponse()
    resp_raw = resp.read().decode("utf-8", errors="ignore")[:64000]
    resp_body = resp_raw
    if parsed.scheme != "https" and is_peer_api and resp_raw:
        try:
            wrapped = json.loads(resp_raw)
            if isinstance(wrapped, dict) and isinstance(wrapped.get("enc"), str):
                dec = _decrypt_payload(str(wrapped.get("enc", "")), token)
                if dec is not None:
                    resp_body = dec
        except (json.JSONDecodeError, ValueError):
            pass
    status = resp.status
    conn.close()
    return status, resp_body
