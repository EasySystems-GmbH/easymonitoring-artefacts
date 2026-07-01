"""Network-touching peer URL resolvers.

Extracted verbatim (behavior-preserving) from the legacy ``unix-monitor.py``
monolith. These resolvers probe a peer's health endpoint to discover a working
base URL (scheme + host + port) and construct the master base URL, applying the
scheme-probe order and LAN-reachability-hint policy.

They were previously parked in the monolith because they were assumed to need
config persistence / UI logging. In practice they do **not**: they receive the
``cfg`` dict from the caller (mutating only that passed-in dict — e.g.
``cfg["peer_master_base_url"] = resolved`` — never calling ``load_config`` /
``save_config`` / ``append_ui_log``), and their only non-pure dependency is the
mTLS-aware ``_peer_http_request`` transport, which is configured independently
via :func:`peering.transport.configure`. Because that transport is imported here
as a live module-level reference (its providers are read at call time), no
``configure()`` injection shim is required for this module.

Composes the already-extracted leaves:

* pure URL helpers — :mod:`.urls` (``PEER_DEFAULT_PORT`` /
  ``_parse_peer_host_port`` / ``_peer_master_port`` / ``_peer_scheme_probe_order``
  / ``_cached_peer_base_url`` / ``_peer_direct_base_url`` /
  ``_peer_lan_reachability_hint``)
* mTLS transport — :mod:`.transport` (``_peer_http_request``)

Call-site signatures are identical to the monolith versions so all existing
callers keep working unchanged.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from .transport import _peer_http_request
from .urls import (
    PEER_DEFAULT_PORT,
    _cached_peer_base_url,
    _parse_peer_host_port,
    _peer_direct_base_url,
    _peer_lan_reachability_hint,
    _peer_master_port,
    _peer_scheme_probe_order,
)


def _resolve_peer_url(
    host: str,
    port: int,
    token: str,
    timeout: int = 5,
    cfg: Optional[Dict[str, Any]] = None,
) -> str:
    """Probe master health and return a working base URL (e.g. http://host:port)."""
    if not host:
        return ""
    probe_timeout = min(max(timeout, 2), 4)
    if cfg is not None:
        cached = _cached_peer_base_url(cfg, host, port)
        if cached:
            try:
                status, _ = _peer_http_request(cached, token, "GET", "/api/peer/health", timeout=min(probe_timeout, 3))
                if status < 500:
                    return cached
            except Exception:
                pass
    for scheme in _peer_scheme_probe_order(port):
        base = f"{scheme}://{host}:{port}"
        try:
            status, _ = _peer_http_request(base, token, "GET", "/api/peer/health", timeout=probe_timeout)
            if status < 500:
                resolved = base.rstrip("/")
                if cfg is not None:
                    cfg["peer_master_base_url"] = resolved
                return resolved
        except Exception:
            continue
    return ""


def _resolve_peer_url_from_stored(
    url_or_host: str,
    token: str,
    timeout: int = 5,
    cfg: Optional[Dict[str, Any]] = None,
    default_port: int = PEER_DEFAULT_PORT,
) -> str:
    """Parse stored url (host, host:port, or full URL) and resolve to working scheme. Returns base URL."""
    host, port = _parse_peer_host_port(url_or_host, default_port)
    if not host:
        return ""
    return _resolve_peer_url(host, port, token, timeout, cfg)


def _peer_master_base_url(cfg: Dict[str, Any], timeout: int = 4) -> Tuple[str, str]:
    """Resolve or construct the master base URL. Returns (url, error_message)."""
    master_host, master_port = _parse_peer_host_port(
        cfg.get("peer_master_url", ""), _peer_master_port(cfg)
    )
    token = str(cfg.get("peering_token", "") or "").strip()
    if not master_host or not token:
        return "", "Missing master host or peering token."
    resolved = _resolve_peer_url(master_host, master_port, token, timeout=timeout, cfg=cfg)
    if resolved:
        return resolved, ""
    direct = _peer_direct_base_url(f"{master_host}:{master_port}", master_port)
    if direct:
        return direct, ""
    return "", (
        f"Cannot reach master at {master_host}:{master_port}. "
        + _peer_lan_reachability_hint(master_host, master_port)
    )
