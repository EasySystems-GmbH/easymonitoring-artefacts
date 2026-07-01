"""Peering helpers extracted from the ``synology-monitor.py`` monolith.

Phase 4 Slice C. Exposes the pure peer instance-id / dedupe / monitor-field
helpers (``instances``) and the pure peer URL / port parsing & formatting
helpers (``urls``) — none hold runtime state or write config. Heavier peering
logic that depends on certs / mTLS / network I/O / config persistence remains
in the entry script for now.
"""

from .instances import (
    _is_valid_peer_instance_id,
    _display_peer_instance_id,
    _normalize_peer_instance_id_key,
    _dedupe_peers_by_instance_id,
    _registered_peer_instance_ids,
    _is_legacy_peer,
    _peer_monitor_name,
    _peer_monitor_mode,
)
from .urls import (
    PEER_DEFAULT_PORT,
    _normalize_peer_port,
    _peer_master_port,
    _peer_agent_port,
    _parse_peer_host_port,
    _peer_url_for_input_display,
    _peer_url_for_open,
    _peer_scheme_probe_order,
    _cached_peer_base_url,
    _peer_direct_base_url,
    _peer_lan_reachability_hint,
)
from .http import (
    _peer_request_path,
    _is_peer_register_path,
    _is_peer_api_path,
    _peer_error_detail,
)
from .certs import (
    configure as configure_certs,
    get_certs_dir,
    _get_mtls_cert_paths,
    _list_signed_agents,
)
from .crypto import (
    configure as configure_crypto,
    _derive_aes_key,
    _encrypt_payload,
    _decrypt_payload,
)
from .transport import (
    configure as configure_transport,
    _peer_http_request,
)
from .resolvers import (
    _resolve_peer_url,
    _resolve_peer_url_from_stored,
    _peer_master_base_url,
)

__all__ = [
    "_is_valid_peer_instance_id",
    "_display_peer_instance_id",
    "_normalize_peer_instance_id_key",
    "_dedupe_peers_by_instance_id",
    "_registered_peer_instance_ids",
    "_is_legacy_peer",
    "_peer_monitor_name",
    "_peer_monitor_mode",
    "PEER_DEFAULT_PORT",
    "_normalize_peer_port",
    "_peer_master_port",
    "_peer_agent_port",
    "_parse_peer_host_port",
    "_peer_url_for_input_display",
    "_peer_url_for_open",
    "_peer_scheme_probe_order",
    "_cached_peer_base_url",
    "_peer_direct_base_url",
    "_peer_lan_reachability_hint",
    "_peer_request_path",
    "_is_peer_register_path",
    "_is_peer_api_path",
    "_peer_error_detail",
    "configure_certs",
    "get_certs_dir",
    "_get_mtls_cert_paths",
    "_list_signed_agents",
    "configure_crypto",
    "_derive_aes_key",
    "_encrypt_payload",
    "_decrypt_payload",
    "configure_transport",
    "_peer_http_request",
    "_resolve_peer_url",
    "_resolve_peer_url_from_stored",
    "_peer_master_base_url",
]
