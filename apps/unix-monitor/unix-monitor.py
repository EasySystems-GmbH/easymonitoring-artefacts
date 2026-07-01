#!/usr/bin/env python3

#########################################
# Author: Konrad von Burg               #
# Date: 2026-02-19                      #
# Description: Interactive menu script  #
# to monitor Unix host storage and   #
# SMART health and report to Kuma.      #
# Version: 1.0.0                        #
# Copyright (c) 2026 EasySystems GmbH   #
#                                       #
# Usage:                                #
#   python3 unix-monitor.py         #
#   python3 unix-monitor.py --run   #
#   python3 unix-monitor.py --run -d
#########################################

from __future__ import annotations

import sys as _sys

if _sys.version_info < (3, 8):
    print("ERROR: Python 3.8 or newer is required.", file=_sys.stderr)
    _sys.exit(1)

import http.client
import html
import json
import os
import base64
import cProfile
import hashlib
import hmac
import pstats
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timedelta
import platform
import warnings
from io import BytesIO, StringIO
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse
try:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning, module="cgi")
        import cgi  # type: ignore[import-not-found]
except Exception:
    cgi = None
try:
    import pyotp  # type: ignore[import-not-found]
except Exception:
    pyotp = None
try:
    import qrcode  # type: ignore[import-not-found]
except Exception:
    qrcode = None
# --- Phase 4 Slice C: helpers extracted from this monolith -----------------
# Make the colocated ``src/`` package importable when the script is run
# directly (``python3 unix-monitor.py``). These modules ship in the install
# tree next to this file (see web_render for the graceful single-file fallback).
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from src.core.auth.totp import (  # noqa: E402
    _build_totp_uri,
    _generate_totp_secret,
    _totp_available,
    _totp_code_at,
    _verify_totp_token,
)
from src.core.auth.password import (  # noqa: E402
    check_password_hash,
    generate_password_hash,
)
from src.core.auth.cookies import (  # noqa: E402
    AUTH_COOKIE_NAME,
    AUTH_CHALLENGE_COOKIE_NAME,
    AUTH_SESSION_TTL_SEC,
    AUTH_CHALLENGE_TTL_SEC,
    build_cookie_header,
    clear_cookie_header,
    parse_cookie_header,
)
from src.core.auth.sessions import (  # noqa: E402
    issue_session_token,
    issue_challenge_token,
    session_token_valid,
    challenge_token_valid,
)
from src.core.auth import auth_state as _auth_state  # noqa: E402
from src.core.auth.auth_state import (  # noqa: E402
    get_auth_state_path,
    _default_auth_state,
    _load_auth_state,
    _save_auth_state,
    _hash_recovery_code,
    _generate_recovery_codes,
    _issue_recovery_hashes,
    _build_qr_data_uri,
    _purge_pending_setups,
    _create_pending_setup,
    _get_pending_setup,
    _pop_pending_setup,
    _is_locked,
    _register_auth_failure,
    _format_lock_wait,
    _lockout_message,
    _invalid_password_message,
    _register_auth_success,
    _auth_initialized,
    _consume_recovery_code,
    _count_unused_recovery,
)
from src import web_render  # noqa: E402
from src.core.peering.instances import (  # noqa: E402
    _is_valid_peer_instance_id,
    _display_peer_instance_id,
    _normalize_peer_instance_id_key,
    _dedupe_peers_by_instance_id,
    _registered_peer_instance_ids,
    _is_legacy_peer,
    _peer_monitor_name,
    _peer_monitor_mode,
)
from src.core.peering.urls import (  # noqa: E402
    PEER_DEFAULT_PORT,
    _normalize_peer_port,
    _peer_master_port,
    _peer_agent_port,
    _parse_peer_host_port,
    _peer_url_for_input_display,
    _peer_url_for_open,
    _peer_direct_base_url,
    _peer_lan_reachability_hint,
)
from src.core.peering.http import (  # noqa: E402
    _peer_request_path,
    _is_peer_register_path,
    _is_peer_api_path,
    _peer_error_detail,
)
from src.core.peering import certs as _peer_certs  # noqa: E402
from src.core.peering.certs import (  # noqa: E402
    get_certs_dir,
    _get_mtls_cert_paths,
    _list_signed_agents,
)
from src.core.peering import crypto as _peer_crypto  # noqa: E402
from src.core.peering.crypto import (  # noqa: E402
    _derive_aes_key,
    _encrypt_payload,
    _decrypt_payload,
)
from src.core.peering import transport as _peer_transport  # noqa: E402
from src.core.peering.transport import (  # noqa: E402
    _peer_http_request,
)
from src.core.peering.resolvers import (  # noqa: E402
    _resolve_peer_url,
    _resolve_peer_url_from_stored,
    _peer_master_base_url,
)
from src.core.security import backup_crypto as _backup_crypto  # noqa: E402
from src.core.security.backup_crypto import (  # noqa: E402
    BACKUP_SALT,
    _derive_backup_key,
    _encrypt_backup,
    _decrypt_backup,
)


VERSION = "1.14.0-0004"
CONFIG_FILE_MODE = 0o600
CRON_MARKER = "# unix-monitor.py - do not edit this line manually"
INTERVAL_MIN = 1
INTERVAL_MAX = 1440
CHECK_MODES = ("mount", "smart", "storage", "ping", "port", "dns", "backup", "service")
PEER_ROLES_ALL = ("standalone", "agent", "master")
PEER_ROLES = PEER_ROLES_ALL
# Set True only in rollout-agent distribution builds (agent-only edition).
ROLLOUT_AGENT_BUILD = False
PEER_HEALTH_TIMEOUT_SEC = 75


def _rollout_agent_mode() -> bool:
    if ROLLOUT_AGENT_BUILD:
        return True
    env = os.environ.get("ESYS_ROLLOUT_AGENT", "").strip().lower()
    return env in ("1", "true", "yes", "on")


def _default_peer_role() -> str:
    return "agent" if _rollout_agent_mode() else "standalone"


def _peer_roles() -> Tuple[str, ...]:
    return ("agent",) if _rollout_agent_mode() else PEER_ROLES_ALL


def _cfg_peer_role(cfg: Dict[str, Any]) -> str:
    role = str(cfg.get("peer_role", _default_peer_role()) or _default_peer_role()).strip().lower()
    if _rollout_agent_mode():
        return "agent"
    return role if role in PEER_ROLES_ALL else _default_peer_role()


def _enforce_rollout_agent_config(cfg: Dict[str, Any]) -> bool:
    if not _rollout_agent_mode():
        return False
    if str(cfg.get("peer_role", "") or "").lower() != "agent":
        cfg["peer_role"] = "agent"
        return True
    return False
# Agent pushes to master on this interval (config override: peer_agent_push_interval_sec).
PEER_AGENT_PUSH_DEFAULT_INTERVAL_SEC = 60
BACK_KEYS = ("0", "b", "back", "q", "quit")
CHANGES_NOTICE = "  Changes are not saved until you confirm (Save/Apply)."
ALLOWED_SCHEMES = ("https", "http")
KUMA_PUSH_PATH_PATTERN = re.compile(r"^/api/push/[A-Za-z0-9_-]+$")
UI_LOG_MAX_LINES = 200
UI_LOG_DISPLAY_LINES = 100
_UI_LOG_STATS_CACHE: Dict[str, Any] = {"key": None, "value": (0, 0)}
UI_LOG_MSG_MAX_CHARS = 6000
LOG_LINE_TS_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}")
NAS_VOLUME_PATTERN = re.compile(r"^/volume[0-9]+$")
SMART_CACHE_MAX_AGE_SEC = 20 * 60
BACKUP_CACHE_MAX_AGE_SEC = 20 * 60
DEFAULT_INTERNET_CHECK_TARGETS: List[Tuple[str, int]] = [("1.1.1.1", 53), ("8.8.8.8", 53), ("9.9.9.9", 53)]
DEFAULT_INTERNET_CHECK_DNS_SERVERS: List[Tuple[str, int]] = [("1.1.1.1", 53), ("8.8.8.8", 53)]
INTERNET_CHECK_PORT_PROFILES = ("dns", "http", "https", "custom", "from-target")
TASK_STATUS_MAX_DETAIL = 2000
HISTORY_MAX_ENTRIES = 500
AUTH_FILE_MODE = 0o600
# AUTH_COOKIE_NAME / AUTH_CHALLENGE_COOKIE_NAME / AUTH_SESSION_TTL_SEC /
# AUTH_CHALLENGE_TTL_SEC now live in src/core/auth/cookies.py (imported above).
AUTH_MAX_LOGIN_ATTEMPTS = 5
AUTH_LOCKOUT_DURATION_SEC = 15 * 60
SYSTEM_LABEL = (platform.uname().system or platform.system() or "Unix").strip()
BRAND_NAME = "EasySystems GmbH"
PRODUCT_NAME = f"{SYSTEM_LABEL} Kuma Monitor Addon"
BRAND_URL = "https://www.easysystems.ch/de"
BRAND_LOGO_URL = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAABLcAAAHpCAMAAABHmi4cAAAAM1BMVEUAAAAtLHAtLHAtLHAtLHAtLHAtLHAtLHAtLHAtLHAtLHAtLHAtLHAtLHAtLHAtLHAtLHBxDoEgAAAAEHRSTlMAQIAQwPCgYOAg0DBwULCQI8EyEwAAIv1JREFUeNrs3ItuGkEMBdDNsgMbIHD//2tLqVDThvCIEHikcz7CGtt3PAAAAAAAwKOtxrcBoCNTknm7GAA6sclRW74PAF0YczJ9DAAdmPLXvNIuAvXlH23ULgLFveV/y80AUNg2X01yEUBh+5wzrwaAoqacIdEFFLbOd9qocgEV5YK2t1wE6sllUvRAOYnKBfQlUbmAviQqF9CXROUC+pKoXEBfWlQuoC9T7rCXRAVeb5kzZOiBwsbcp40DwEu95QK3IoCKcr/ZfS7glaZc47IgUMs2nwhFAB14zw9ZLQK3K9Ao/ta2A8ArrPKHAT3QjTk/NxlzAbeo8+Dy9we4TaUHV9LkUIHrSj24pLmAmxRZKZ4sNYvANUUyXDIRwO1KhOY/W2sWgafa5chmEejGYs6RzSLQjU3LiRgq0IdNHsI5VOCKQikufxaBa6oWLvN54HlWLQ/RPgaA71Qczh/sPLmAJ9mscyASAXRkscuBSATwi717yVEchgIoWsSxyYfA2/9qe9BSS9AUgcKkYumcDTCzYnOf3ZIu/jKyCDTjMPjkAhqTLj65gNZU/OTyxyKwjdRFaLmAtozn0HIBjam2WcwmFoGtnLKJRaAxqUQd0/wFsI1DH+7lAhpzzCJUoDHpoogAWjP2jueB1iyD43mgManLBhaBxoxn9TzQmjoB/WCvCDy0x4DeXhFYtbeA3l4RWLO7gN5eEVi3t4Decz/Aqr0F9MVeEVizt4B+Mq8IrNlbQG9eEXjGvgJ6d9sAb5uX7txP8U/u+9Ith+8Ceq/9AL8pLZc+vjOcu8PdgF4QAfyS8dTHqr6b6wf0WRABvC4dp3hSLkv1gP7yBfCSseR4RS6Hm83iZOoHqKv+1M5wSjcBvdsEgY3MffxQGa8Deg/DAlsYS7yhjNcroKttgPv2dJdWGSsG9OUL4LF5qj0bnbp4x+R0HnjoFFXk7jqgdzoPfEg6Ry3T4TqgdzoPfMI8xJWaj7l22WWCQHVLjit1ZwzHop0HKjtGdd1NQO8WVKCmS3xAn24SC38rAtWUWFHlPpp08bcisO9lKyIfa40QZQsX8Fy2Vf3S5ePg3nlgj0fyD0Z1UqeHAN40x2eV/58r82AG8I4xx4r6z1wsgzFr4OemqG+9YuiykAvYU7j1xHfSeBZyAT+yxCbK3efKLFzA61KObZR7P95buPjD3t3tNAzDYBjOT8PSrl2++79aGGISAiHRpjDLeZ9z0I4sx/UPYKfh9FdNDHkhcAHYKer/bOG7SI0LwE5VXfoHdSYCFwBDjfK/iTYr6yEAmCzK/1ybj9z5AbBHUqf+2nxkBSoAw+mWVObwRWTpPAAj22t+MH1P+djHBcDmx8SH9bzfUKnNA8PZ9ARlPu+D5i0AGMxNz7Dk81borAHAUGZ16g9c89KdvAEYyao+/acyLkWdlgBgJIueprYtXlrVJyxuBmD2mfgVL0UANkcT/8wUAAzjJh9omwfGUeRDofsUGMVVXlCaB0bhpLx1R2keGESTG4z7AIOY5EcMAEbgpSxPLwQwDnlCwgWMIMoTEi5gBL7iFgkXMIJVrpBwAQNI2mlqpgeDSLgA/5L2KC28yesiq0i4AP+S9qmXcBdfZBQJF+Beko5Frtlo5OJ+NeBe0n5LtBy5mFIEvEs6ouVwFy3WuUi4AO+SDqnx8ef2sIcLcC7poBbeXe2lXOzhApxLvecPs7kqF4tPAedWHVauRjcPcr0a8C3quBI/3orGduHUAMCzqB4Xm4GL0z6Ab6dEiGyrOk/CBfhWPQYuhn0A1yZ1KVeLT0WmqwHXkjwGLhIuwLNNnZb8+EeGMOwDeDar183i6lR6TwHP6ml9npYWodIKAXj2ol5lDu9ylRktAPBrU7fJ3nEgvigCnuUTJwKbrCBuAa4t561gyGaaIYhbgGuv7N1bcuMgEIVhQFwESKj3v9qZJE7FM76BwCnF+b8F6PFUg5ruTfp5dbDZENxvAS9tHTnV3cox8D8ReG0ygD/Y1Tz9W8BrK8cruJwt5t1mE/3yAC4sxyq40rZGdS4vxUkTxzIy4MXFoVPdrfSYl6iuWb1jUjOAL0kGWAZc8xetbppCcZwSAYw8KKbuB48lqgfWLdEDAeBNlBFy30SvpFWNaTXWyR0zs7eAXyGNbPWMz9/WOunFFDvLBVdo3AJ+iSADzB0pmLLaJ+tz/EYEfo9JRoi7r8s22kQBtPIj39ZkaeO4kQLQTssAft8fxUKxBWCPWfrNe6o3tyoA2COMfMwcKLYAPN/kBm4tzBRbAO44yv7Xf3qwKLYAXHPAgmtTJ5ZiC8Awcd3801ohrDrxFFsARpi0KbNImp72SNHWHzpnii0Ad8W3yHpU5mzSy6mTQIM8gJ7E2qx88U+94apsY000yAO4Iupgim2aqGe+J7ecUQBwJur19jIJ3/1LsT+3CkMbALzTOhhjreuaXxxG5dbEVD8AV+X3sPLWulGj+dKg3FIcEQF80H8txphirX3KCmc9Krc4IgI/QjRGv8mqm/4QTptP37jv2Ty/jcmtyBER+Bnif+tJZ9tGnip8w2uf+U7d5thpCBxUDsY6OaCg6qzSwd7OLUOjKXBok16MTXIgDU+YyzNyy3OxBfwMUS+mHKL6clk9kkecFM31DlbLxRbw02QdzGatDDM+tqKXdcBJcVEnhut44EVErY3Zev8Njo+t6EVknvr/KerL+Vsze1iBV5G1/ujDmqVPf2xF/9/Qvyl1t28lUgt4bdOpm7SmTWv4JujoL6ul7GSXpD6RWsAvE796Tkt1Z9d8I/LSVJla5yfFtXNMsya1AJxl2r+y+uTbY0uXi9zpuuJa1YkhtQA8NLXHlra3g0eVnvWJylpSC8ADU2qNrZDkkpt67uat+kSXKYBHcmrbmDMt88PocdKKB4gAqmXXNCUwbk5uMecfbUSVBaBWkJbY0l7uWXfP4ioKAOosLbEVUn2XaiC3ADyFr4+taJw8lKa9wWU5KAKoMJXqUfJrkSq2ck8GowEBDOx/kHDtD2Itvzu4xGYFAPdkVxdb2kuLrT64mGsKoImuiq1oZmkU2oOLwTUAKgSpiK1QZIeg2vq4GG+KP+zdW3LjIBRFUd4gEOjOf7Td7f5JIseOjFCq8F6DOMXjcgB+wjyvki+3CdNBwcVX+gAOCs/mr5Y19f3/c+itIh9hAHjC5sexZXf7w57gCnJc4GoRwEfL49iqTfrFrzP5nHMBeF3xD2KrBi+nWHdXl0elle0igJvq5a5cOkLryVsh6+QlmegC8P38Q47By6mC3d9fHpe2SnYB722TS+wLU0uSl6WwctoFvCsbpEPf54t2ky6pmUp6AW/HZrlYVB/oJN2SC6Zqdo7AuyhZrpW3oj4xXk7induM0VrzEhuYWfFyJXfvLnBpMoD7x/xFhRcwl+jlMr5Fq+7TWQZyCsA8VrlK3rR6JCYZRwGYRpBL+BYXtXNdcgUFYBK2yQWc0Wrn0uTynNIDs7BZRstbteqImOVsiZpnYBolSa/+zNrTQc7kqHgG5lG8jONMxwTVYpKcw1PYBcwkyiAprEX10sFLt8ZSC5iKkQG8M9WqM/RXfrXIqRYwlzAishZ1Mr3lF5d8VQGYi3VyIheMtmqQJYZ8MLMiz6uB+dgs53DN1KKGs9q09LM1H2WCwJyKl17ZmfXq1hgdTXBJ7kmumUgFBDCv6uWQfUAs6jcVrfVq/lu11pQGAtOLcpxzzRhNLR+ADsNjy7tbVplKAx+AX1f0TTU7Vd8wYQ4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwB/27mw9VRiMwnDmiQDr/q92H+yhfXYjEiIY4nrPa6mxnyDyQ0RERERERERERERERERERPQS0QkiohuJDhBERLcRHcBuEfVs8moxCf8k49QcxceSDmC36C/5Ch/8/3SGeTUos0uexAeSBmC36AteQQl6Ee0XbAvrp71NSAOwW8Ru9WpyFjsYLz6HNwC7RexWr6TBXuFTyuUDwG4Ru9WryaBGmMX4fADYLWK3eqVX1FoG/5xL+wCwW8RudWsKqGfH3uWSALtF7Fa/Mo5ZxcDYLWK3euZwlNFiWOwWsVsdczgujRsudovYrX45gOFit4jduhMHMFzsFh3ullEHSUFHKbQadSYVu0UPcbfpvSTaZTEkdovYrT5pixcYc0YEu0XsVp8cXiGJEbFbxG51SQI8McJuEbt1KwavYUe8VJHdInarRxJ/8Jwiu0Xs1k0s2LAoGcVvWmYXsGnAHS52i9itDsWqiabTGj7rCmt2i9itDmU8kOTGGL0yO9635tktYrc6lOo/rFIWD4w3uJndInarP/rI19+nhLJFjIbdInarP/OhU4PaoGy4A0V2i9it/iiUBH3kLKR1481sZreI3eqPOfg5lU4fEC12i9itLqWjh3vRjh8tdovYrS6hxIgd/PjRYreI3epSwxXSZvhosVvEbnWpYQagvEu0JnarF2MNaXtbt6Kc1V9yEq+kvz90vzOkUSJHeBHKvJqEf5JZs+ynWzIrYyx+s6a4ce30rEz6egaUj2Lb5JUxwNd2KT/1shT9eUe3puwS/pOc1y95bGXsz4fu8qrjMb/2PimDorTKHW9m32QUyIKK1Z3X9GDj5soeFOivaPml9Dviw8h5Z1FgF69PWYrbt+vqbkW/WDyweNFmchZlKUfxjFTfaFFLq8qfP3kCYG7PYsBPVmyIKmCDdVJsUqdOTZTOVmzctq195egsyoys365FikealuLe6bq0WzonbAot5fIJW54u1IRvclsngnju5JHLEQWm+UBt3XrbwFPBv6lb2oeKjWvollbYYKL4jzR4IsyirHEp7rxvf2G3pMOJT6YMeMZIsSk19SPVjpWxJw/SWlof3lXdgyM67BLyO7qVLfawvrVbMmCTzeK7uGAHM4mS5qW4752gLuuWD9jHRFFPL9jDabEht/QjVufBoGQ59/pH1XivoVQVhrIwX90tGbBXkE3dynUvwtk2/Y3tS3GLs9Lv65YP2M16UWsK2MdurZNuOVBcq4/23NkDaSx+ChVrVvE9DW1QY9FXdksvqLHq491ydXcYd9jNaFHSvhT3vB7/km75cO60dI/9nN53ZBVEnVDdnnz23RBXFMi265B07ftGmZ2v65a0qJOmo91y2CXpA4VJWpS0L8Utd7ku6JY0qOVOyxaQonhkPp4PWT9TRqLM+jM/mXcn/PRkUW29qlse1aw/1i1X9frWCWgJV91SDDbj+/RuaYcD1GnZAuwv9s50XU4YBMOJ2ROj3P/V9um+cZwAwaqd72+bObYc3wHC8jGRAtuakcGGoP2LVCUDnXdA1DnvCi7vTuFWBI4Sh1sRhrUi+U0BuKSmuF+sqM6tCCx1M6oGMA1cOztQDIyH31jJYSnRk6B4Kx/M1SGruhO4FQFUwAVCNc6TbQaX3BS3A5c6tzqgCn5fuv2sdfFB4Ba4jH/4F0VPA1dD6EP/V4YJjqK3WpOg6+zbyA2Yqk6dWxG4Srrc8gkYWl9/E/4n4NLPbwWse6G83LEVuVND/Vp+byqqBHBVZpJtY4V5AZTJFQFRmVv91YGt6pS5tQNfVoFbynvJO8D/Ai59bsWx4ZwpsC6+yp+4K8jf2cOoO7fCTwWuY9MMlbm48uo0RsHsbFfN4/EkX5sut5KMEdfjFmIBsimesVdFn1v993J4N5rA9wwqVmtQuSWMfb04XqCYeK06LsALbd0QRE9SybsbV+ArN1VutQAS1QtyC6xBJTfFtSeMSLglDxR9p7wrjRxqbW7wWtO7EQ5uvIu7VbgaY8A/lf2Azr2KnPwd73XzW66CTMsFueVff0n9FzeKKtzCUeAtLVEdqc6cH+31iIMf6AQ9PoRLBTK69Eu42ui5DmxF5TqIHaQq1+MW/m0uN8XdJOXWMFtyokZ9gXgguMF2jzQaWSXOKIiNmoBSRZcHRG5eS3WEA2Xv68GFnS63LIjlL8gtBDHDpnjQrnMCt0SB4uLo/kenhTNpLGoKfbjc0s/s8ZE6BXlvCiVc0tbGDLjqat13gGBD8YLVrpev8KFyTN+ervU9w8ey1+MW8u0sNcUdJ3Gdwa04PofDEr1XYsVXAsiNEFkVeuVrINe0jyuvZUpzdZ3WUl0AEXKr2+NQs1Xyv6gCIo8oke4Sw96G5yt5Nrfytiw9LUhtovRMN4gkprjkMOArcMuuZliedPFVqPFZqo4CkrEH3wmwlWaPtz6jhKvNii7tcHtficgFiuJ8+QyoAub4N092uOBIYSnICL9j5dEz0SAimuI9D2K2OsndsQpPn8glDYGABDq48JdC1ga1M7L5m/S+0mbEVFrcSrSm+gVwbWRuITmR4l8bdTWjZ4JBRDbFld55Kbf8MiQjEA0C/V9wy1Ep1InFUfL7+milzdWzqicWSnDlIuIDKHErE5PaiXilSJuCExkzSuLALafYFDfMyLPzi0ZVkYAiFW6ZSKwtj1Kf1XmgylvZfow+qVp1oX12QnqsVLhlydf9idYRSGiYQSAkOpPMNFPcrNj0ytxKlJSV1Zgi1Gnuk5swHn4HPXI5QLRN6g5aiMkzG6ozJ3BrA0Qbne9Qie9NdgaVP8IW7cxuJpnibj2Jl+ZWodQhWJVNOJkUKCbEMSerBz1ybYDICbqxBS+LKafsfXXHSMHlKVEZtSy0wIcKxDPezDHFLe8RL8stQ/J2VDbh7KTrwW1KBZ/bgK7o2BNp1jnTbxZBFaMitxJnQnWhBIqC0RTSM9mgWp5RUHpbbnnKjwoazQqFUo5V8KJAumwGskJXaK5OwqSK//fc2liPFQnB5UFRKNHhyuQzFFM8VTfnlldZKOEJd5orTENnykDW5pjZs0ac7kxg3PKvueV4C0EKoeyA3om9wawz7tgUVytt+qFnc2uh/KhVZddzIqCoAgI5ptxCJ1ewk5urm7jYEdI/5lZnjnndxgEPqApjuq0jn8Etbp/Sevg/cKuptLW7MNyE3JDg62SfKwlKuKTby5wg8SbnFuWfsM5t5qTP3isw64wlmeLGl4bP5ZapKuCKw1jYp+/hsRsQFQXvo3RbbKXvQdbnVmVOp3bjoRZj/HuedcYaVPVhK6kfza2kMv/MDlf9ZIUbzUINFyNnruo25fZxp1dp6HMLJS8XeN5gYmzs9bPOWKop7jjw4arcataWCdwyGWn0kisP0qijKRS5egwCcEkqsjb0r3K2wOXktLhFPxjZASZuVcabscw6YxmmeFq0+Hvb25CkwyF2n+GHvF9Sk3Crq3y7LIOefFTLgbq0kcBFR8BKbKmmDwcOselwi97ZtPB7ooa55QkfLjljWaa4b0/PP58HUdYNMAW/Nha3cAfBF/mTDrpRAb8ZOh9dSVDCJepmTITxLCdxa8fe9ck/krESx846Y7mmuHWF/D/jVvID4zwxbtFntMu/XPxQlJQIv4LK6GqSeOMYcEG2/Kqu5VxueTa32vD/LKNYys46YwWmeAq6KNzSvuCvyTG4ha+b8mleCdcy5ut1oyK3VhhQdoISLsnCRQuvVVd3Ircq9gR+SCgmbsOtMVM8ItV1Erd6hhGFvdC5ZVr44LMmlXDlD//SuFeif8G4k0sqg5syHTXSBrXqcwsEUuRWm3XGSk3xgMqIU7hVPAwrRvrVZamASOZ0xYEXd0W4oSQb4ZWKuIQLL5iok+Ye5sU9m1sIDlTO2AmmuLvTdQa3egCmzKBcPHDgeGoDSKqIV6Imt2bJDvaAnSDSTbwXOpYTuNUUuEXmifYZuSnunek6gVs7sCVgo9grzi9DwEIq3tLPEVqyFQphH8YUcEEs6tyy/zG3TAvwX5BLn1sR+JozwCqzUpHrS29+IfW/6ZMr0rMrhOz9JHBBdG9uCc/QTfG43kX0t/gq2IJZ4WiIRVTCFQk9PrpyC3wsR71ly5SWanqGEVdY39zSOkM3xU2Fc0sfW9V/UYVDCd5p+XfL9iJQbFjxlr5ahY+0yvZj4NWpogwjLl/e3NI5QzfFTYNFZW4lDFl7L+aHnF22MKsVshyYLCyCZ0+n9PhIEVHJww7iy5bqReP2JaQ3t6Rn5Ka48yoyXW6VMLa1tO1ZwC2cXPKJHuHYnQrU4i392NuRT7mR7msFl2t/c0vrDN0UN5Qut/w43FucNHqiLGGSVxwPidDJ4wb0wdXJ+zESb2EZLkup03tzS+sM3RT3kyq3+p9kd+ZA7m/gSCqd5InIdhgHbqcVb9FX6+HKx6HlOmHOb68wqngXbrU7cuuzKZ4MLlVuZWQSOolcfGJ6wSIJ7PnrYboom5NVAmDyhl7CNTDNWcfnijfhlrkntz6b4rng0uSWhV9VCz09ZfgqewBUtbBKuMrRjcNiztYCmAJ9P8Y+sA+DphZhTMubW/IzdFM8Yu+P5sNvSBMvbY2gESlVwn5gTO6gxsBLirfkcoCKHl0GQku1IFBHZd/cYp1RMMXdRjkrcsvx3oAFfkqnGzk7Bnnzge/izfnagM6ZdJTLx1uquWp7EMzeEXGrwFT5W3Nr2BQ3K51X5FZHP1vOLXm4WCn/BBwJ679eUrcCJsvdj4EzbVWekb/cYB7E7bn11RQPixQVHz0iiWsyt+RyUWCk8NFdXUZCYIkclX32kFv0Eq4N/yORXKpwqODO4pah6iIMQs+omOJeDpcityr8VBJwS6zm2dWU+wfobXNvY/pGdtoKzi3ufoyidM3Ujr/pFw1u+Te3PjDFcxwuxSeHX+Qk3JIrBVLBAM4n+1FJQZ/yamdDE4dbeAnXUfeiXO5oWGu+1nz5R3PrpSnuJDm35LtT9bll3Ma0fcW9jzzL4GXNvGSS43ALx1MTtFRLp+90BW4tyLn05tYrU9xqevM53FoF3NLJY3v6sfDBlcMuyP94JMOgld86CgebcuSQAuDaFbiVsJ/z5tYPUzyhT1GPWwv8lP333DKJleFy6BdSnFG81aOkF7DzynA2vIRrEbRUi8Y6VgVuYRCub259Yu/MltwIYSgKLXZ64f+/NpVKZTKZwW4kgcswOs9JjCNzWXSR7kMxEa/RLXgD3VKetLqcFV0Byw13vQLGwTbMZ5LcHSrdGQD4+FJlgG6pByIsunUTiol4jW6pd9AttVMub46K/Hqux0ljnPx1EvGnZ6uVxqlPqvmzRQ/QLVPLmopu/cNP75n/SbqlDMXAH77P5JPrcfKlTgKeDcLSupQEP9DQgy44wdetq55kEN16HoqZKgj+KN3KlAX4+nZQjOwCzWBLHcM7Jhpily7TybxFcGFsBN2iHYZFtz4RJndw/SjdUoZwwRW/XZLs/OngmBVFwJJTQoladorPztctuqok0a1P7KJbE+mWp2xt0tc9WuIXaI7M/h1XqeLJZ1T+uSreD1y/SrdO6mPLuIRutYRCdKtBf+Kb6FakrL/+i9bFHqYXUx6RgK49kWpY5d9jZ3s/cODrFtDvD21Ud2w2L6BbTaEQ3ZrEv/Utm0ZxpsPXq6XMceXWsZraST517GgJeDdjgvH7Lc14TJAa5M7m6XXrTyhkv9VhZm7volum/INyGeW7vfEx5TEb0E56F+XWus5JuS4J+U4X+LrFqU7mGrpuW5hctxpDIbr1AE2zMEJ4O906ygcnIimJWPAwHdPgKo+ItFwSP/vm2tqOOL5ubYqjza6h62CCqXWrNRSiW13rQUCiOHi9J+oWeqKDuhBKQT+uGY94XoZcHbbOt/JgPgl7VA/JbP9WfWAQm7X5hPsMW4J5das5FOLfalrWPa38cLvFKpM69OAtXF6FTt31o72RjisjS+56XjKTmm6I6f/GvnCzJLH88uWoNIHyCGdvvn+0l2BW3WoPhfjlEfVO0ZuQ9r9kM/a+1pDSkGfutkLt5Y7gdg1/x6B3FzrtkUy5I2ISid/c91D9c6HH+8Ri8/c63BpzGL7gtgFegjl1qz0U8j6x8erPk85OiJOlzcghXbRrMdevu74pbaS2P+gpkamTeGVRrMuVjiecehD1dGve/8QeUN/RXvGuw3mCGXWrORRSD6L5OGKBUmADc0qxGacUO/89oVMswJaOJJIdpI5nbxqD8/pDgPwVCqn+Vp1wbXrfLvPxLdDZh7T93cfm40q1PwDz6VZzKKT+1nMSIrFeP3TjTikelcPLfIXR7JRrR3S3nECx0OkfCsYwXhPxFFuXG6x5It/ndLrVIRQTMVK3dlSWVVvCifuwiBUD6M4rN6Yi914o8FfL3KftOpjCJCB2hdg86lk4uLl0qzUUUl8e7Vr2+OQ81qaTcvN+7uLvjLZuuQs+CTjlAMjF97nsPe7/tiHHcDeVbvUIxUwM9Z255l+CpmU4sm23msfE2RWHatLtbYTL5o4bvYDwh/CwgFvK6mxjjuFuJt1qCMWy/RPNxiDWpKJxO6RNqUPYBwWvquyWVYR4G1THGFKnyy0c0GflNUPX+IP75ffCwcaJdEuZH7XdUqUXumm2u4pyHaY8gpTpC981FHxgTvQ4yl4MruDhD+XsYt6CNDQFarmVwhxrCzvTfqs9FAuYIIbrFoTylbTnz3/geNpEl2pRSNun4UTvLN/BYOoVE97iqEhQ0KPPk2pIbGXg/88g5BmBnup+ixuKqZKJXXULccVgzu03lwnlORwTZTDmdKae/Q2gsHii9I3PKlqvCFjuk2r+bPF9fCJ2xPBsniufiPiusz9NHKFb/DlpLuzLA21fsbqAHVevXNvXL5UXRQbqZmEiW6f7MzPgGG7zdP6t5lBMXglihG7xT0GOUH8rh1esLo6SdBtvhDLQuVL09aLt4tXLmOv6Jz1TnPGdz20olnDK99ctvnBZT6obCOYFm+I8NNa7LRTsrqikbrbpnIadTM4OmwVvCxI36bvq36H4CYfEl+iW2jDLHEK3aJ9R7KFoBGzSbXxe0TBG4TsmljasNISMqCLJnXbRFAz2mLf+FiUUs13Jv0q31GEReweEbpEWmkQO0z44b5wNVrW0YgA9F9+IU90LSFVy6ui+u9lr7nqn6FDM5Tftr1vcBc9FXn353Q6+gdTDbXracVWL778ARSM63MhJwkUeMVylDRen74uBCsVMtQKH6ladI9z+B7L7YsBmEb9KZgYO1BDiFkoL1uUx9gunyEDb2E/dNWcRvGoithyg3Br9E5tDMatqDdGtOj49m4WxSz8f2EO5+RQ6iALNLPQVbkXrUB0YUKtXu5uxp50QAx8eCw1mvP58PjYPC/WrbgrFvOhe3Mc8P5iQ5/+/l6j/oSqgPqT+Kfxj4qFGkvfTljrWbLrTh5QKYeDY7UmdKfVFL7gDG1LwLjwYm595FuNDMbVovZy8O/NlFh4w4ENS+Uw6e8x1VIFmPlFv139mf2OuTUfVDTfOgBiPzZnQdejRf6pvGozbjthncMGc27HuJK6GYt2vOxJAbKfIxMpGkIed26jX9tBHftGCsBJ+2pK2CPvWqQRBWIhz2pK2dcwqzmlBEB4BE9dYa36eaJUgCAuxL3YLdNXNW4IgLERa7BbITt+JShCEG+Jit0DHCrV6BUF4yjVv55Mq5wKtEQRBeE5Y6xYolhoL6LEgCPU3PvM+Rv1gk1t5QVget5h5K9T7YQiCsBB26h4CT27lF9NjQRA+OBYzb7k1eroIgvCEcy2zABR5Ui0IqwOLmbf2ehdCQRAWwi9mFgjypFoQlietZRbQ5S+LmWkFQfggLmYW+MXevRwhCEVBFKzi8wARNf9oXVluiOBUdxQDzHCH8hbkTa2ywGxSDX176wfNm/IW5J2xWPIwqYa80SpvnSbV0Le2YslwDwPyrlgsWU2qIW+0YsnmHgbkzbFYsnx+Wl9Jgb+tFUsOk2roW1qd8rd7GJB3xMpbq0k15D1bnfLLpBr69lZ562VSDXln7O31dCfw+AsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADf9uCABAAAAEDQ/9ftCFQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADgJTBUMNyALqpSAAAAAElFTkSuQmCC"
BRAND_FAVICON_URL = "https://www.easysystems.ch/Themes/essys_v2-v1_19-08-2025/favicon/android-icon-96x96.png"
BRAND_FONT_STACK = "\"Overpass\",\"Segoe UI\",\"Inter\",\"Helvetica Neue\",Arial,sans-serif"
BRAND_AUTHOR = "Konrad von Burg"
BRAND_COPYRIGHT = "Copyright (c) 2026"
PUBLIC_GITHUB_REPO = os.environ.get("PUBLIC_REPO", "EasySystems-GmbH/EasySystems-GmbH/easymonitoring-artefacts")
REPO_URL = f"https://github.com/{PUBLIC_GITHUB_REPO}"
GITHUB_REPO = PUBLIC_GITHUB_REPO
AUTOUPDATE_CHECK_INTERVAL_SEC = 6 * 3600  # Max once per 6 hours
UPDATE_SCRIPT_REMOTE_PATH = "apps/unix-monitor/unix-monitor.py"
PRODUCT_DESC = (
    "Checks Unix host SMART and storage health, provides guided elevated-access setup and diagnostics, "
    "and pushes monitor status to Uptime Kuma."
)


def _brand_asset_data_uri(filename: str, mime: str) -> Optional[str]:
    script_path = Path(__file__).resolve()
    candidates: List[Path] = []
    for root in [script_path.parent, *script_path.parents]:
        candidates.append(root / "corporate identity" / filename)
        candidates.append(root / "dev" / "corporate identity" / filename)
    payload: Optional[bytes] = None
    for asset_path in candidates:
        try:
            payload = asset_path.read_bytes()
            break
        except Exception:
            continue
    if payload is None:
        return None
    encoded = base64.b64encode(payload).decode("ascii")
    return f"data:{mime};base64,{encoded}"


_brand_logo_uri = _brand_asset_data_uri("rabbit.png", "image/png") or _brand_asset_data_uri("logo-systems-c.svg", "image/svg+xml")
if _brand_logo_uri:
    BRAND_LOGO_URL = _brand_logo_uri

_brand_favicon_uri = _brand_asset_data_uri("rabbit.png", "image/png") or _brand_asset_data_uri("logo-systems-c.svg", "image/svg+xml")
if _brand_favicon_uri:
    BRAND_FAVICON_URL = _brand_favicon_uri


def _normalize_source_platform(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return "unix"
    if "synology" in raw or raw == "dsm":
        return "synology"
    return "unix"


def _monitor_source_platform(monitor: Dict[str, Any]) -> str:
    hint = (
        str(monitor.get("source_platform", "") or "")
        or str(monitor.get("platform", "") or "")
        or str(monitor.get("source", "") or "")
    )
    return _normalize_source_platform(hint)


def _check_title_for_platform(source_platform: str) -> str:
    return "Synology check" if _normalize_source_platform(source_platform) == "synology" else "Unix check"


def get_script_path() -> Path:
    return Path(__file__).resolve()


_request_ctx = threading.local()
_peer_sync_guard = threading.Lock()


def _set_request_display_host(host: str) -> None:
    """Store request host for UI rendering on the current thread."""
    _request_ctx.display_host = str(host or "").strip()


def _get_request_display_host() -> str:
    return str(getattr(_request_ctx, "display_host", "") or "").strip()


def _detect_primary_server_ip() -> str:
    """Best-effort primary local IP for UI display."""
    candidates: List[str] = []
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None):
            if len(info) < 5 or not info[4]:
                continue
            ip = str(info[4][0])
            if ip and ip not in candidates:
                candidates.append(ip)
    except Exception:
        pass
    for ip in candidates:
        if "." in ip and not ip.startswith("127."):
            return ip
    for ip in candidates:
        if ":" in ip and ip != "::1":
            return ip
    return candidates[0] if candidates else "n/a"


def _request_interface_host() -> str:
    """Best-effort request host/interface label from proxy or direct Host header."""
    host = _get_request_display_host()
    if not host:
        return ""
    raw = host.split(",")[0].strip()
    if not raw:
        return ""
    if raw.startswith("[") and "]" in raw:
        return raw[1:raw.index("]")]
    if ":" in raw:
        return raw.rsplit(":", 1)[0]
    return raw


def _list_system_ips() -> List[str]:
    ips: List[str] = []
    rc, out = _run_cmd(["ip", "-o", "addr", "show"], timeout_sec=5)
    if rc == 0 and out.strip():
        for ln in out.splitlines():
            m = re.search(r"\sinet6?\s+([0-9a-fA-F\.:]+)/\d+", ln)
            if not m:
                continue
            ip = m.group(1).strip()
            if ip and ip not in ips:
                ips.append(ip)
        if ips:
            return ips
    rc_host, out_host = _run_cmd(["hostname", "-I"], timeout_sec=4)
    if rc_host == 0 and out_host.strip():
        for part in out_host.replace("\n", " ").split():
            ip = str(part).strip()
            if ip and ip not in ips:
                ips.append(ip)
        if ips:
            return ips
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None):
            if len(info) < 5 or not info[4]:
                continue
            ip = str(info[4][0]).strip()
            if ip and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    if "127.0.0.1" not in ips:
        ips.append("127.0.0.1")
    return ips


def _normalize_ui_bind_host(host: Any, known_ips: Optional[List[str]] = None) -> str:
    raw = str(host or "").strip()
    if raw in ("", "*", "all"):
        return "0.0.0.0"
    if raw in ("localhost", "loopback"):
        return "127.0.0.1"
    if raw in ("0.0.0.0", "127.0.0.1"):
        return raw
    if known_ips and raw in known_ips:
        return raw
    try:
        socket.inet_aton(raw)
        return raw
    except OSError:
        return "0.0.0.0"


def _normalize_ui_bind_port(port: Any, default: int = 8787) -> int:
    try:
        parsed = int(port if port is not None else default)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(parsed, 65535))


def _ui_bind_host_options(all_ips: List[str]) -> List[str]:
    opts = ["0.0.0.0", "127.0.0.1"]
    for ip in all_ips:
        if "." not in ip:
            continue
        if ip not in opts:
            opts.append(ip)
    return opts


def _ntp_sync_details() -> Dict[str, str]:
    result = {"synced": "unknown", "service": "unknown", "source": "unknown", "detail": "No NTP details available"}
    rc, out = _run_cmd(["timedatectl", "show", "-p", "NTPSynchronized", "-p", "NTPService", "-p", "SystemClockSynchronized"], timeout_sec=5)
    if rc == 0 and out.strip():
        values: Dict[str, str] = {}
        for ln in out.splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                values[k.strip()] = v.strip()
        ntp_sync = values.get("NTPSynchronized", values.get("SystemClockSynchronized", "unknown")).lower()
        result["synced"] = "yes" if ntp_sync == "yes" else ("no" if ntp_sync == "no" else "unknown")
        result["service"] = values.get("NTPService", "unknown") or "unknown"
    for cmd in (["chronyc", "sources", "-n"], ["ntpq", "-pn"]):
        rc2, out2 = _run_cmd(cmd, timeout_sec=6)
        if rc2 != 0 or not out2.strip():
            continue
        lines = [ln.strip() for ln in out2.splitlines() if ln.strip()]
        src = ""
        for ln in lines:
            if ln.startswith(("^*", "*", "+", "^+")):
                parts = ln.split()
                if len(parts) >= 2:
                    src = parts[1]
                    break
        if not src and len(lines) > 2:
            parts = lines[2].split()
            if len(parts) >= 2:
                src = parts[1]
        if src:
            result["source"] = src
            result["detail"] = f"Synced={result['synced']} | Service={result['service']} | Source={src}"
            return result
    result["detail"] = f"Synced={result['synced']} | Service={result['service']} | Source={result['source']}"
    return result


def _append_login_event(auth: Dict[str, Any], ip: str, state: str) -> None:
    events = auth.get("login_history", [])
    if not isinstance(events, list):
        events = []
    events.append({"ts": int(time.time()), "ip": str(ip or "unknown"), "state": str(state or "unknown")})
    auth["login_history"] = events[-20:]


def get_config_path() -> Path:
    script_dir = get_script_path().parent
    home_config = Path.home() / ".config" / "unix-monitor.json"
    package_var = Path("/var/lib/unix-monitor/unix-monitor.json")
    if package_var.exists():
        return package_var
    script_local = script_dir / "unix-monitor.json"
    if script_local.exists():
        return script_local
    if home_config.exists():
        return home_config
    if package_var.parent.exists() and os.access(str(package_var.parent), os.W_OK):
        return package_var
    if os.access(str(script_dir), os.W_OK):
        return script_local
    home_config.parent.mkdir(parents=True, exist_ok=True)
    return home_config


def _legacy_config_candidates(active: Path) -> List[Path]:
    script_local = get_script_path().parent / "unix-monitor.json"
    home_config = Path.home() / ".config" / "unix-monitor.json"
    candidates = [script_local, home_config]
    return [p for p in candidates if p != active and p.exists()]


def _read_json_file(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _migrate_config_if_needed(active_path: Path) -> bool:
    if active_path.exists():
        return False
    for cand in _legacy_config_candidates(active_path):
        data = _read_json_file(cand)
        if data and data.get("monitors"):
            try:
                active_path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(str(active_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, CONFIG_FILE_MODE)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                append_ui_log(f"config-migrate | imported monitors from {cand}")
                return True
            except OSError:
                continue
    return False


def get_runtime_data_dir() -> Path:
    script_dir = get_script_path().parent
    package_var_dir = Path("/var/lib/unix-monitor")
    home_dir = Path.home() / ".config" / "unix-monitor"
    candidates = [package_var_dir, script_dir, home_dir]
    for d in candidates:
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        if d.exists() and os.access(str(d), os.R_OK | os.W_OK):
            return d
    return script_dir


# Inject monolith-owned runtime values into the extracted auth state helpers
# (behavior-preserving: same data dir, product name, and lockout tuning).
_auth_state.configure(
    runtime_data_dir=get_runtime_data_dir,
    product_name=PRODUCT_NAME,
    auth_file_mode=AUTH_FILE_MODE,
    max_login_attempts=AUTH_MAX_LOGIN_ATTEMPTS,
    lockout_duration_sec=AUTH_LOCKOUT_DURATION_SEC,
)

# Inject the same runtime data dir into the extracted peer cert-path helpers
# (behavior-preserving: certs dir resolves identically to the monolith).
_peer_certs.configure(runtime_data_dir=get_runtime_data_dir)


def get_ui_log_path() -> Path:
    return get_runtime_data_dir() / "unix-monitor-ui.log"


def append_ui_log(message: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    if len(message) > UI_LOG_MSG_MAX_CHARS:
        message = message[: UI_LOG_MSG_MAX_CHARS - 3] + "..."
    line = f"{ts} | {message}\n"
    path = get_ui_log_path()
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
        if path.exists():
            current = stat.S_IMODE(path.stat().st_mode)
            if current != CONFIG_FILE_MODE:
                path.chmod(CONFIG_FILE_MODE)
    except OSError:
        pass


def _parse_log_line_datetime(line: str) -> Optional[datetime]:
    if len(line) < 19:
        return None
    if not LOG_LINE_TS_PREFIX.match(line[:32]):
        return None
    try:
        return datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _normalize_log_date(value: str) -> str:
    v = (value or "all").strip().lower()
    if v in ("all", "any", ""):
        return "all"
    if v in ("today", "yesterday"):
        return v
    if re.match(r"^\d{4}-\d{2}-\d{2}$", v):
        return v
    return "all"


def _normalize_log_time_scope(value: str) -> str:
    v = (value or "all").strip().lower()
    if v in ("all", "any", ""):
        return "all"
    if v in ("15m", "1h", "6h", "24h"):
        return v
    return "all"


def _normalize_log_time_hhmm(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    m = re.match(r"^(\d{1,2}):(\d{2})(?::\d{2})?$", v)
    if not m:
        return ""
    hh, mm = m.group(1), m.group(2)
    try:
        hhi = int(hh)
        mmi = int(mm)
    except ValueError:
        return ""
    if hhi < 0 or hhi > 23 or mmi < 0 or mmi > 59:
        return ""
    return f"{hhi:02d}:{mmi:02d}"


def _filter_log_lines(
    lines: List[str],
    log_filter: str,
    log_date: str,
    log_time_scope: str,
    log_time_from: str = "",
    log_time_to: str = "",
) -> List[str]:
    filt = (log_filter or "all").strip().lower()
    ld = _normalize_log_date(log_date)
    now = datetime.now()
    target_day = None
    if ld == "today":
        target_day = now.date()
    elif ld == "yesterday":
        target_day = (now - timedelta(days=1)).date()
    elif ld != "all":
        try:
            target_day = datetime.strptime(ld[:10], "%Y-%m-%d").date()
        except ValueError:
            target_day = None
    lt = _normalize_log_time_scope(log_time_scope)
    cutoff = None
    if lt != "all":
        age_sec = {"15m": 15 * 60, "1h": 60 * 60, "6h": 6 * 60 * 60, "24h": 24 * 60 * 60}[lt]
        cutoff = now - timedelta(seconds=age_sec)
    tf = _normalize_log_time_hhmm(log_time_from)
    tt = _normalize_log_time_hhmm(log_time_to)
    needs_ts = bool(target_day or cutoff or tf or tt)

    def _to_min(hhmm: str) -> int:
        h, m = hhmm.split(":")
        return int(h) * 60 + int(m)

    tfm = _to_min(tf) if tf else None
    ttm = _to_min(tt) if tt else None
    out: List[str] = []
    for ln in lines:
        low = (ln or "").lower()
        if filt in ("smart", "storage", "ping", "port", "dns", "backup", "service") and filt not in low:
            continue
        ts = _parse_log_line_datetime(ln) if needs_ts else None
        if needs_ts and ts is None:
            continue
        if target_day is not None and ts is not None and ts.date() != target_day:
            continue
        if cutoff is not None and ts is not None and ts < cutoff:
            continue
        if (tfm is not None or ttm is not None) and ts is not None:
            cur = ts.hour * 60 + ts.minute
            if tfm is not None and ttm is not None:
                ok = (tfm <= cur <= ttm) if tfm <= ttm else (cur >= tfm or cur <= ttm)
            elif tfm is not None:
                ok = cur >= tfm
            else:
                ok = cur <= int(ttm or 0)
            if not ok:
                continue
        out.append(ln)
    return out


def get_ui_log_stats() -> Tuple[int, int]:
    path = get_ui_log_path()
    if not path.exists():
        return 0, 0
    try:
        st = path.stat()
        sz = int(st.st_size)
        key = (int(st.st_mtime_ns), sz)
        cached_key = _UI_LOG_STATS_CACHE.get("key")
        cached_value = _UI_LOG_STATS_CACHE.get("value")
        if cached_key == key and isinstance(cached_value, tuple) and len(cached_value) == 2:
            return int(cached_value[0]), int(cached_value[1])
        n = 0
        had_data = False
        last_byte = b""
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                had_data = True
                n += chunk.count(b"\n")
                last_byte = chunk[-1:]
        if had_data and last_byte != b"\n":
            n += 1
        out = (sz, n)
        _UI_LOG_STATS_CACHE["key"] = key
        _UI_LOG_STATS_CACHE["value"] = out
        return out
    except OSError:
        return 0, 0


def _fmt_ui_log_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KiB"
    return f"{num_bytes / (1024 * 1024):.1f} MiB"


def _fmt_bytes(num_bytes: Optional[float]) -> str:
    try:
        n = float(num_bytes or 0)
    except (TypeError, ValueError):
        return "n/a"
    if n <= 0:
        return "n/a"
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    idx = 0
    while n >= 1024 and idx < len(units) - 1:
        n /= 1024.0
        idx += 1
    precision = 0 if n >= 10 or idx == 0 else 1
    return f"{n:.{precision}f} {units[idx]}"


def _fmt_uptime(seconds: Optional[float]) -> str:
    try:
        total = int(float(seconds or 0))
    except (TypeError, ValueError):
        return "n/a"
    if total < 0:
        return "n/a"
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts: List[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def _collect_system_specs() -> Dict[str, str]:
    cpu = os.environ.get("PROCESSOR_IDENTIFIER", "").strip()
    if not cpu:
        try:
            with open("/proc/cpuinfo", encoding="utf-8", errors="ignore") as f:
                for ln in f:
                    if ":" not in ln:
                        continue
                    k, v = ln.split(":", 1)
                    key = k.strip().lower()
                    val = v.strip()
                    if key not in {"model name", "hardware", "processor"}:
                        continue
                    # Skip "processor: 0/1/2..." index lines and prefer real model/hardware names.
                    if key == "processor" and re.fullmatch(r"\d+", val):
                        continue
                    cpu = val
                    if cpu:
                        break
        except OSError:
            pass
    if not cpu:
        cpu = platform.machine() or "unknown"

    mem_total_bytes = 0.0
    try:
        with open("/proc/meminfo", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                if ln.startswith("MemTotal:"):
                    parts = ln.split()
                    if len(parts) >= 2:
                        mem_total_bytes = float(parts[1]) * 1024.0
                    break
    except OSError:
        pass

    disk_text = "n/a"
    try:
        st = os.statvfs("/")
        total = float(st.f_blocks) * float(st.f_frsize)
        free = float(st.f_bavail) * float(st.f_frsize)
        disk_text = f"{_fmt_bytes(total)} / {_fmt_bytes(free)}"
    except OSError:
        pass

    uptime_seconds = 0.0
    try:
        with open("/proc/uptime", encoding="utf-8", errors="ignore") as f:
            uptime_seconds = float((f.read().strip().split() or ["0"])[0])
    except (OSError, ValueError):
        pass

    return {
        "cpu": cpu or "n/a",
        "ram": _fmt_bytes(mem_total_bytes),
        "disk": disk_text,
        "uptime": _fmt_uptime(uptime_seconds),
    }


def read_ui_log(
    max_lines: int = UI_LOG_DISPLAY_LINES,
    log_filter: str = "all",
    log_date: str = "all",
    log_time_scope: str = "all",
    log_time_from: str = "",
    log_time_to: str = "",
) -> str:
    path = get_ui_log_path()
    if not path.exists():
        return "No log entries yet."
    has_active_filter = (
        (log_filter or "all").strip().lower() != "all"
        or _normalize_log_date(log_date) != "all"
        or _normalize_log_time_scope(log_time_scope) != "all"
        or bool(_normalize_log_time_hhmm(log_time_from))
        or bool(_normalize_log_time_hhmm(log_time_to))
    )
    try:
        if not has_active_filter and max_lines > 0:
            tail_lines = _read_tail_lines(path, max_lines=max_lines)
            text = "".join(tail_lines).strip()
            if text:
                return text
            return "No log entries yet."
        with open(path, encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()
        lines = _filter_log_lines(all_lines, log_filter, log_date, log_time_scope, log_time_from, log_time_to)
        tail = lines[-max_lines:] if max_lines > 0 else lines
        text = "".join(tail).strip()
        if text:
            return text
        has_any_logs = bool(all_lines)
        if has_any_logs and has_active_filter:
            return "No data in the selected period."
        return "No log entries yet."
    except OSError as e:
        return f"Failed to read log: {type(e).__name__}: {e}"


def apply_log_filters_to_text(
    text: str,
    log_filter: str = "all",
    log_date: str = "all",
    log_time_scope: str = "all",
    log_time_from: str = "",
    log_time_to: str = "",
    max_lines: int = UI_LOG_DISPLAY_LINES,
) -> str:
    if not (text or "").strip():
        return text
    lines = text.splitlines(keepends=True)
    if not lines:
        return text
    lines = _filter_log_lines(lines, log_filter, log_date, log_time_scope, log_time_from, log_time_to)
    tail = lines[-max_lines:] if max_lines > 0 else lines
    out = "".join(tail).strip()
    if out:
        return out
    return "No data in the selected period."


def clear_ui_log() -> None:
    path = get_ui_log_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("")
        path.chmod(CONFIG_FILE_MODE)
    except OSError:
        pass


def _clear_file(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


def clear_smart_cache() -> None:
    _clear_file(get_smart_cache_path())


def clear_backup_cache() -> None:
    _clear_file(get_backup_cache_path())


def clear_system_log_cache() -> None:
    _clear_file(get_system_log_cache_path())


def clear_task_status() -> None:
    _clear_file(get_task_status_path())


def clear_history() -> None:
    _save_history([])


# ---------------------------------------------------------------------------
# Peering (multi-instance master/agent)
# ---------------------------------------------------------------------------

def _get_instance_id(cfg: Dict[str, Any]) -> str:
    iid = str(cfg.get("instance_id", "") or "").strip()
    if iid:
        return iid
    import uuid
    iid = str(uuid.uuid4())
    cfg["instance_id"] = iid
    save_config(cfg, reapply_cron=False)
    return iid


# Pure peer instance-id / monitor-field helpers moved to
# ``src/core/peering/instances.py`` (Phase 4 Slice C). Imported at top of file:
# _is_valid_peer_instance_id, _display_peer_instance_id,
# _normalize_peer_instance_id_key, _dedupe_peers_by_instance_id,
# _registered_peer_instance_ids, _is_legacy_peer, _peer_monitor_name,
# _peer_monitor_mode.


def _peer_agent_bound_to_master(cfg: Dict[str, Any]) -> bool:
    """True when an agent has established trust or a successful master sync (role change blocked until released)."""
    if str(cfg.get("peer_role", "") or "").lower() != "agent":
        return False
    sec = _get_mtls_security_status(cfg)
    if sec.get("has_master_cert"):
        return True
    res = str(cfg.get("last_peer_sync_result", "") or "")
    return res.startswith("OK")


def _peer_master_has_registered_agents(cfg: Dict[str, Any]) -> bool:
    return len(_registered_peer_instance_ids(cfg)) > 0


def _peer_role_change_blocked_reason(cfg: Dict[str, Any]) -> str:
    """Non-empty string if the Role control should be locked; empty if the user may change role."""
    if _rollout_agent_mode():
        return ""
    r = _cfg_peer_role(cfg)
    if r == "agent" and _peer_agent_bound_to_master(cfg):
        return "agent"
    if r == "master" and _peer_master_has_registered_agents(cfg):
        return "master"
    return ""


def _peer_agent_release_master_binding(cfg: Dict[str, Any]) -> None:
    """Clear agent-side master trust and sync markers (keeps token / master host fields)."""
    d = get_certs_dir()
    (d / "master.crt").unlink(missing_ok=True)
    cfg["last_peer_sync"] = 0
    cfg["last_peer_sync_result"] = ""
    cfg["last_peer_sync_latency_ms"] = None
    cfg.pop("peer_master_approval_status", None)


def _peer_remove_agent_master_certs(cfg: Dict[str, Any]) -> None:
    """Remove mTLS material obtained from a hosted master (agent role)."""
    d = get_certs_dir()
    (d / "master.crt").unlink(missing_ok=True)
    instance_id = str(cfg.get("instance_id", "") or "").strip()
    if instance_id:
        safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", instance_id)[:40]
        for suffix in (".crt", ".key", ".csr"):
            (d / f"{safe_id}{suffix}").unlink(missing_ok=True)
    # Agent stores the master's CA as ca.crt only; a local master also has ca.key.
    if not (d / "ca.key").exists():
        (d / "ca.crt").unlink(missing_ok=True)


def _peer_clear_standalone_peering(cfg: Dict[str, Any], *, prev_role: str = "") -> None:
    """Clear master connection settings and agent-side master trust when role is standalone."""
    prev = str(prev_role or "").lower()
    had_agent_master_certs = prev == "agent" or (get_certs_dir() / "master.crt").exists()
    _peer_agent_release_master_binding(cfg)
    cfg["peer_master_url"] = ""
    cfg["peering_token"] = ""
    cfg["agent_callback_url"] = ""
    cfg.pop("peer_master_base_url", None)
    cfg.pop("peer_master_port", None)
    if had_agent_master_certs:
        _peer_remove_agent_master_certs(cfg)


# ``_peer_error_detail`` (pure peer-HTTP error-response parser) now lives in
# ``src/core/peering/http.py`` (Phase 4 Slice C) and is imported at top of file.


def _peer_set_master_approval_status(cfg: Dict[str, Any], status_code: int, body: str) -> Optional[str]:
    """Persist hosted-master approval state and return a user-facing block message when rejected."""
    if status_code < 300:
        cfg.pop("peer_master_approval_status", None)
        return None
    code, message = _peer_error_detail(body)
    if code == "pairing_not_approved" or code == "pairing_required":
        cfg["peer_master_approval_status"] = "pending"
        return (
            "Master has not approved this agent yet. "
            "This agent should appear under Pending pairing on the hosted master — ask the operator to approve it."
        )
    if code == "pairing_rejected":
        cfg["peer_master_approval_status"] = "rejected"
        return message or "Master rejected this agent pairing request."
    cfg.pop("peer_master_approval_status", None)
    return None


def get_peer_data_dir() -> Path:
    d = get_runtime_data_dir() / "peers"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load_peer_snapshot(peer_id: str) -> Optional[Dict[str, Any]]:
    p = get_peer_data_dir() / f"{peer_id}.json"
    if not p.exists():
        return None
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _save_peer_snapshot(peer_id: str, data: Dict[str, Any]) -> None:
    d = get_peer_data_dir()
    tmp = d / f".{peer_id}.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(str(tmp), str(d / f"{peer_id}.json"))
    except OSError:
        pass


def _load_all_peer_snapshots() -> List[Dict[str, Any]]:
    d = get_peer_data_dir()
    results: List[Dict[str, Any]] = []
    if not d.exists():
        return results
    for p in sorted(d.glob("*.json")):
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                results.append(data)
        except (OSError, json.JSONDecodeError):
            pass
    return results


# ---------------------------------------------------------------------------
# Peering Security: mTLS Certificate Management + Payload Encryption
# ---------------------------------------------------------------------------

def _openssl_available() -> bool:
    try:
        rc, _ = _run_cmd(["openssl", "version"], timeout_sec=5)
        return rc == 0
    except Exception:
        return False


def _generate_ca(force: bool = False) -> Tuple[bool, str]:
    """Generate a self-signed CA key + cert for the master. Returns (ok, message)."""
    d = get_certs_dir()
    ca_key = d / "ca.key"
    ca_crt = d / "ca.crt"
    if ca_key.exists() and ca_crt.exists() and not force:
        return True, "CA already exists."
    if not _openssl_available():
        return False, "openssl not found on this system."
    try:
        rc, out = _run_cmd([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_crt),
            "-days", "3650", "-subj", "/CN=UnixMonitorCA",
        ], timeout_sec=30)
        if rc != 0:
            return False, f"openssl CA generation failed (rc={rc}): {out[:200]}"
        ca_key.chmod(0o600)
        ca_crt.chmod(0o644)
        append_ui_log("mtls | CA key+cert generated")
        return True, "CA generated."
    except Exception as e:
        return False, f"CA generation error: {e}"


def _generate_instance_cert(instance_id: str, cn_prefix: str = "peer") -> Tuple[bool, str]:
    """Generate a key + CSR, sign it with the CA. Returns (ok, message)."""
    d = get_certs_dir()
    ca_key = d / "ca.key"
    ca_crt = d / "ca.crt"
    if not ca_key.exists() or not ca_crt.exists():
        return False, "CA not generated yet."
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', instance_id)[:40]
    key_path = d / f"{safe_id}.key"
    csr_path = d / f"{safe_id}.csr"
    crt_path = d / f"{safe_id}.crt"
    try:
        rc, out = _run_cmd([
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path), "-out", str(csr_path),
            "-subj", f"/CN={cn_prefix}-{safe_id[:20]}",
        ], timeout_sec=20)
        if rc != 0:
            return False, f"CSR generation failed: {out[:200]}"
        rc, out = _run_cmd([
            "openssl", "x509", "-req", "-in", str(csr_path),
            "-CA", str(ca_crt), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(crt_path),
            "-days", "3650",
        ], timeout_sec=20)
        if rc != 0:
            return False, f"cert signing failed: {out[:200]}"
        key_path.chmod(0o600)
        crt_path.chmod(0o644)
        csr_path.unlink(missing_ok=True)
        append_ui_log(f"mtls | cert generated for {cn_prefix}-{safe_id[:20]}")
        return True, "Certificate generated and signed."
    except Exception as e:
        return False, f"cert generation error: {e}"


def _sign_agent_csr(csr_pem: str, agent_id: str) -> Tuple[Optional[str], str]:
    """Sign an agent CSR with the CA. Returns (signed_cert_pem_or_None, message)."""
    d = get_certs_dir()
    ca_key = d / "ca.key"
    ca_crt = d / "ca.crt"
    if not ca_key.exists() or not ca_crt.exists():
        return None, "CA not available."
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', agent_id)[:40]
    csr_file = d / f"agent-{safe_id}.csr"
    crt_file = d / f"agent-{safe_id}.crt"
    try:
        csr_file.write_text(csr_pem, encoding="utf-8")
        rc, out = _run_cmd([
            "openssl", "x509", "-req", "-in", str(csr_file),
            "-CA", str(ca_crt), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(crt_file),
            "-days", "3650",
        ], timeout_sec=20)
        csr_file.unlink(missing_ok=True)
        if rc != 0:
            return None, f"signing failed: {out[:200]}"
        signed_pem = crt_file.read_text(encoding="utf-8")
        crt_file.chmod(0o644)
        append_ui_log(f"mtls | signed agent cert for {agent_id[:20]}")
        return signed_pem, "Agent cert signed."
    except Exception as e:
        return None, f"signing error: {e}"


def _get_ca_fingerprint() -> str:
    ca_crt = get_certs_dir() / "ca.crt"
    if not ca_crt.exists():
        return ""
    try:
        rc, out = _run_cmd(["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", str(ca_crt)], timeout_sec=5)
        if rc == 0 and "=" in out:
            return out.strip().split("=", 1)[1].strip()
    except Exception:
        pass
    return ""


def _peer_entry_for_instance_id(cfg: Dict[str, Any], instance_id: str) -> Optional[Dict[str, Any]]:
    needle = str(instance_id or "").strip()
    if not needle:
        return None
    peers = cfg.get("peers", [])
    if not isinstance(peers, list):
        return None
    for p in peers:
        if not isinstance(p, dict):
            continue
        pid = str(p.get("instance_id", "") or "").strip()
        if pid == needle:
            return p
    return None


def _revoke_agent_cert(agent_id: str) -> str:
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', agent_id)[:40]
    d = get_certs_dir()
    removed = False
    for suffix in (".crt", ".key", ".csr"):
        p = d / f"agent-{safe_id}{suffix}"
        if p.exists():
            p.unlink()
            removed = True
    if removed:
        append_ui_log(f"mtls | revoked cert for agent {agent_id[:20]}")
        return f"Certificate for {agent_id} revoked."
    return f"No certificate found for {agent_id}."


def _get_mtls_security_status(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Return summary of mTLS and signing state for display in UI."""
    d = get_certs_dir()
    ca_exists = (d / "ca.crt").exists()
    fingerprint = _get_ca_fingerprint() if ca_exists else ""
    cert, key, ca = _get_mtls_cert_paths(cfg)
    instance_cert_ok = cert is not None
    signed_agents = _list_signed_agents() if ca_exists else []
    openssl_ok = _openssl_available()
    signing_active = instance_cert_ok and openssl_ok and key is not None
    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
    has_master_cert = (d / "master.crt").exists() if role == "agent" else False
    return {
        "openssl_available": openssl_ok,
        "ca_exists": ca_exists,
        "ca_fingerprint": fingerprint,
        "instance_cert_ok": instance_cert_ok,
        "signed_agents": signed_agents,
        "mtls_active": ca_exists and instance_cert_ok,
        "signing_active": signing_active,
        "has_master_cert": has_master_cert,
    }


# --- Payload encryption (AES-GCM) for HTTP safety net ---
# _derive_aes_key / _encrypt_payload / _decrypt_payload now live in
# src/core/peering/crypto.py (imported at top). The openssl-CLI encryption
# fallback's _run_cmd dependency is injected via _peer_crypto.configure(...)
# once _run_cmd is defined.


# --- Config-backup encryption (AES-GCM) ---
# BACKUP_SALT / _derive_backup_key / _encrypt_backup / _decrypt_backup now live
# in src/core/security/backup_crypto.py (imported at top). The backup family
# uses a backup-specific salt distinct from the peer-crypto salt. The
# openssl-CLI encryption fallback's _run_cmd dependency is injected via
# _backup_crypto.configure(...) once _run_cmd is defined.


def _agent_request_cert(cfg: Dict[str, Any]) -> str:
    """Agent requests a signed cert from master and stores cert chain locally."""
    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
    if role != "agent":
        return "Certificate request is only available for agent role."
    master_host, master_port = _parse_peer_host_port(
        cfg.get("peer_master_url", ""), _peer_master_port(cfg)
    )
    token = str(cfg.get("peering_token", "") or "").strip()
    if not master_host or not token:
        return "Missing master host or peering token."
    master_url, resolve_err = _peer_master_base_url(cfg, timeout=4)
    if not master_url:
        return resolve_err
    if not _openssl_available():
        return "openssl not available on this system."
    instance_id = _get_instance_id(cfg)
    safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", instance_id)[:40]
    d = get_certs_dir()
    key_path = d / f"{safe_id}.key"
    csr_path = d / f"{safe_id}.csr"
    crt_path = d / f"{safe_id}.crt"
    try:
        rc, out = _run_cmd([
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path), "-out", str(csr_path),
            "-subj", f"/CN=agent-{safe_id[:20]}",
        ], timeout_sec=25)
        if rc != 0:
            return f"CSR generation failed: {out[:200]}"
        csr_pem = csr_path.read_text(encoding="utf-8")
        payload = {
            "instance_id": instance_id,
            "instance_name": str(cfg.get("instance_name", "") or ""),
            "version": VERSION,
            "monitor_count": len(cfg.get("monitors", [])) if isinstance(cfg.get("monitors", []), list) else 0,
            "csr_pem": csr_pem,
        }
        status, body = _peer_http_request(master_url, token, "POST", "/api/peer/register", payload=payload, timeout=30)
        if status >= 300:
            approval_msg = _peer_set_master_approval_status(cfg, status, body)
            if approval_msg:
                save_config(cfg, reapply_cron=False)
                return approval_msg
            return f"Register failed (HTTP {status}): {body[:300]}"
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return "Register failed: invalid response from master."
        signed_cert = str(data.get("signed_cert", "") or "").strip()
        ca_cert = str(data.get("ca_cert", "") or "").strip()
        master_cert = str(data.get("master_cert", "") or "").strip()
        if not signed_cert or not ca_cert:
            csr_note = str(data.get("csr_note", "") or "").strip()
            if csr_note:
                return (
                    "Master accepted registration but did not sign a certificate. "
                    f"{csr_note} Token-only peering still works for sync/push."
                )
            return "Register failed: master did not return signed cert + CA cert."
        crt_path.write_text(signed_cert + ("\n" if not signed_cert.endswith("\n") else ""), encoding="utf-8")
        (d / "ca.crt").write_text(ca_cert + ("\n" if not ca_cert.endswith("\n") else ""), encoding="utf-8")
        if master_cert:
            (d / "master.crt").write_text(master_cert + ("\n" if not master_cert.endswith("\n") else ""), encoding="utf-8")
            (d / "master.crt").chmod(0o644)
        key_path.chmod(0o600)
        crt_path.chmod(0o644)
        (d / "ca.crt").chmod(0o644)
        csr_path.unlink(missing_ok=True)
        cfg["peer_master_base_url"] = master_url
        save_config(cfg, reapply_cron=False)
        return "Certificate signed by master CA and stored locally."
    except Exception as e:
        hint = _peer_lan_reachability_hint(master_host, master_port)
        return f"Certificate request failed: {type(e).__name__}: {e}. {hint}"


def _agent_maybe_request_cert_bg(cfg: Dict[str, Any]) -> None:
    """After a successful push, request a signed cert from the master when OpenSSL + CA are available."""
    if str(cfg.get("peer_role", "") or "").lower() != "agent":
        return
    if not _openssl_available():
        return
    if _get_mtls_security_status(cfg).get("instance_cert_ok"):
        return
    if not str(cfg.get("peer_master_url", "") or "").strip() or not str(cfg.get("peering_token", "") or "").strip():
        return

    def _run() -> None:
        try:
            result = _agent_request_cert(load_config())
            append_ui_log(f"peer-cert | auto: {result}")
        except Exception as exc:
            append_ui_log(f"peer-cert | auto error: {type(exc).__name__}: {exc}")

    threading.Thread(target=_run, daemon=True).start()


def _agent_decode_peer_json(body: str, token: str) -> Dict[str, Any]:
    try:
        wrapped = json.loads(body)
        if isinstance(wrapped, dict) and isinstance(wrapped.get("enc"), str):
            dec = _decrypt_payload(str(wrapped.get("enc", "")), token)
            if dec:
                parsed = json.loads(dec)
                return parsed if isinstance(parsed, dict) else {}
        return wrapped if isinstance(wrapped, dict) else {}
    except (json.JSONDecodeError, ValueError, TypeError):
        return {}


def _agent_apply_hosted_monitors(cfg: Dict[str, Any], fleet_config: Dict[str, Any]) -> int:
    """Apply monitor list from hosted fleet config (safe scalar fields only)."""
    raw_monitors = fleet_config.get("monitors")
    if not isinstance(raw_monitors, list) or not raw_monitors:
        return 0
    applied: List[Dict[str, Any]] = []
    for item in raw_monitors:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        schedule = item.get("schedule") if isinstance(item.get("schedule"), dict) else {}
        interval = schedule.get("intervalMinutes", schedule.get("interval_minutes", 15))
        try:
            interval_minutes = max(1, int(interval))
        except (TypeError, ValueError):
            interval_minutes = 15
        entry: Dict[str, Any] = {
            "name": name,
            "check_mode": str(item.get("checkMode") or item.get("check_mode") or "smart").lower(),
            "enabled": bool(item.get("enabled", True)),
            "interval_minutes": interval_minutes,
        }
        field_map = (
            ("probeHost", "probe_host"),
            ("probePort", "probe_port"),
            ("dnsName", "dns_name"),
            ("dnsServer", "dns_server"),
            ("serviceNames", "service_names"),
            ("serviceDescriptionFilter", "service_description_filter"),
            ("storagePaths", "storage_paths"),
            ("mountPaths", "mount_paths"),
            ("backupTaskNames", "backup_task_names"),
        )
        for camel, snake in field_map:
            val = item.get(camel, item.get(snake))
            if val not in (None, "", []):
                entry[snake] = val
        applied.append(entry)
    if not applied:
        return 0
    cfg["monitors"] = applied
    return len(applied)


def _agent_master_recently_connected(cfg: Dict[str, Any]) -> bool:
    result = str(cfg.get("last_peer_sync_result", "") or "").strip().upper()
    if result.startswith("OK"):
        return True
    ts = int(cfg.get("last_peer_sync", 0) or 0)
    return ts > 0 and (int(time.time()) - ts) < 3600


def _agent_effective_web_enabled(cfg: Dict[str, Any]) -> bool:
    if not bool(cfg.get("web_enabled", True)):
        return False
    if bool(cfg.get("lock_local_ui_when_connected", False)) and _agent_master_recently_connected(cfg):
        return False
    return True


def _agent_apply_hosted_fleet_policy(cfg: Dict[str, Any], fleet_config: Dict[str, Any]) -> List[str]:
    defaults = fleet_config.get("defaults") if isinstance(fleet_config.get("defaults"), dict) else {}
    unix_defaults = defaults.get("unix") if isinstance(defaults.get("unix"), dict) else {}
    notes: List[str] = []
    if "webEnabled" in unix_defaults or "web_enabled" in unix_defaults:
        cfg["web_enabled"] = bool(unix_defaults.get("webEnabled", unix_defaults.get("web_enabled", True)))
        notes.append(f"web_enabled={cfg['web_enabled']}")
    return notes


def _systemd_ui_unit_name() -> str:
    return "unix-rollout-agent-ui.service" if _rollout_agent_mode() else "unix-monitor-ui.service"


def _agent_apply_web_policy(cfg: Dict[str, Any]) -> str:
    if not shutil.which("systemctl"):
        return "web policy skipped (no systemd)"
    desired = _agent_effective_web_enabled(cfg)
    unit = _systemd_ui_unit_name()
    try:
        status = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        running = (status.stdout or "").strip() == "active"
    except Exception as exc:
        return f"web policy status error: {type(exc).__name__}"
    try:
        if desired and not running:
            subprocess.run(["systemctl", "enable", "--now", unit], capture_output=True, timeout=20, check=False)
            return "web policy applied (started UI service)"
        if not desired and running:
            subprocess.run(["systemctl", "disable", "--now", unit], capture_output=True, timeout=20, check=False)
            return "web policy applied (stopped UI service)"
    except Exception as exc:
        return f"web policy apply failed: {type(exc).__name__}"
    return "web policy unchanged"


def _agent_pull_hosted_config(cfg: Dict[str, Any], *, apply_monitors: bool = False) -> str:
    if str(cfg.get("peer_role", "") or "").lower() != "agent":
        return "hosted config pull skipped (not agent role)"
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return "hosted config pull skipped (no peering token)"
    master_url, resolve_err = _peer_master_base_url(cfg, timeout=4)
    if not master_url:
        return f"hosted config pull skipped: {resolve_err}"
    instance_id = _get_instance_id(cfg)
    try:
        status, body = _peer_http_request(master_url, token, "GET", "/api/peer/config", timeout=12)
        if status >= 300:
            return f"hosted config pull failed: HTTP {status}"
        data = _agent_decode_peer_json(body, token)
        version_id = str(data.get("version") or "").strip()
        fleet_config = data.get("config") if isinstance(data.get("config"), dict) else {}
        if version_id:
            cfg["pinned_config_version_id"] = version_id
        note = f"pinned config version {version_id or '?'}"
        policy_notes: List[str] = []
        if fleet_config:
            policy_notes = _agent_apply_hosted_fleet_policy(cfg, fleet_config)
            if policy_notes:
                note = f"{note}; {', '.join(policy_notes)}"
        if apply_monitors and fleet_config:
            count = _agent_apply_hosted_monitors(cfg, fleet_config)
            if count:
                save_config(cfg, reapply_cron=True)
                web_note = _agent_apply_web_policy(cfg)
                if web_note:
                    note = f"{note}; {web_note}"
                return f"{note}; applied {count} monitor(s)"
        save_config(cfg, reapply_cron=False)
        web_note = _agent_apply_web_policy(cfg)
        if web_note:
            note = f"{note}; {web_note}"
        append_ui_log(f"peer-hosted | config pull: {note}")
        return note
    except Exception as exc:
        return f"hosted config pull error: {type(exc).__name__}: {exc}"


def _agent_ack_hosted_action(master_url: str, token: str, instance_id: str, action_id: str) -> bool:
    if not action_id:
        return False
    try:
        status, _ = _peer_http_request(
            master_url,
            token,
            "POST",
            f"/api/peer/actions/{quote(action_id, safe='')}/ack",
            payload={"instance_id": instance_id},
            timeout=12,
        )
        return status < 300
    except Exception:
        return False


def _agent_process_hosted_actions(cfg: Dict[str, Any]) -> str:
    if str(cfg.get("peer_role", "") or "").lower() != "agent":
        return "hosted actions skipped (not agent role)"
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return "hosted actions skipped (no peering token)"
    master_url, resolve_err = _peer_master_base_url(cfg, timeout=4)
    if not master_url:
        return f"hosted actions skipped: {resolve_err}"
    instance_id = _get_instance_id(cfg)
    try:
        status, body = _peer_http_request(
            master_url,
            token,
            "GET",
            f"/api/peer/actions?instance_id={quote(instance_id, safe='')}",
            timeout=12,
        )
        if status >= 300:
            return f"hosted actions pull failed: HTTP {status}"
        data = _agent_decode_peer_json(body, token)
        items = data.get("items") if isinstance(data.get("items"), list) else []
        if not items:
            return "no pending hosted actions"
        notes: List[str] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            action_id = str(item.get("actionId") or item.get("action_id") or "").strip()
            action = str(item.get("action") or "").strip()
            payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
            if action == "sync-config":
                notes.append(_agent_pull_hosted_config(cfg, apply_monitors=True))
            elif action == "update-peering-token":
                new_token = str(
                    payload.get("peeringToken") or payload.get("peering_token") or ""
                ).strip()
                if new_token:
                    cfg["peering_token"] = new_token
                    save_config(cfg, reapply_cron=False)
                    notes.append("updated peering token from master")
                else:
                    notes.append("update-peering-token missing token in payload")
            else:
                notes.append(f"ignored action {action or '?'}")
            if action_id:
                if _agent_ack_hosted_action(master_url, token, instance_id, action_id):
                    notes.append(f"acked {action_id}")
                else:
                    notes.append(f"ack failed for {action_id}")
        summary = "; ".join(n for n in notes if n)
        append_ui_log(f"peer-hosted | actions: {summary}")
        return summary or "processed hosted actions"
    except Exception as exc:
        return f"hosted actions error: {type(exc).__name__}: {exc}"


def _peer_push_to_master(cfg: Dict[str, Any]) -> str:
    master_host, master_port = _parse_peer_host_port(
        cfg.get("peer_master_url", ""), _peer_master_port(cfg)
    )
    token = str(cfg.get("peering_token", "") or "").strip()
    if not master_host or not token:
        return "Agent sync skipped: no master host or peering token configured."
    master_url, resolve_err = _peer_master_base_url(cfg, timeout=4)
    if not master_url:
        return f"Agent sync skipped: {resolve_err}"
    instance_id = _get_instance_id(cfg)
    instance_name = str(cfg.get("instance_name", "") or "").strip() or instance_id[:8]
    history = _load_history()
    state = _load_monitor_state()
    auth = _load_auth_state()
    live = _build_live_snapshot()
    monitors_cfg = live.get("monitors") or cfg.get("monitors", [])
    channels = live.get("channels") or {}
    cb_host, cb_port = _parse_peer_host_port(
        cfg.get("agent_callback_url", ""), _peer_agent_port(cfg)
    )
    push_payload: Dict[str, Any] = {
        "instance_id": instance_id,
        "instance_name": instance_name,
        "version": VERSION,
        "platform": SYSTEM_LABEL,
        "platform_family": "unix",
        "monitors": monitors_cfg,
        "channels": channels,
        "history": history[-200:],
        "state": state,
        "pushed_at": int(time.time()),
        "last_login_ip": str(auth.get("last_login_ip", "") or "").strip(),
        "last_login_at": int(auth.get("last_login_at", 0) or 0),
    }
    if cb_host:
        push_payload["callback_url"] = f"{cb_host}:{cb_port}"
    try:
        t0 = time.time()
        status, body = _peer_http_request(master_url, token, "POST", "/api/peer/push", push_payload, timeout=12)
        latency_ms = round((time.time() - t0) * 1000)
        cfg["last_peer_sync"] = int(time.time())
        cfg["last_peer_sync_latency_ms"] = latency_ms
        if status < 300:
            cfg.pop("peer_master_approval_status", None)
            cfg["last_peer_sync_result"] = f"OK ({latency_ms} ms)"
            save_config(cfg, reapply_cron=False)
            _agent_maybe_request_cert_bg(cfg)
            _agent_pull_hosted_config(cfg)
            _agent_process_hosted_actions(cfg)
            return f"Pushed to master ({master_url}): {status} ({latency_ms} ms)"
        approval_msg = _peer_set_master_approval_status(cfg, status, body)
        cfg["last_peer_sync"] = int(time.time())
        cfg["last_peer_sync_latency_ms"] = latency_ms
        cfg["last_peer_sync_result"] = f"HTTP {status}"
        save_config(cfg, reapply_cron=False)
        if approval_msg:
            return f"Master push blocked ({master_url}): {approval_msg}"
        return f"Master push failed ({master_url}): HTTP {status} - {body}"
    except Exception as e:
        cfg["last_peer_sync"] = int(time.time())
        cfg["last_peer_sync_result"] = f"Error: {type(e).__name__}"
        cfg["last_peer_sync_latency_ms"] = None
        save_config(cfg, reapply_cron=False)
        return f"Master push error: {type(e).__name__}: {e}. {_peer_lan_reachability_hint(master_host, master_port)}"


# ``PEER_DEFAULT_PORT`` + the pure peer URL/port parsing & formatting helpers
# (``_normalize_peer_port``, ``_peer_master_port``, ``_peer_agent_port``,
# ``_parse_peer_host_port``, ``_peer_url_for_input_display``,
# ``_peer_url_for_open``, ``_peer_scheme_probe_order``,
# ``_cached_peer_base_url``, ``_peer_direct_base_url``,
# ``_peer_lan_reachability_hint``) now live in
# ``src/core/peering/urls.py`` (Phase 4 Slice C). Imported at top of file.
# The network-touching resolvers below depend on ``_peer_http_request`` (mTLS)
# and stay here for now.


# The network-touching peer URL resolvers (``_resolve_peer_url`` /
# ``_resolve_peer_url_from_stored`` / ``_peer_master_base_url``) now live in
# ``src/core/peering/resolvers.py``. Imported at top of file. They take ``cfg``
# as a parameter (mutating only that passed-in dict) and consume the configured
# ``_peer_http_request`` transport, so they need no config-injection shim.


def _peer_agent_test_inputs(form: Dict[str, List[str]], cfg: Dict[str, Any]) -> Tuple[str, str]:
    """Read master host/port + token from test-connection POST (save-form or legacy hidden fields)."""
    token = (form.get("peer_token", [""])[0] or form.get("peering_token", [""])[0] or "").strip()
    raw = (form.get("peer_url", [""])[0] or "").strip()
    port_raw = (form.get("peer_master_port", [""])[0] or "").strip()
    master_port = int(port_raw) if port_raw.isdigit() else _peer_master_port(cfg)
    if not raw:
        master_host = (form.get("peer_master_url", [""])[0] or "").strip()
        if not master_host:
            master_host = str(cfg.get("peer_master_url", "") or "").strip()
        if master_host:
            host, _ = _parse_peer_host_port(master_host, master_port)
            if host:
                raw = f"{host}:{master_port}"
    if not token:
        token = str(cfg.get("peering_token", "") or "").strip()
    return raw, token


# ``_peer_http_request`` (the mTLS-aware peer transport) now lives in
# ``src/core/peering/transport.py`` (Phase 4 Slice C). Imported at top of file;
# its monolith-owned ``load_config`` / ``append_ui_log`` dependencies are
# injected via ``_peer_transport.configure(...)`` once both are defined. The
# network-touching resolvers (``_resolve_peer_url`` /
# ``_resolve_peer_url_from_stored`` / ``_peer_master_base_url``) that call it now
# live in ``src/core/peering/resolvers.py`` (also imported at top of file).


def _peer_test_connection(url: str, token: str) -> str:
    url = url.strip().rstrip("/")
    if not url or not token:
        return "Missing URL or token."
    try:
        t0 = time.time()
        status, body = _peer_http_request(url, token, "GET", "/api/peer/health", timeout=8)
        latency_ms = round((time.time() - t0) * 1000)
        if status < 300:
            try:
                data = json.loads(body)
                name = data.get("instance_name", "") or data.get("instance_id", "?")
                role = data.get("role", "?")
                ver = data.get("version", "?")
                mc = data.get("monitor_count", 0)
                return (
                    f"OK: Connected to {name} ({latency_ms} ms)\n"
                    f"  Role: {role} | Version: {ver} | Monitors: {mc}"
                )
            except (json.JSONDecodeError, ValueError):
                return f"OK: {url} responded {status} ({latency_ms} ms)"
        return f"FAILED: {url} responded HTTP {status}"
    except Exception as e:
        return f"Connection error: {type(e).__name__}: {e}"


def _probe_agent_callback_health(url_or_host: str, token: str, *, default_port: int = PEER_DEFAULT_PORT) -> str:
    """Check whether an agent callback URL responds to /api/peer/health."""
    raw = str(url_or_host or "").strip()
    token = str(token or "").strip()
    if not raw:
        return "No agent callback URL configured."
    if not token:
        return "No peering token configured."
    host, port = _parse_peer_host_port(raw, default_port)
    if not host:
        return "No agent callback host configured."
    try:
        t0 = time.time()
        resolved = _resolve_peer_url_from_stored(raw, token, timeout=10)
        if not resolved:
            resolved = _resolve_peer_url_from_stored(f"{host}:{port}", token, timeout=10)
        if not resolved:
            return f"FAILED: Cannot reach agent at {host}:{port}"
        status, body = _peer_http_request(resolved, token, "GET", "/api/peer/health", timeout=10)
        latency_ms = round((time.time() - t0) * 1000)
        if status < 300:
            return f"OK: Agent reachable at {resolved} ({latency_ms} ms)"
        detail = body.strip()[:160] if body.strip() else f"HTTP {status}"
        return f"FAILED: {detail} ({latency_ms} ms)"
    except Exception as e:
        return f"FAILED: {type(e).__name__}: {e}"


def _peer_sync_from_master(cfg: Dict[str, Any]) -> str:
    """Master pulls full snapshot from each agent, saves it, and updates peer status."""
    peers = cfg.get("peers", [])
    if not isinstance(peers, list) or not peers:
        return "No peers configured."
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return "No peering token configured."
    now = int(time.time())
    lines: List[str] = []
    for p in peers:
        pid = str(p.get("instance_id", ""))
        pname = str(p.get("instance_name", "") or pid[:8])
        p_url_raw = str(p.get("url", "") or "").strip().rstrip("/")
        if not p_url_raw:
            lines.append(f"{pname}: skipped (no URL)")
            continue
        p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=8)
        if not p_url:
            lines.append(f"{pname}: cannot reach {p_url_raw}")
            continue
        try:
            t0 = time.time()
            status, body = _peer_http_request(p_url, token, "GET", "/api/peer/snapshot", timeout=10)
            latency_ms = round((time.time() - t0) * 1000)
            if status < 300:
                p["last_seen"] = now
                p["status"] = "online"
                p["latency_ms"] = latency_ms
                try:
                    snap = json.loads(body)
                    p["monitor_count"] = len(snap.get("monitors", []))
                    p["instance_name"] = str(snap.get("instance_name", "") or pname)
                    p["version"] = str(snap.get("version", "") or "")
                    snap["received_at"] = now
                    _save_peer_snapshot(pid, snap)
                except (json.JSONDecodeError, ValueError):
                    pass
                lines.append(f"{pname}: online ({latency_ms} ms)")
            else:
                p["status"] = "offline"
                p["latency_ms"] = None
                lines.append(f"{pname}: HTTP {status}")
        except Exception as e:
            p["status"] = "offline"
            p["latency_ms"] = None
            lines.append(f"{pname}: {type(e).__name__}: {e}")
    cfg["peers"] = peers
    cfg["last_peer_sync"] = now
    save_config(cfg, reapply_cron=False)
    return "\n".join(lines) if lines else "Done."


def _trigger_peer_sync_bg(cfg: Dict[str, Any]) -> None:
    """Fire-and-forget peer sync in a background thread (agent push or master pull)."""
    role = str(cfg.get("peer_role", "") or "").lower()
    if role not in ("agent", "master"):
        return
    if not _peer_sync_guard.acquire(blocking=False):
        append_ui_log("peer-sync | auto skipped: previous sync still running")
        return

    def _do_sync() -> None:
        try:
            fresh = load_config()
            r = fresh.get("peer_role", "")
            if str(r).lower() == "agent":
                result = _peer_push_to_master(fresh)
            elif str(r).lower() == "master":
                result = _peer_sync_from_master(fresh)
            else:
                return
            append_ui_log(f"peer-sync | auto: {result}")
        except Exception as exc:
            append_ui_log(f"peer-sync | auto error: {type(exc).__name__}: {exc}")
        finally:
            _peer_sync_guard.release()
    threading.Thread(target=_do_sync, daemon=True).start()


def _agent_peer_should_push(cfg: Dict[str, Any]) -> bool:
    """True if this instance is an agent with enough config to push snapshots to the master."""
    return (
        str(cfg.get("peer_role", "") or "").lower() == "agent"
        and bool(str(cfg.get("peer_master_url", "") or "").strip())
        and bool(str(cfg.get("peering_token", "") or "").strip())
    )


def _agent_peer_push_interval_sec(cfg: Dict[str, Any]) -> int:
    try:
        raw = int(cfg.get("peer_agent_push_interval_sec", PEER_AGENT_PUSH_DEFAULT_INTERVAL_SEC) or PEER_AGENT_PUSH_DEFAULT_INTERVAL_SEC)
    except (TypeError, ValueError):
        raw = PEER_AGENT_PUSH_DEFAULT_INTERVAL_SEC
    return max(60, min(raw, 3600))


def _agent_peer_push_if_due(cfg: Dict[str, Any], *, force: bool = False) -> bool:
    """Push agent snapshot to master when peer_agent_push_interval_sec has elapsed."""
    if not _agent_peer_should_push(cfg):
        return False
    interval = _agent_peer_push_interval_sec(cfg)
    last = int(cfg.get("last_peer_sync", 0) or 0)
    now = int(time.time())
    if force or last <= 0 or (now - last) >= interval:
        _trigger_peer_sync_bg(cfg)
        return True
    return False


def _agent_peer_heartbeat_loop() -> None:
    """Background loop while the setup UI runs: push to master on an interval so the master stays 'online' after reboot."""
    time.sleep(5)
    while True:
        try:
            cfg = load_config()
            if not _agent_peer_should_push(cfg):
                time.sleep(30)
                continue
            _agent_peer_push_if_due(cfg, force=True)
            time.sleep(_agent_peer_push_interval_sec(cfg))
        except Exception:
            time.sleep(60)


def _fetch_agent_diag(
    cfg: Dict[str, Any],
    peer_id: str,
    view: str,
    log_filter: str = "all",
    log_date: str = "all",
    log_time_scope: str = "all",
    log_time_from: str = "",
    log_time_to: str = "",
    resolve_timeout: int = 15,
    fetch_timeout: int = 25,
) -> str:
    """Master fetches diagnostic text from an agent."""
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return "No peering token configured."
    peers = cfg.get("peers", [])
    target = None
    for p in (peers if isinstance(peers, list) else []):
        if str(p.get("instance_id", "")) == peer_id:
            target = p
            break
    if not target:
        return f"Agent '{peer_id}' not found in peers."
    p_name = str(target.get("instance_name", "") or peer_id[:8])
    p_url_raw = str(target.get("url", "") or "").strip().rstrip("/")
    if not p_url_raw:
        return f"No URL configured for agent '{p_name}'."
    p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=resolve_timeout)
    if not p_url:
        return f"Cannot reach agent '{p_name}' at {p_url_raw}."
    try:
        qs = (
            f"?view={quote(view)}&log_filter={quote(log_filter)}"
            f"&log_date={quote(log_date)}&log_time_scope={quote(log_time_scope)}"
            f"&log_time_from={quote(log_time_from)}&log_time_to={quote(log_time_to)}"
        )
        status, body = _peer_http_request(p_url, token, "GET", f"/api/peer/diag{qs}", timeout=fetch_timeout)
        if status < 300:
            text = body
            try:
                data = json.loads(body)
                text = str(data.get("text", body))
            except (json.JSONDecodeError, ValueError):
                pass
            header = f"--- Agent: {p_name} ({p_url}) | View: {view} ---\n\n"
            return header + text
        return f"Agent returned HTTP {status}: {body[:500]}"
    except Exception as e:
        return f"Failed to fetch from agent: {type(e).__name__}: {e}"


def _clear_agent_logs(cfg: Dict[str, Any], peer_id: str, timeout: int = 12) -> str:
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return "No peering token configured."
    peers = cfg.get("peers", [])
    target = None
    for p in (peers if isinstance(peers, list) else []):
        if str(p.get("instance_id", "")) == peer_id:
            target = p
            break
    if not target:
        return f"Agent '{peer_id}' not found in peers."
    p_name = str(target.get("instance_name", "") or peer_id[:8])
    p_url_raw = str(target.get("url", "") or "").strip().rstrip("/")
    if not p_url_raw:
        return f"No URL configured for agent '{p_name}'."
    p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=8)
    if not p_url:
        return f"Cannot reach agent '{p_name}' at {p_url_raw}."
    try:
        status, body = _peer_http_request(p_url, token, "POST", "/api/peer/clear-logs", payload={}, timeout=timeout)
        if status < 300:
            try:
                data = json.loads(body)
                msg = str(data.get("message", "Remote logs cleared"))
            except Exception:
                msg = "Remote logs cleared"
            return f"{p_name}: {msg}"
        return f"{p_name}: HTTP {status} - {body[:300]}"
    except Exception as e:
        return f"{p_name}: {type(e).__name__}: {e}"


def _trigger_agent_update(cfg: Dict[str, Any], peer_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Master triggers update on agent. Returns (session_id, error). session_id None on error."""
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return None, "No peering token configured."
    peers = cfg.get("peers", [])
    target = None
    for p in (peers if isinstance(peers, list) else []):
        if str(p.get("instance_id", "")) == peer_id:
            target = p
            break
    if not target:
        return None, f"Agent '{peer_id}' not found in peers."
    update_supported, _source_platform, update_block_reason = _peer_update_capability(cfg, peer_id)
    if not update_supported:
        return None, update_block_reason
    p_url_raw = str(target.get("url", "") or "").strip().rstrip("/")
    if not p_url_raw:
        return None, f"No URL configured for agent."
    p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=10)
    if not p_url:
        return None, f"Cannot reach agent at {p_url_raw}."
    try:
        status, body = _peer_http_request(p_url, token, "POST", "/api/peer/update", payload={}, timeout=15)
        if status in (200, 202):
            try:
                data = json.loads(body)
                return str(data.get("session_id", "") or ""), None
            except (json.JSONDecodeError, ValueError):
                return None, f"Invalid response: {body[:200]}"
        try:
            err = json.loads(body)
            msg = str(err.get("error", body))[:500]
            tb = err.get("traceback", "")
            if tb:
                return None, f"HTTP {status}: {msg}\n\nTraceback:\n{tb[:1500]}"
            return None, f"HTTP {status}: {msg}"
        except (json.JSONDecodeError, ValueError):
            return None, f"HTTP {status}: {body[:500]}"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _fetch_agent_update_status(cfg: Dict[str, Any], peer_id: str, session_id: str) -> Dict[str, Any]:
    """Master fetches update status from agent."""
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return {"error": "No peering token configured."}
    peers = cfg.get("peers", [])
    target = None
    for p in (peers if isinstance(peers, list) else []):
        if str(p.get("instance_id", "")) == peer_id:
            target = p
            break
    if not target:
        return {"error": f"Agent '{peer_id}' not found."}
    p_url_raw = str(target.get("url", "") or "").strip().rstrip("/")
    if not p_url_raw:
        return {"error": "No URL configured for agent."}
    p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=5)
    if not p_url:
        return {"error": f"Cannot reach agent at {p_url_raw}."}
    try:
        qs = f"?session_id={quote(session_id)}"
        status, body = _peer_http_request(p_url, token, "GET", f"/api/peer/update-status{qs}", timeout=10)
        if status < 300:
            try:
                return json.loads(body) if body else {}
            except (json.JSONDecodeError, ValueError):
                return {"error": "Invalid response", "raw": body[:200]}
        try:
            err = json.loads(body)
            return {"error": str(err.get("error", body))[:500], "stage": err.get("stage", "unknown")}
        except (json.JSONDecodeError, ValueError):
            return {"error": f"HTTP {status}", "stage": "unknown"}
    except Exception as e:
        return {"error": str(e), "stage": "unknown"}


def _diagnose_agent_diag_connection(cfg: Dict[str, Any], peer_id: str) -> str:
    """Run step-by-step diagnostic for master->agent log fetch. Returns a detailed report."""
    lines: List[str] = []
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return "Diagnostic: No peering token configured."
    peers = cfg.get("peers", []) or []
    target = None
    for p in peers:
        if str(p.get("instance_id", "")) == peer_id:
            target = p
            break
    if not target:
        return f"Diagnostic: Agent '{peer_id}' not found in peers."
    p_name = str(target.get("instance_name", "") or peer_id[:8])
    p_url_raw = str(target.get("url", "") or "").strip().rstrip("/")
    lines.append(f"=== Master->Agent Diag Connection Diagnostic ===")
    lines.append(f"Agent: {p_name} (id={peer_id})")
    lines.append(f"Stored URL: {p_url_raw or '(empty)'}")
    lines.append("")
    if not p_url_raw:
        lines.append("FAIL: No URL configured. Set the agent URL in Settings > Peering > Connected Agents.")
        return "\n".join(lines)
    host, port = _parse_peer_host_port(p_url_raw)
    lines.append(f"Parsed host: {host or '(none)'}  port: {port}")
    lines.append("")
    # Step 1: Try HTTPS
    lines.append("Step 1: Resolve URL (try HTTPS, then HTTP)...")
    t0 = time.time()
    try:
        resolved = _resolve_peer_url_from_stored(p_url_raw, token, timeout=15)
        elapsed = round((time.time() - t0) * 1000)
        if resolved:
            lines.append(f"  OK: Resolved to {resolved} ({elapsed} ms)")
        else:
            lines.append(f"  FAIL: Could not reach agent ({elapsed} ms). Tried HTTPS and HTTP on {host}:{port}.")
            lines.append("  Check: firewall, network path, agent service running, correct IP/hostname.")
            return "\n".join(lines)
    except Exception as ex:
        lines.append(f"  FAIL: {type(ex).__name__}: {ex}")
        return "\n".join(lines)
    # Step 2: Health check
    lines.append("")
    lines.append("Step 2: Health check (GET /api/peer/health)...")
    t0 = time.time()
    try:
        status, body = _peer_http_request(resolved, token, "GET", "/api/peer/health", timeout=10)
        elapsed = round((time.time() - t0) * 1000)
        if status < 300:
            lines.append(f"  OK: HTTP {status} ({elapsed} ms)")
        else:
            lines.append(f"  FAIL: HTTP {status} ({elapsed} ms) - {body[:200]}")
    except Exception as ex:
        lines.append(f"  FAIL: {type(ex).__name__}: {ex} (timeout or connection error)")
        lines.append("  If timeout: agent may be slow, on different VLAN, or firewall blocking.")
        return "\n".join(lines)
    # Step 3: Diag fetch
    lines.append("")
    lines.append("Step 3: Fetch diag (GET /api/peer/diag?view=logs)...")
    t0 = time.time()
    try:
        status, body = _peer_http_request(resolved, token, "GET", "/api/peer/diag?view=logs&log_filter=all", timeout=25)
        elapsed = round((time.time() - t0) * 1000)
        if status < 300:
            lines.append(f"  OK: HTTP {status} ({elapsed} ms, body ~{len(body)} chars)")
        else:
            lines.append(f"  FAIL: HTTP {status} ({elapsed} ms) - {body[:200]}")
    except Exception as ex:
        lines.append(f"  FAIL: {type(ex).__name__}: {ex} (timeout or connection error)")
        lines.append("  Diag payload can be large; try increasing timeout or check network latency.")
        return "\n".join(lines)
    lines.append("")
    lines.append("All steps passed. Log fetch should work.")
    return "\n".join(lines)


def _peer_create_remote_monitor(cfg: Dict[str, Any], peer_id: str,
                                monitor_cfg: Dict[str, Any]) -> str:
    """Master sends a monitor config to an agent for creation."""
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return "No peering token set."
    peers = cfg.get("peers", [])
    target = None
    for p in peers:
        if str(p.get("instance_id", "")) == peer_id:
            target = p
            break
    if not target:
        return f"Peer {peer_id} not found."
    p_url_raw = str(target.get("url", "") or "").strip().rstrip("/")
    if not p_url_raw:
        return f"Peer {target.get('instance_name', peer_id[:8])} has no URL configured."
    p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=10)
    if not p_url:
        return f"Cannot reach peer at {p_url_raw}."
    try:
        status, body = _peer_http_request(
            p_url, token, "POST", "/api/peer/create-monitor",
            payload=monitor_cfg, timeout=10,
        )
        if status < 300:
            return f"Monitor created on {target.get('instance_name', peer_id[:8])}: {body.strip()}"
        return f"Failed (HTTP {status}): {body.strip()}"
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


def _trigger_agent_monitor_action(
    cfg: Dict[str, Any],
    peer_id: str,
    action: str,
    monitor_name: str = "",
    timeout: int = 20,
) -> Tuple[bool, str, str]:
    token = str(cfg.get("peering_token", "") or "").strip()
    if not token:
        return False, "No peering token configured.", ""
    peers = cfg.get("peers", [])
    target = None
    for p in (peers if isinstance(peers, list) else []):
        if str(p.get("instance_id", "")) == peer_id:
            target = p
            break
    if not target:
        return False, f"Agent '{peer_id}' not found in peers.", ""
    p_name = str(target.get("instance_name", "") or peer_id[:8])
    p_url_raw = str(target.get("url", "") or "").strip().rstrip("/")
    if not p_url_raw:
        return False, f"No URL configured for agent '{p_name}'.", ""
    p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=8)
    if not p_url:
        return False, f"Cannot reach agent '{p_name}' at {p_url_raw}.", ""
    payload = {
        "action": action,
        "monitor_name": monitor_name,
        "triggered_by": "master",
    }
    try:
        status, body = _peer_http_request(p_url, token, "POST", "/api/peer/monitor-action", payload=payload, timeout=timeout)
        if status < 300:
            try:
                data = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                data = {}
            msg = str(data.get("message", f"Action '{action}' executed on agent")).strip()
            out = str(data.get("output", "") or "").strip()
            return True, f"{p_name}: {msg}", out
        try:
            err = json.loads(body)
            err_msg = str(err.get("error", body)).strip()
        except (json.JSONDecodeError, ValueError):
            err_msg = body.strip()[:500]
        return False, f"{p_name}: HTTP {status} - {err_msg}", ""
    except Exception as e:
        return False, f"{p_name}: {type(e).__name__}: {e}", ""


def _agent_request_master_monitor_action(
    cfg: Dict[str, Any],
    action: str,
    monitor_name: str = "",
    timeout: int = 25,
) -> Tuple[bool, str, str]:
    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
    if role != "agent":
        return False, "This action is only supported on agent role.", ""
    master_host, master_port = _parse_peer_host_port(
        cfg.get("peer_master_url", ""), _peer_master_port(cfg)
    )
    token = str(cfg.get("peering_token", "") or "").strip()
    if not master_host or not token:
        return False, "Missing master host or peering token.", ""
    master_url = _resolve_peer_url(master_host, master_port, token, timeout=10)
    if not master_url:
        return False, f"Cannot reach master at {master_host}:{master_port}.", ""
    payload = {
        "instance_id": _get_instance_id(cfg),
        "action": action,
        "monitor_name": monitor_name,
    }
    try:
        status, body = _peer_http_request(master_url, token, "POST", "/api/peer/trigger-monitor-action", payload=payload, timeout=timeout)
        if status < 300:
            try:
                data = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                data = {}
            msg = str(data.get("message", "Action executed via master")).strip()
            out = str(data.get("output", "") or "").strip()
            return True, msg, out
        try:
            err = json.loads(body)
            err_msg = str(err.get("error", body)).strip()
        except (json.JSONDecodeError, ValueError):
            err_msg = body.strip()[:500]
        return False, f"HTTP {status} - {err_msg}", ""
    except Exception as e:
        return False, f"{type(e).__name__}: {e}", ""


def _infer_peer_source_platform(cfg: Dict[str, Any], peer_id: str) -> str:
    for p in (cfg.get("peers", []) or []):
        if str(p.get("instance_id", "")) != peer_id:
            continue
        direct = str(p.get("platform", "") or "")
        if direct:
            return _normalize_source_platform(direct)
        probe = " ".join(
            [
                str(p.get("instance_name", "") or ""),
                str(p.get("version", "") or ""),
                str(p.get("url", "") or ""),
            ]
        )
        if "synology" in probe.lower() or "dsm" in probe.lower():
            return "synology"
    snap = _load_peer_snapshot(peer_id) or {}
    for key in ("platform", "platform_family", "instance_name", "version"):
        val = str(snap.get(key, "") or "")
        if "synology" in val.lower() or "dsm" in val.lower():
            return "synology"
    return "unix"


def _infer_peer_source_platform_for_update(cfg: Dict[str, Any], peer_id: str) -> str:
    for p in (cfg.get("peers", []) or []):
        if str(p.get("instance_id", "")) != peer_id:
            continue
        direct = str(p.get("platform", "") or "").strip().lower()
        if direct:
            if "synology" in direct or direct == "dsm":
                return "synology"
            # Non-Synology explicit platform values default to updatable Unix-class agents.
            return "unix"
        for key in ("platform_family", "instance_name", "version", "url"):
            val = str(p.get(key, "") or "").strip().lower()
            if not val:
                continue
            if "synology" in val or "dsm" in val:
                return "synology"
    snap = _load_peer_snapshot(peer_id) or {}
    for key in ("platform", "platform_family"):
        val = str(snap.get(key, "") or "").strip().lower()
        if not val:
            continue
        if "synology" in val or "dsm" in val:
            return "synology"
        return "unix"
    return "unknown"


def _is_unknown_update_override_enabled(cfg: Dict[str, Any], peer_id: str) -> bool:
    raw = cfg.get("allow_unknown_update_peers", [])
    if not isinstance(raw, list):
        return False
    return peer_id in {str(x or "").strip() for x in raw}


def _set_unknown_update_override(cfg: Dict[str, Any], peer_id: str, enabled: bool) -> None:
    raw = cfg.get("allow_unknown_update_peers", [])
    ids = {str(x or "").strip() for x in (raw if isinstance(raw, list) else []) if str(x or "").strip()}
    if enabled:
        ids.add(peer_id)
    else:
        ids.discard(peer_id)
    cfg["allow_unknown_update_peers"] = sorted(ids)


def _peer_update_capability(cfg: Dict[str, Any], peer_id: str) -> Tuple[bool, str, str]:
    source_platform = _infer_peer_source_platform_for_update(cfg, peer_id)
    if source_platform == "synology":
        return False, source_platform, "Synology updates are manual (Package Center/SPK)."
    if source_platform == "unix":
        return True, source_platform, ""
    if _is_unknown_update_override_enabled(cfg, peer_id):
        return True, "unknown", ""
    return False, "unknown", "Unknown platform; update blocked by default."


def _peer_agent_platform_display(cfg: Dict[str, Any], peer_id: str) -> Tuple[str, str]:
    snap = _load_peer_snapshot(peer_id) or {}
    plat = str(snap.get("platform", "") or "").strip()
    fam = str(snap.get("platform_family", "") or "").strip()
    for p in (cfg.get("peers", []) or []):
        if str(p.get("instance_id", "")) != peer_id:
            continue
        if not plat:
            plat = str(p.get("platform", "") or "").strip()
        if not fam:
            fam = str(p.get("platform_family", "") or "").strip()
        break
    return plat, fam


def _peer_update_options_hint_inner_html(cfg: Dict[str, Any], peer_id: str) -> str:
    plat, fam = _peer_agent_platform_display(cfg, peer_id)
    explain = (
        "Remote updates are only offered when this master recognizes the agent as a supported Unix install. "
        "If the agent does not advertise a known platform, updates stay disabled until you allow them here."
    )
    det_parts = []
    if plat:
        det_parts.append(f"OS: {plat}")
    if fam:
        det_parts.append(f"family: {fam}")
    det = " · ".join(det_parts) if det_parts else "Not reported yet (wait for the next agent sync)."
    return (
        f"<div class='peer-update-options-hint'>"
        f"<p class='muted' style='font-size:11px;line-height:1.4;margin:0 0 8px 0;'>{html.escape(explain)}</p>"
        f"<p style='font-size:11px;line-height:1.4;margin:0 0 10px 0;color:#c8dbf8;'>{html.escape(det)}</p>"
        f"</div>"
    )


def get_smart_cache_path() -> Path:
    return get_runtime_data_dir() / "unix-smart-cache.json"


def get_system_log_cache_path() -> Path:
    return get_runtime_data_dir() / "unix-system-log-cache.json"


def _write_smart_cache(payload: Dict[str, Any]) -> None:
    path = get_smart_cache_path()
    tmp = path.parent / ".unix-smart-cache.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(str(tmp), str(path))
        path.chmod(0o644)
    except OSError:
        pass


def _write_system_log_cache(payload: Dict[str, Any]) -> None:
    path = get_system_log_cache_path()
    tmp = path.parent / ".unix-system-log-cache.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(str(tmp), str(path))
        path.chmod(0o644)
    except OSError:
        pass


def _read_smart_cache() -> Optional[Dict[str, Any]]:
    path = get_smart_cache_path()
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _read_system_log_cache() -> Optional[Dict[str, Any]]:
    path = get_system_log_cache_path()
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def get_backup_cache_path() -> Path:
    return get_runtime_data_dir() / "unix-backup-cache.json"


def _write_backup_cache(payload: Dict[str, Any]) -> None:
    path = get_backup_cache_path()
    tmp = path.parent / ".unix-backup-cache.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(str(tmp), str(path))
        path.chmod(0o644)
    except OSError:
        pass


def _read_backup_cache() -> Optional[Dict[str, Any]]:
    path = get_backup_cache_path()
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def get_backup_helper_script_path() -> Path:
    return get_script_path().parent / "backup-helper.sh"


def get_smart_helper_script_path() -> Path:
    return get_script_path().parent / "smart-helper.sh"


def get_update_helper_path() -> Path:
    return get_script_path().parent / "update-helper.sh"


def _update_helper_env(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Env for update-helper: UNIX_MONITOR_USE_MAIN=1 when update_from_main is enabled."""
    if cfg is None:
        cfg = load_config()
    if cfg.get("update_from_main"):
        return {"UNIX_MONITOR_USE_MAIN": "1"}
    return {}


def _get_update_check_path() -> Path:
    return get_runtime_data_dir() / "unix-update-check.json"


def _version_tuple(version: str) -> Tuple[int, ...]:
    """Parse '1.5.0-0001' or 'v1.0.0-0055' to (1, 0, 0, 55) for comparison."""
    s = str(version or "").strip().lstrip("vV")
    if not s:
        return (0, 0, 0, 0)
    main, _, build = s.partition("-")
    parts = [int(x or 0) for x in re.split(r"[.]", main)[:3]]
    while len(parts) < 3:
        parts.append(0)
    try:
        parts.append(int(build.strip()) if build.strip() else 0)
    except ValueError:
        parts.append(0)
    return tuple(parts[:4])


def _version_display_short(version: str, max_len: int = 24) -> str:
    raw = str(version or "").strip()
    if not raw:
        return "unknown"
    short = raw.split("+", 1)[0].strip() or raw
    if len(short) <= max_len:
        return short
    return short[:max_len] + "..."


def _selected_update_channel(cfg: Optional[Dict[str, Any]] = None) -> str:
    if cfg is None:
        cfg = load_config()
    return "main" if bool(cfg.get("update_from_main", False)) else "latest"


def _fetch_latest_release_tag() -> Tuple[Optional[str], Optional[str]]:
    try:
        req = http.client.HTTPSConnection("api.github.com", timeout=10)
        req.request(
            "GET",
            f"/repos/{GITHUB_REPO}/releases/latest",
            headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "unix-monitor"},
        )
        resp = req.getresponse()
        data = resp.read().decode("utf-8", errors="ignore")
        req.close()
        if resp.status != 200:
            return None, f"HTTP {resp.status}"
        obj = json.loads(data)
        tag = str(obj.get("tag_name", "") or "").strip().lstrip("vV")
        if not tag:
            return None, "No tag_name in response"
        return tag, None
    except Exception as e:
        return None, str(e) if str(e) else type(e).__name__


def _fetch_public_version_from_script(ref: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        req = http.client.HTTPSConnection("raw.githubusercontent.com", timeout=10)
        ref_path = quote(ref, safe="")
        req.request("GET", f"/{GITHUB_REPO}/{ref_path}/{UPDATE_SCRIPT_REMOTE_PATH}", headers={"User-Agent": "unix-monitor"})
        resp = req.getresponse()
        data = resp.read().decode("utf-8", errors="ignore")
        req.close()
        if resp.status != 200:
            return None, f"HTTP {resp.status}"
        m = re.search(r'^VERSION\s*=\s*"([^"]+)"', data, flags=re.MULTILINE)
        if not m:
            return None, "No VERSION in script"
        return m.group(1).strip(), None
    except Exception as e:
        return None, str(e) if str(e) else type(e).__name__


def _run_update_check(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Fetch selected channel public version, compare with local VERSION. Returns result dict."""
    channel = _selected_update_channel(cfg)
    result: Dict[str, Any] = {
        "checked_at": int(time.time()),
        "error": None,
        "latest_version": None,
        "public_version": None,
        "selected_channel": channel,
        "selected_ref": None,
        "effective_ref": None,
        "update_available": False,
    }
    try:
        if channel == "main":
            ref = "main"
        else:
            tag, tag_err = _fetch_latest_release_tag()
            if tag_err or not tag:
                result["error"] = tag_err or "Failed to resolve latest release"
                return result
            ref = tag

        result["selected_ref"] = ref
        effective_ref = ref
        public_version, version_err = _fetch_public_version_from_script(ref)
        if (version_err or not public_version) and ref != "main":
            # Match update-helper behavior: release tags may not include unix-monitor; fall back to main.
            public_version, version_err = _fetch_public_version_from_script("main")
            if not version_err and public_version:
                effective_ref = "main"
        if version_err or not public_version:
            result["error"] = version_err or "Failed to resolve public script version"
            return result

        result["public_version"] = public_version
        result["latest_version"] = public_version  # Backward compatibility with existing cache consumers
        result["effective_ref"] = effective_ref
        current = _version_tuple(VERSION)
        latest = _version_tuple(public_version)
        result["update_available"] = latest > current
    except Exception as e:
        result["error"] = str(e) if str(e) else type(e).__name__
    return result


def _save_update_check_result(result: Dict[str, Any]) -> None:
    path = _get_update_check_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.parent / ".unix-update-check.json.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        os.replace(str(tmp), str(path))
    except Exception:
        pass


def _load_update_check_result() -> Dict[str, Any]:
    path = _get_update_check_path()
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _update_check_needs_refresh(
    cfg: Optional[Dict[str, Any]] = None,
    last: Optional[Dict[str, Any]] = None,
    ttl_sec: int = AUTOUPDATE_CHECK_INTERVAL_SEC,
) -> bool:
    if cfg is None:
        cfg = load_config()
    if last is None:
        last = _load_update_check_result()
    if not isinstance(last, dict) or not last:
        return True
    selected_channel = _selected_update_channel(cfg)
    cached_channel = str(last.get("selected_channel", "") or "")
    if cached_channel != selected_channel:
        return True
    checked_at = int(last.get("checked_at", 0) or 0)
    if checked_at <= 0:
        return True
    return (int(time.time()) - checked_at) >= int(ttl_sec)


def _ensure_fresh_update_check(
    cfg: Optional[Dict[str, Any]] = None,
    force: bool = False,
    ttl_sec: int = AUTOUPDATE_CHECK_INTERVAL_SEC,
) -> Dict[str, Any]:
    if cfg is None:
        cfg = load_config()
    last = _load_update_check_result()
    if not force and not _update_check_needs_refresh(cfg=cfg, last=last, ttl_sec=ttl_sec):
        return last
    result = _run_update_check(cfg)
    _save_update_check_result(result)
    return result


def _parse_info_version_text(content: str) -> str:
    m = re.search(r'^version="([^"]+)"', str(content or ""), flags=re.MULTILINE)
    return str(m.group(1)).strip() if m else ""


def _detect_installed_unix_monitor_version() -> str:
    info_candidates = [
        Path("/var/packages/synology-monitor/INFO"),
        Path("/var/packages/synology-monitor/target/INFO"),
        Path("/usr/local/synology-monitor/INFO"),
        Path("/opt/synology-monitor/INFO"),
    ]
    for p in info_candidates:
        try:
            if p.exists():
                txt = p.read_text(encoding="utf-8", errors="ignore")
                v = _parse_info_version_text(txt)
                if v:
                    return v
        except OSError:
            continue
    py_candidates = [
        Path("/opt/unix-monitor/unix-monitor.py"),
        get_script_path(),
    ]
    for p in py_candidates:
        try:
            if p.exists():
                txt = p.read_text(encoding="utf-8", errors="ignore")
                m = re.search(r'^VERSION\s*=\s*"([^"]+)"', txt, flags=re.MULTILINE)
                if m:
                    return str(m.group(1)).strip()
        except OSError:
            continue
    return VERSION


def _version_cmp_value(a: str, b: str) -> int:
    ta = _version_tuple(a)
    tb = _version_tuple(b)
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def _build_unix_update_sync_report(cfg: Optional[Dict[str, Any]] = None, force: bool = True) -> Dict[str, Any]:
    if cfg is None:
        cfg = load_config()
    check = _ensure_fresh_update_check(cfg=cfg, force=force, ttl_sec=AUTOUPDATE_CHECK_INTERVAL_SEC)
    installed = _detect_installed_unix_monitor_version()
    public_version = str(check.get("public_version", "") or check.get("latest_version", "") or "").strip()
    cmp_val = _version_cmp_value(installed or "0", public_version or "0") if public_version else 0
    status = "unknown"
    if check.get("error"):
        status = "error"
    elif public_version:
        status = "update_available" if cmp_val < 0 else "up_to_date"
    return {
        "installed_version": installed or VERSION,
        "public_version": public_version,
        "selected_channel": str(check.get("selected_channel", "") or _selected_update_channel(cfg)),
        "error": str(check.get("error", "") or "").strip(),
        "cmp": cmp_val,
        "status": status,
        "raw_check": check,
    }


def _cleanup_update_runtime_cache() -> None:
    cleanup_paths = [
        Path("/var/lib/unix-monitor/__pycache__"),
        Path("/var/lib/unix-monitor/cache"),
        Path.home() / ".cache" / "unix-monitor",
    ]
    for p in cleanup_paths:
        try:
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            elif p.exists():
                p.unlink()
        except Exception:
            pass


def _get_autoupdate_on_logout_flag_path() -> Path:
    return get_runtime_data_dir() / "unix-autoupdate-on-logout.flag"


def _get_agent_update_session_path() -> Path:
    return get_runtime_data_dir() / "unix-agent-update-session.json"


def _load_agent_update_session() -> Dict[str, Any]:
    path = _get_agent_update_session_path()
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_agent_update_session(data: Dict[str, Any]) -> None:
    path = _get_agent_update_session_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.parent / ".unix-agent-update-session.json.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(str(tmp), str(path))
    except OSError:
        pass


def _run_agent_update_background() -> str:
    """Run update-helper in background, streaming output to session file. Returns session_id."""
    session_id = secrets.token_hex(8)
    helper = get_update_helper_path()
    script_dir = str(get_script_path().parent)
    append_ui_log(f"peer-update | session {session_id} helper={helper} script_dir={script_dir}")
    if not helper.exists():
        append_ui_log(f"peer-update | helper missing at {helper}")
        try:
            _save_agent_update_session({
                "session_id": session_id,
                "stage": "failed",
                "log": [],
                "error": "Update helper not found",
                "started_at": int(time.time()),
                "updated_at": int(time.time()),
            })
        except Exception as e:
            append_ui_log(f"peer-update | save session failed: {type(e).__name__}: {e}")
            raise
        return session_id
    try:
        _save_agent_update_session({
            "session_id": session_id,
            "stage": "running",
            "log": [],
            "error": None,
            "started_at": int(time.time()),
            "updated_at": int(time.time()),
        })
    except Exception as e:
        append_ui_log(f"peer-update | save session failed: {type(e).__name__}: {e}")
        raise

    def _do_update() -> None:
        log_lines: List[str] = []
        try:
            cfg = load_config()
            proc_env = {**os.environ, **_update_helper_env(cfg)}
            proc = subprocess.Popen(
                [str(helper), script_dir, "update", "no-restart"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=proc_env,
            )
            assert proc.stdout
            for line in iter(proc.stdout.readline, ""):
                line = line.rstrip("\n")
                if line:
                    log_lines.append(line)
                    sess = _load_agent_update_session()
                    sess["log"] = list(log_lines)
                    sess["updated_at"] = int(time.time())
                    _save_agent_update_session(sess)
            proc.wait()
            sess = _load_agent_update_session()
            sess["log"] = list(log_lines)
            sess["stage"] = "done" if proc.returncode == 0 else "failed"
            sess["error"] = None if proc.returncode == 0 else f"Exit code {proc.returncode}"
            sess["updated_at"] = int(time.time())
            _save_agent_update_session(sess)
            if proc.returncode == 0:
                time.sleep(2)
                for u in ("unix-monitor-ui.service", "unix-monitor-scheduler.timer", "unix-monitor-smart-helper.timer", "unix-monitor-backup-helper.timer", "unix-monitor-system-log-helper.timer"):
                    _run_cmd(["systemctl", "restart", u], timeout_sec=10)
        except Exception as e:
            log_lines.append(f"Error: {e}")
            sess = _load_agent_update_session()
            sess["log"] = list(log_lines)
            sess["stage"] = "failed"
            sess["error"] = str(e)
            sess["updated_at"] = int(time.time())
            _save_agent_update_session(sess)

    threading.Thread(target=_do_update, daemon=True).start()
    return session_id


def _maybe_run_autoupdate(defer_if_user_logged_in: bool = True) -> None:
    """Background: if autoupdate enabled, check for updates. If available and not deferred, run update. Throttled.
    When defer_if_user_logged_in=True (page load), only check and save result; do not apply.
    When defer_if_user_logged_in=False (e.g. logout), apply update if available."""
    try:
        cfg = load_config()
        result = _ensure_fresh_update_check(cfg=cfg, force=False, ttl_sec=AUTOUPDATE_CHECK_INTERVAL_SEC)
        if defer_if_user_logged_in:
            return
        if not cfg.get("autoupdate_enabled"):
            return
        if not result.get("update_available"):
            return
        helper = get_update_helper_path()
        if not helper.exists():
            return
        script_dir = str(get_script_path().parent)
        rc, out = _run_cmd([str(helper), script_dir, "update", "no-restart"], timeout_sec=30, env=_update_helper_env(cfg))
        if rc != 0:
            append_ui_log(f"autoupdate | failed: {out.strip() or rc}")
            return
        append_ui_log(f"autoupdate | updated to {result.get('latest_version', '?')}")

        def _delayed_restart() -> None:
            time.sleep(2)
            for u in ("unix-monitor-ui.service", "unix-monitor-scheduler.timer", "unix-monitor-smart-helper.timer", "unix-monitor-backup-helper.timer", "unix-monitor-system-log-helper.timer"):
                _run_cmd(["systemctl", "restart", u], timeout_sec=10)

        threading.Thread(target=_delayed_restart, daemon=True).start()
    except Exception:
        pass


def get_task_guide_images() -> Dict[str, Path]:
    base = get_script_path().parent
    return {
        "task-scheduler-guide.png": base / "task-scheduler-guide.png",
        "task-step-general.png": base / "task-step-general.png",
        "task-step-schedule.png": base / "task-step-schedule.png",
        "task-step-command.png": base / "task-step-command.png",
    }


def get_task_status_path() -> Path:
    return get_runtime_data_dir() / "unix-task-status.json"


def _write_task_status(payload: Dict[str, Any]) -> None:
    path = get_task_status_path()
    tmp = path.parent / ".unix-task-status.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(str(tmp), str(path))
        path.chmod(0o644)
    except OSError:
        pass


def _read_task_status() -> Optional[Dict[str, Any]]:
    path = get_task_status_path()
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _detect_task_hint() -> str:
    helper = str(get_smart_helper_script_path())
    for crontab_path in ("/etc/crontab", "/etc/crontab.user"):
        try:
            text = Path(crontab_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if helper in text:
            return f"Found helper reference in {crontab_path}"
    return "No task hint detected in system crontab files"


def get_history_path() -> Path:
    return get_runtime_data_dir() / "unix-monitor-history.json"


def get_monitor_state_path() -> Path:
    return get_runtime_data_dir() / "unix-monitor-state.json"


def get_schedule_state_path() -> Path:
    return get_runtime_data_dir() / "unix-schedule-state.json"


def _load_monitor_state() -> Dict[str, Dict[str, Any]]:
    p = get_monitor_state_path()
    if not p.exists():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        out: Dict[str, Dict[str, Any]] = {}
        for k, v in data.items():
            if isinstance(k, str) and isinstance(v, dict):
                out[k] = v
        return out
    except (OSError, json.JSONDecodeError):
        return {}


def _save_monitor_state(state: Dict[str, Dict[str, Any]]) -> None:
    p = get_monitor_state_path()
    tmp = p.parent / ".unix-monitor-state.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(str(tmp), str(p))
        p.chmod(0o644)
    except OSError:
        pass


def _set_monitor_state(name: str, banner: str, output: str, level: str = "ok") -> None:
    state = _load_monitor_state()
    state[name] = {
        "banner": banner,
        "output": output,
        "level": "err" if level == "err" else "ok",
        "updated_at": int(time.time()),
    }
    _save_monitor_state(state)


def _is_scheduled_due(interval_minutes: int, monitor_name: str = "") -> bool:
    if interval_minutes < 1:
        interval_minutes = 1
    state = _read_schedule_state()
    now = int(time.time())
    if monitor_name:
        per_mon = state.get("per_monitor", {})
        last_run = int(per_mon.get(monitor_name, 0) or 0)
    else:
        last_run = int(state.get("last_run_ts", 0) or 0)
    if now - last_run < interval_minutes * 60:
        return False
    return True


def _touch_scheduled_run(monitor_name: str = "") -> None:
    p = get_schedule_state_path()
    state = _read_schedule_state()
    now = int(time.time())
    state["last_run_ts"] = now
    if monitor_name:
        state.setdefault("per_monitor", {})[monitor_name] = now
    tmp = p.parent / ".unix-schedule-state.json.tmp"
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(str(tmp), str(p))
        p.chmod(0o644)
    except OSError:
        pass


def _read_schedule_state() -> Dict[str, Any]:
    p = get_schedule_state_path()
    if not p.exists():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _scheduler_pid_path() -> Path:
    return Path("/var/lib/unix-monitor/scheduler.pid")


def _scheduler_service_path() -> Path:
    return Path("/usr/local/bin/unix-monitor-service")


def _systemd_show_properties(unit: str, props: List[str]) -> Dict[str, str]:
    if not unit or not props:
        return {}
    cmd = ["systemctl", "show", unit, "--no-pager"]
    for prop in props:
        cmd.extend(["-p", prop])
    rc, out = _run_cmd(cmd, timeout_sec=8)
    if rc != 0:
        return {}
    data: Dict[str, str] = {}
    for ln in (out or "").splitlines():
        if "=" not in ln:
            continue
        k, v = ln.split("=", 1)
        if k and k not in data:
            data[k] = v.strip()
    return data


def _systemd_timer_status(timer_unit: str) -> Dict[str, str]:
    keys = ["LoadState", "ActiveState", "SubState", "NextElapseUSecRealtime", "LastTriggerUSec", "UnitFileState"]
    data = _systemd_show_properties(timer_unit, keys)
    if not data:
        return {
            "load_state": "unknown",
            "active_state": "unknown",
            "sub_state": "unknown",
            "next": "n/a",
            "last": "n/a",
            "unit_file_state": "unknown",
        }
    return {
        "load_state": data.get("LoadState", "unknown"),
        "active_state": data.get("ActiveState", "unknown"),
        "sub_state": data.get("SubState", "unknown"),
        "next": data.get("NextElapseUSecRealtime", "n/a"),
        "last": data.get("LastTriggerUSec", "n/a"),
        "unit_file_state": data.get("UnitFileState", "unknown"),
    }


def _scheduler_status_data(cfg: Dict[str, Any]) -> Dict[str, Any]:
    interval = int(cfg.get("cron_interval_minutes", 60) or 60)
    cron_enabled = bool(cfg.get("cron_enabled", False))
    backend = str(cfg.get("scheduler_backend", "cron")).strip().lower()
    if backend not in ("systemd", "cron"):
        backend = "cron"
    cfg_path = str(get_config_path())
    runtime_dir = str(get_runtime_data_dir())
    state = _read_schedule_state()
    last_ts = int(state.get("last_run_ts", 0) or 0)
    last_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_ts)) if last_ts else "never"
    due_text = "yes" if _is_scheduled_due(interval) else "no"
    helper_ok, helper_msg = get_smart_helper_status()
    lines: List[str]
    scheduler_process = "n/a"
    scheduler_timer = "n/a"
    timer_next = "n/a"
    timer_last = "n/a"
    pid_text = "missing"
    if backend == "systemd":
        t = _systemd_timer_status("unix-monitor-scheduler.timer")
        timer_running = t.get("active_state") == "active"
        scheduler_timer = (
            f"{'active' if timer_running else 'inactive'} "
            f"(state={t.get('active_state')}/{t.get('sub_state')}, unit={t.get('unit_file_state')})"
        )
        timer_next = str(t.get("next", "n/a"))
        timer_last = str(t.get("last", "n/a"))
        lines = [
            f"Scheduler backend: {backend}",
            f"Scheduler timer: {scheduler_timer}",
            "Scheduler service mode: systemd oneshot (no persistent PID expected)",
            f"Automatic checks enabled (global): {'yes' if cron_enabled else 'no'}",
            f"Configured scheduler interval: {interval} minute(s)",
            f"Timer next trigger: {timer_next}",
            f"Timer last trigger: {timer_last}",
            f"Last scheduled run (state file): {last_text}",
            f"SMART elevated cache: {'active' if helper_ok else 'inactive'} | {helper_msg}",
            f"Config file: {cfg_path}",
            f"Runtime data dir: {runtime_dir}",
            f"Scheduler service script: {_scheduler_service_path()}",
        ]
    else:
        pid_path = _scheduler_pid_path()
        running = False
        if pid_path.exists():
            try:
                pid = int(pid_path.read_text(encoding="utf-8", errors="ignore").strip() or "0")
                pid_text = str(pid) if pid > 0 else "invalid"
                if pid > 0:
                    try:
                        os.kill(pid, 0)
                        running = True
                    except OSError:
                        running = False
            except (OSError, ValueError):
                pid_text = "invalid"
        scheduler_process = f"{'running' if running else 'not running'} (pid={pid_text})"
        lines = [
            f"Scheduler backend: {backend}",
            f"Scheduler process: {scheduler_process}",
            f"Automatic checks enabled (global): {'yes' if cron_enabled else 'no'}",
            f"Configured scheduler interval: {interval} minute(s)",
            f"Last scheduled run: {last_text}",
            f"SMART elevated cache: {'active' if helper_ok else 'inactive'} | {helper_msg}",
            f"Config file: {cfg_path}",
            f"Runtime data dir: {runtime_dir}",
            f"Scheduler service script: {_scheduler_service_path()}",
        ]
    per_mon = state.get("per_monitor", {})
    monitors = cfg.get("monitors", [])
    if monitors:
        lines.append("")
        lines.append("Per-monitor schedule:")
    per_monitor_rows: List[Dict[str, Any]] = []
    if monitors:
        for m in monitors:
            mn = str(m.get("name", "?"))
            mi = int(m.get("interval", interval) or interval)
            mc = bool(m.get("cron_enabled", cron_enabled))
            mlr = int(per_mon.get(mn, 0) or 0)
            mlr_text = time.strftime("%H:%M:%S", time.localtime(mlr)) if mlr else "never"
            due = "yes" if _is_scheduled_due(mi, mn) else "no"
            lines.append(f"  {mn}: {mi}m | cron={'on' if mc else 'off'} | last={mlr_text} | due={due}")
            per_monitor_rows.append({
                "name": mn,
                "interval_minutes": mi,
                "enabled": mc,
                "last_run": mlr_text,
                "due": due,
            })
    return {
        "backend": backend,
        "global_enabled": cron_enabled,
        "global_interval_minutes": interval,
        "last_scheduled_run": last_text,
        "is_due": due_text,
        "scheduler_process": scheduler_process if backend != "systemd" else "systemd oneshot",
        "scheduler_timer": scheduler_timer,
        "timer_next": timer_next,
        "timer_last": timer_last,
        "smart_cache_active": helper_ok,
        "smart_cache_message": helper_msg,
        "config_path": cfg_path,
        "runtime_dir": runtime_dir,
        "service_script": str(_scheduler_service_path()),
        "monitor_rows": per_monitor_rows,
        "raw_text": "\n".join(lines),
    }


def _scheduler_status_text(cfg: Dict[str, Any]) -> str:
    return str(_scheduler_status_data(cfg).get("raw_text", ""))


def _load_history() -> List[Dict[str, Any]]:
    p = get_history_path()
    if not p.exists():
        return []
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        return []
    except (OSError, json.JSONDecodeError):
        return []


def _save_history(entries: List[Dict[str, Any]]) -> None:
    p = get_history_path()
    tmp = p.parent / ".unix-monitor-history.json.tmp"
    trimmed = entries[-HISTORY_MAX_ENTRIES:]
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(trimmed, f, indent=2)
        os.replace(str(tmp), str(p))
        p.chmod(0o644)
    except OSError:
        pass


def _prune_ui_log_for_monitor(name: str) -> None:
    path = get_ui_log_path()
    if not path.exists():
        return
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        keep: List[str] = []
        needle = name.strip()
        for ln in lines:
            low = ln.lower()
            # Remove monitor-specific lines while keeping global diagnostics.
            if f"| {needle} |" in ln or f"{needle}:" in ln:
                continue
            if "delete-monitor" in low and needle in ln:
                continue
            keep.append(ln)
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(keep[-UI_LOG_MAX_LINES * 3 :])
        path.chmod(CONFIG_FILE_MODE)
    except OSError:
        pass


def _delete_monitor_runtime_data(name: str) -> None:
    # Remove history entries for this monitor so "last run" does not carry over.
    entries = _load_history()
    filtered = [e for e in entries if str(e.get("monitor", "")) != name]
    if len(filtered) != len(entries):
        _save_history(filtered)

    # Remove persistent monitor card status/result banner.
    state = _load_monitor_state()
    if name in state:
        state.pop(name, None)
        _save_monitor_state(state)

    # Remove monitor-related lines from UI log.
    _prune_ui_log_for_monitor(name)


def _record_history(monitor_name: str, mode: str, status: str, ping_ms: float) -> None:
    now = int(time.time())
    entries = _load_history()
    channels = [mode]
    for channel in channels:
        entries.append(
            {
                "ts": now,
                "monitor": monitor_name,
                "mode": mode,
                "channel": channel,
                "status": status,
                "ping_ms": round(float(ping_ms), 2),
            }
        )
    _save_history(entries)


def _tail_text_file(path: Path, max_lines: int = 120) -> str:
    if not path.exists():
        return f"{path}: missing"
    try:
        lines = _read_tail_lines(path, max_lines=max_lines)
        tail = "".join(lines).strip()
        return tail if tail else f"{path}: empty"
    except OSError as e:
        return f"{path}: {type(e).__name__}: {e}"


def _extract_error_lines(text: str, max_lines: int = 80) -> str:
    patt = re.compile(r"(error|fail|failed|warning|warn|traceback|permission denied|exception)", re.IGNORECASE)
    lines = [ln for ln in (text or "").splitlines() if patt.search(ln)]
    if not lines:
        return "No error/warning lines found."
    return "\n".join(lines[-max_lines:])


def _build_task_diag_text(cfg: Dict[str, Any]) -> str:
    interval = int(cfg.get("cron_interval_minutes", 60) or 60)
    cron_enabled = bool(cfg.get("cron_enabled", False))
    backend = str(cfg.get("scheduler_backend", "cron")).strip().lower()
    if backend not in ("systemd", "cron"):
        backend = "cron"
    sched_state = _read_schedule_state()
    last_sched = int(sched_state.get("last_run_ts", 0) or 0)
    last_sched_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_sched)) if last_sched else "never"

    pid_val = 0
    running = False
    timer_diag = ""
    if backend == "systemd":
        t = _systemd_timer_status("unix-monitor-scheduler.timer")
        running = t.get("active_state") == "active"
        timer_diag = (
            f"- scheduler timer: {'active' if running else 'inactive'} "
            f"(state={t.get('active_state')}/{t.get('sub_state')}, unit={t.get('unit_file_state')})\n"
            "- scheduler service mode: systemd oneshot (no persistent PID expected)\n"
            f"- timer next trigger: {t.get('next', 'n/a')}\n"
            f"- timer last trigger: {t.get('last', 'n/a')}\n"
        )
    else:
        pid_path = _scheduler_pid_path()
        if pid_path.exists():
            try:
                pid_val = int(pid_path.read_text(encoding="utf-8", errors="ignore").strip() or "0")
                if pid_val > 0:
                    try:
                        os.kill(pid_val, 0)
                        running = True
                    except OSError:
                        running = False
            except (OSError, ValueError):
                pid_val = 0

    helper_ok, helper_msg = get_smart_helper_status()
    cache = _read_smart_cache() or {}
    helper_checked = int(cache.get("checked_at", 0) or 0)
    helper_checked_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(helper_checked)) if helper_checked else "never"

    cron_text = "(cron backend not selected)"
    if backend == "cron":
        rc, out = _run_cmd(["crontab", "-l"], timeout_sec=8)
        if rc == 0:
            cron_lines = [ln for ln in out.splitlines() if "unix-monitor" in ln]
            cron_text = "\n".join(cron_lines) if cron_lines else "(no unix-monitor crontab entries)"
        else:
            cron_text = f"(crontab unavailable rc={rc})"

    auto_task = _read_task_status()
    auto_task_text = json.dumps(auto_task, indent=2) if auto_task else "No auto-create task attempts recorded."

    helper_log = Path("/var/lib/unix-monitor/smart-helper.log")
    backup_helper_log = Path("/var/lib/unix-monitor/backup-helper.log")
    sched_log = Path("/var/lib/unix-monitor/monitor-scheduler.log")

    backup_cache = _read_backup_cache() or {}
    backup_checked = int(backup_cache.get("checked_at", 0) or 0)
    backup_checked_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(backup_checked)) if backup_checked else "never"
    backup_overall = str(backup_cache.get("overall", "n/a"))

    per_mon = sched_state.get("per_monitor", {})
    monitors = cfg.get("monitors", [])
    per_mon_lines = []
    for m in monitors:
        mn = str(m.get("name", "?"))
        mi = int(m.get("interval", interval) or interval)
        mc = bool(m.get("cron_enabled", cron_enabled))
        mlr = int(per_mon.get(mn, 0) or 0)
        mlr_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mlr)) if mlr else "never"
        per_mon_lines.append(f"  {mn}: interval={mi}m, cron={'on' if mc else 'off'}, last_run={mlr_text}")
    per_mon_text = "\n".join(per_mon_lines) if per_mon_lines else "  (no monitors)"

    scheduler_line = (
        f"- scheduler process: {'running' if running else 'not running'} (pid={pid_val or 'n/a'})\n"
        if backend == "cron"
        else timer_diag
    )

    return (
        "Automation Overview\n"
        f"- scheduler backend: {backend}\n"
        f"- automatic checks enabled (global): {'yes' if cron_enabled else 'no'}\n"
        f"- configured scheduler interval: {interval} minute(s)\n"
        f"{scheduler_line}"
        f"- last scheduled run: {last_sched_text}\n"
        f"\nPer-monitor schedule:\n{per_mon_text}\n"
        f"- SMART helper cache: {'active' if helper_ok else 'inactive'} (last: {helper_checked_text})\n"
        f"- SMART helper message: {helper_msg}\n"
        f"- Backup helper cache: last={backup_checked_text} overall={backup_overall}\n\n"
        "Crontab entries (unix-monitor; cron backend only)\n"
        f"{cron_text}\n\n"
        "Auto-create task status\n"
        f"{auto_task_text}\n\n"
        "Scheduler log (tail)\n"
        f"{_tail_text_file(sched_log)}\n\n"
        "SMART helper log (tail)\n"
        f"{_tail_text_file(helper_log)}\n\n"
        "Backup helper log (tail)\n"
        f"{_tail_text_file(backup_helper_log)}"
    )


def _build_system_diag_text() -> str:
    ui_log = _tail_text_file(get_ui_log_path(), max_lines=200)
    helper_log = _tail_text_file(Path("/var/lib/unix-monitor/smart-helper.log"), max_lines=160)
    backup_helper_log_text = _tail_text_file(Path("/var/lib/unix-monitor/backup-helper.log"), max_lines=100)
    sched_log = _tail_text_file(Path("/var/lib/unix-monitor/monitor-scheduler.log"), max_lines=160)
    sys_cache = _read_system_log_cache() or {}
    cache_checked = int(sys_cache.get("checked_at", 0) or 0)
    cache_checked_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cache_checked)) if cache_checked else "never"
    cache_age = max(0, int(time.time()) - cache_checked) if cache_checked else -1
    system_log_text = ""
    if sys_cache:
        src = str(sys_cache.get("source", "unknown"))
        errs = str(sys_cache.get("errors", "") or "No error/warning lines found.")
        system_log_text = f"Cached by root helper @ {cache_checked_text} (age={cache_age}s)\nSource: {src}\n{errs}"
    else:
        system_log_text = "No root system-log cache yet. Run system-log helper once or wait for scheduler."

    return (
        "Package UI log (tail)\n"
        f"{ui_log}\n\n"
        "Scheduler errors/warnings (filtered)\n"
        f"{_extract_error_lines(sched_log, max_lines=80)}\n\n"
        "SMART helper errors/warnings (filtered)\n"
        f"{_extract_error_lines(helper_log, max_lines=80)}\n\n"
        "Backup helper log (tail)\n"
        f"{backup_helper_log_text or '(no log yet)'}\n\n"
        "System log errors/warnings (filtered)\n"
        f"{system_log_text}"
    )


def _build_diag_text(
    cfg: Dict[str, Any],
    history: List[Dict[str, Any]],
    diag_view: str,
    log_filter: str,
    log_date: str = "all",
    log_time_scope: str = "all",
    log_time_from: str = "",
    log_time_to: str = "",
) -> str:
    view = (diag_view or "logs").strip().lower()
    if view == "task":
        return _build_task_diag_text(cfg)
    if view == "config":
        return json.dumps(cfg, indent=2)
    if view == "cache":
        smart_cache = _read_smart_cache()
        backup_cache = _read_backup_cache()
        parts: List[str] = []
        parts.append("=== SMART Helper Cache ===")
        parts.append(json.dumps(smart_cache, indent=2) if smart_cache else "No SMART helper cache yet.")
        parts.append("")
        parts.append("=== Backup Helper Cache ===")
        parts.append(json.dumps(backup_cache, indent=2) if backup_cache else "No Backup helper cache yet.")
        return "\n".join(parts)
    if view == "history":
        return json.dumps(history[-120:], indent=2) if history else "No run history yet."
    if view == "paths":
        details = {
            "config_path": str(get_config_path()),
            "ui_log_path": str(get_ui_log_path()),
            "smart_cache_path": str(get_smart_cache_path()),
            "backup_cache_path": str(get_backup_cache_path()),
            "system_log_cache_path": str(get_system_log_cache_path()),
            "task_status_path": str(get_task_status_path()),
            "helper_script_path": str(get_smart_helper_script_path()),
            "backup_helper_script_path": str(get_backup_helper_script_path()),
            "task_hint": _detect_task_hint(),
        }
        return json.dumps(details, indent=2)
    if view == "system":
        return _build_system_diag_text()
    return read_ui_log(
        log_filter=log_filter,
        log_date=log_date,
        log_time_scope=log_time_scope,
        log_time_from=log_time_from,
        log_time_to=log_time_to,
    )


def _build_live_snapshot() -> Dict[str, Any]:
    cfg = load_config()
    history = _load_history()
    state = _load_monitor_state()

    channels_order = ("smart", "storage", "ping", "port", "dns", "backup", "service")
    used_channels: List[str] = []
    for m in cfg.get("monitors", []):
        mode = str(m.get("check_mode", "smart")).lower()
        if mode in channels_order and mode not in used_channels:
            used_channels.append(mode)
    for e in history:
        ch = str(e.get("channel", "")).lower()
        if ch in channels_order and ch not in used_channels:
            used_channels.append(ch)
    used_channels = [c for c in channels_order if c in used_channels]
    if not used_channels:
        used_channels = ["smart", "storage"]

    channel_data: Dict[str, Dict[str, Any]] = {}
    for channel in used_channels:
        items = [e for e in history if str(e.get("channel")) == channel]
        latest = items[-1] if items else {}
        st = str(latest.get("status", "unknown"))
        pct = {"up": 100, "warning": 55, "down": 15}.get(st, 0)
        ts = int(latest.get("ts", 0) or 0)
        channel_data[channel] = {
            "status": st,
            "pct": pct,
            "ts": ts,
            "history_statuses": [str(x.get("status", "unknown")) for x in items[-20:]],
        }

    monitor_latest: Dict[str, Dict[str, Any]] = {}
    for e in history:
        name = str(e.get("monitor", ""))
        if name:
            monitor_latest[name] = e

    monitors: List[Dict[str, Any]] = []
    for m in cfg.get("monitors", []):
        if m.get("_remote_peer"):
            continue
        name = str(m.get("name", "?"))
        mode = str(m.get("check_mode", "smart"))
        latest = monitor_latest.get(name, {})
        st = str(latest.get("status", "unknown"))
        ping = latest.get("ping_ms", "n/a")
        ts = int(latest.get("ts", 0) or 0)
        s = state.get(name, {})
        monitors.append(
            {
                "name": name,
                "mode": mode,
                "status": st,
                "ping_ms": ping,
                "ts": ts,
                "banner": str(s.get("banner", "") or ""),
                "output": str(s.get("output", "") or ""),
                "level": "err" if str(s.get("level", "ok")) == "err" else "ok",
                "origin": "local",
            }
        )

    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
    peers_summary: List[Dict[str, Any]] = []
    peers_cfg_map: Dict[str, Dict[str, Any]] = {}
    for pc in (cfg.get("peers", []) or []):
        pcid = str(pc.get("instance_id", ""))
        if pcid:
            peers_cfg_map[pcid] = pc
    sync_info: Dict[str, Any] = {
        "role": role,
        "last_sync": int(cfg.get("last_peer_sync", 0) or 0),
        "last_sync_result": str(cfg.get("last_peer_sync_result", "") or ""),
        "last_sync_latency_ms": cfg.get("last_peer_sync_latency_ms"),
    }
    if role == "master":
        now = int(time.time())
        token = str(cfg.get("peering_token", "") or "").strip()
        for snap in _load_all_peer_snapshots():
            peer_id = str(snap.get("instance_id", "") or "").strip()
            if not peer_id or peer_id not in peers_cfg_map:
                continue
            peer_name = str(snap.get("instance_name", "") or peer_id[:8])
            received_at = int(snap.get("received_at", 0) or 0)
            pc_info = peers_cfg_map.get(peer_id, {})
            cfg_last_seen = int(pc_info.get("last_seen", 0) or 0)
            best_seen = max(received_at, cfg_last_seen)
            age = now - best_seen if best_seen else 9999
            peer_status = "online" if age < PEER_HEALTH_TIMEOUT_SEC else "offline"
            peer_latency = pc_info.get("latency_ms")
            p_url_raw = str(pc_info.get("url", "") or "").strip().rstrip("/")
            p_url = p_url_raw
            if peer_status == "offline" and p_url_raw and token:
                try:
                    p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=5)
                    t0 = time.time()
                    hst, _ = _peer_http_request(p_url, token, "GET", "/api/peer/health", timeout=5)
                    if hst < 300:
                        peer_status = "online"
                        peer_latency = round((time.time() - t0) * 1000)
                        best_seen = now
                except Exception:
                    pass
            update_supported, source_platform, update_block_reason = _peer_update_capability(cfg, peer_id)
            peers_summary.append({
                "instance_id": peer_id,
                "instance_name": peer_name,
                "status": peer_status,
                "last_seen": best_seen,
                "monitor_count": len(snap.get("monitors", [])),
                "latency_ms": peer_latency,
                "url": p_url,
                "open_url": _peer_url_for_open(p_url),
                "version": str(pc_info.get("version", "") or ""),
                "agent_platform": str(snap.get("platform", "") or ""),
                "agent_platform_family": str(snap.get("platform_family", "") or ""),
                "source_platform": source_platform,
                "update_supported": update_supported,
                "update_block_reason": update_block_reason,
                "unknown_update_allowed": _is_unknown_update_override_enabled(cfg, peer_id),
            })
            peer_history = snap.get("history", [])
            peer_state_raw = snap.get("state", {})
            peer_state: Dict[str, Dict[str, Any]] = {}
            if isinstance(peer_state_raw, dict):
                for mk, mv in peer_state_raw.items():
                    k = str(mk or "").strip()
                    if not k:
                        continue
                    peer_state[k] = mv if isinstance(mv, dict) else {}
            elif isinstance(peer_state_raw, list):
                # Backward-compatible read path: older peers may serialize state as a list.
                for item in peer_state_raw:
                    if not isinstance(item, dict):
                        continue
                    mk = (
                        str(item.get("monitor", "") or "").strip()
                        or str(item.get("name", "") or "").strip()
                        or str(item.get("monitor_name", "") or "").strip()
                    )
                    if not mk:
                        continue
                    peer_state[mk] = item
            for e in peer_history:
                ch = str(e.get("channel", "")).lower()
                if ch in channels_order and ch not in used_channels:
                    used_channels.append(ch)
            for channel in channels_order:
                items = [e for e in peer_history if str(e.get("channel")) == channel]
                if not items:
                    continue
                if channel not in channel_data:
                    used_channels_set = set(used_channels)
                    if channel not in used_channels_set:
                        used_channels.append(channel)
                    latest = items[-1]
                    st = str(latest.get("status", "unknown"))
                    pct = {"up": 100, "warning": 55, "down": 15}.get(st, 0)
                    ts = int(latest.get("ts", 0) or 0)
                    channel_data[channel] = {
                        "status": st, "pct": pct, "ts": ts,
                        "history_statuses": [str(x.get("status", "unknown")) for x in items[-20:]],
                    }
                else:
                    existing = channel_data[channel]
                    latest = items[-1]
                    if int(latest.get("ts", 0) or 0) > existing.get("ts", 0):
                        st = str(latest.get("status", "unknown"))
                        existing["status"] = st
                        existing["pct"] = {"up": 100, "warning": 55, "down": 15}.get(st, 0)
                        existing["ts"] = int(latest.get("ts", 0) or 0)
                    combined_hist = existing.get("history_statuses", []) + [str(x.get("status", "unknown")) for x in items[-10:]]
                    existing["history_statuses"] = combined_hist[-20:]
            peer_monitor_latest: Dict[str, Dict[str, Any]] = {}
            for e in peer_history:
                mn = str(e.get("monitor", ""))
                if mn:
                    peer_monitor_latest[mn] = e
            for pm in snap.get("monitors", []):
                pname = _peer_monitor_name(pm, "?")
                pmode = _peer_monitor_mode(pm)
                platest = peer_monitor_latest.get(pname, {})
                pst = str(platest.get("status", "unknown"))
                pping = platest.get("ping_ms", "n/a")
                pts = int(platest.get("ts", 0) or 0)
                ps = peer_state.get(pname, {})
                monitors.append({
                    "name": pname,
                    "mode": pmode,
                    "status": pst,
                    "ping_ms": pping,
                    "ts": pts,
                    "banner": str(ps.get("banner", "") or ""),
                    "output": str(ps.get("output", "") or ""),
                    "level": "err" if str(ps.get("level", "ok")) == "err" else "ok",
                    "origin": peer_name,
                })

    return {
        "generated_at": int(time.time()),
        "channels": channel_data,
        "monitors": monitors,
        "peers": peers_summary,
        "sync": sync_info,
    }


def _build_live_snapshot_for_source(source_id: str = "local") -> Dict[str, Any]:
    """Build a live snapshot scoped to one source context (local or a peer instance_id)."""
    base = _build_live_snapshot()
    cfg = load_config()
    local_name = str(cfg.get("instance_name", "") or "").strip() or "Local"
    sid = (source_id or "local").strip()
    if sid == "local":
        base["source_id"] = "local"
        base["source_name"] = local_name
        base["source_scope"] = "local"
        return base

    if not _is_valid_peer_instance_id(sid):
        base["source_id"] = "local"
        base["source_name"] = local_name
        base["source_scope"] = "local"
        return base

    snap = _load_peer_snapshot(sid)
    if not snap:
        base["source_id"] = "local"
        base["source_name"] = local_name
        base["source_scope"] = "local"
        return base

    if sid not in _registered_peer_instance_ids(cfg):
        base["source_id"] = "local"
        base["source_name"] = local_name
        base["source_scope"] = "local"
        return base

    channels_order = ("smart", "storage", "ping", "port", "dns", "backup", "service")
    peer_name = str(snap.get("instance_name", "") or sid[:8])
    peer_history = snap.get("history", [])
    peer_state_raw = snap.get("state", {})
    peer_state: Dict[str, Dict[str, Any]] = {}
    if isinstance(peer_state_raw, dict):
        for mk, mv in peer_state_raw.items():
            k = str(mk or "").strip()
            if not k:
                continue
            peer_state[k] = mv if isinstance(mv, dict) else {}
    elif isinstance(peer_state_raw, list):
        # Backward-compatible read path: older peers may serialize state as a list.
        for item in peer_state_raw:
            if not isinstance(item, dict):
                continue
            mk = (
                str(item.get("monitor", "") or "").strip()
                or str(item.get("name", "") or "").strip()
                or str(item.get("monitor_name", "") or "").strip()
            )
            if not mk:
                continue
            peer_state[mk] = item
    peer_monitors_cfg = snap.get("monitors", [])

    used_channels: List[str] = []
    for pm in peer_monitors_cfg:
        mode = str(pm.get("check_mode", "smart")).lower()
        if mode in channels_order and mode not in used_channels:
            used_channels.append(mode)
    for e in peer_history:
        ch = str(e.get("channel", "")).lower()
        if ch in channels_order and ch not in used_channels:
            used_channels.append(ch)
    used_channels = [c for c in channels_order if c in used_channels] or ["smart", "storage"]

    channel_data: Dict[str, Dict[str, Any]] = {}
    for channel in used_channels:
        items = [e for e in peer_history if str(e.get("channel")) == channel]
        latest = items[-1] if items else {}
        st = str(latest.get("status", "unknown"))
        pct = {"up": 100, "warning": 55, "down": 15}.get(st, 0)
        ts = int(latest.get("ts", 0) or 0)
        channel_data[channel] = {
            "status": st,
            "pct": pct,
            "ts": ts,
            "history_statuses": [str(x.get("status", "unknown")) for x in items[-20:]],
        }

    peer_monitor_latest: Dict[str, Dict[str, Any]] = {}
    for e in peer_history:
        mn = str(e.get("monitor", ""))
        if mn:
            peer_monitor_latest[mn] = e

    monitors: List[Dict[str, Any]] = []
    for pm in peer_monitors_cfg:
        pname = _peer_monitor_name(pm, "?")
        pmode = _peer_monitor_mode(pm)
        platest = peer_monitor_latest.get(pname, {})
        pst = str(platest.get("status", "unknown"))
        pping = platest.get("ping_ms", "n/a")
        pts = int(platest.get("ts", 0) or 0)
        ps = peer_state.get(pname, {})
        monitors.append(
            {
                "name": pname,
                "mode": pmode,
                "status": pst,
                "ping_ms": pping,
                "ts": pts,
                "banner": str(ps.get("banner", "") or ""),
                "output": str(ps.get("output", "") or ""),
                "level": "err" if str(ps.get("level", "ok")) == "err" else "ok",
                "origin": peer_name,
            }
        )

    base["channels"] = channel_data
    base["monitors"] = monitors
    base["source_id"] = sid
    base["source_name"] = peer_name
    base["source_scope"] = "remote"
    return base


def get_smart_helper_status() -> Tuple[bool, str]:
    if os.geteuid() == 0:
        return True, "Package is running as root."
    cache = _read_smart_cache()
    if not cache:
        return False, "No root helper cache found yet."
    checked_at = int(cache.get("checked_at", 0) or 0)
    age = max(0, int(time.time()) - checked_at)
    if age <= SMART_CACHE_MAX_AGE_SEC:
        return True, f"Root helper cache is active (age {age}s)."
    return False, f"Root helper cache is stale (age {age}s)."


def _ui_auto_create_task_beta() -> str:
    helper_script = str(get_smart_helper_script_path())
    if not Path(helper_script).exists():
        msg = f"Helper script not found: {helper_script}"
        append_ui_log(f"auto-task | failed | {msg}")
        _write_task_status(
            {
                "attempted_at": int(time.time()),
                "success": False,
                "summary": msg,
                "detail": msg,
            }
        )
        return msg

    attempts: List[str] = []
    success = False
    summary = "Auto-create task failed; use manual Task Scheduler setup."

    # Attempt 1: create non-root cron entry for current package user.
    cron_line = f"*/5 * * * * {helper_script} # unix-monitor smart helper beta"
    rc, out = _run_cmd(["crontab", "-l"], timeout_sec=8)
    if rc == 127:
        attempts.append("crontab: command not found")
    else:
        current = out if rc == 0 else ""
        if cron_line not in current:
            new_cron = (current.rstrip() + "\n" + cron_line + "\n").lstrip("\n")
            try:
                p = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
                p.communicate(new_cron)
                if p.returncode == 0:
                    success = True
                    summary = "Created package-user cron task. Change user to root in DSM Task Scheduler if needed."
                    attempts.append("crontab: created package-user cron entry")
                else:
                    attempts.append("crontab: failed to install entry")
            except OSError as e:
                attempts.append(f"crontab: failed to execute ({type(e).__name__}: {e})")
        else:
            success = True
            summary = "Cron entry already exists for helper script."
            attempts.append("crontab: entry already exists")

    # Attempt 2: probe TaskScheduler API availability for diagnostics (best-effort).
    rc, out = _run_cmd(
        ["synowebapi", "--exec", "api=SYNO.Core.TaskScheduler", "version=1", "method=list"],
        timeout_sec=10,
    )
    probe_line = f"synowebapi probe rc={rc}"
    if out.strip():
        probe_line += f" detail={out.strip().replace(chr(10), ' ')[:300]}"
    attempts.append(probe_line)

    detail = " | ".join(attempts)
    if len(detail) > TASK_STATUS_MAX_DETAIL:
        detail = detail[: TASK_STATUS_MAX_DETAIL - 3] + "..."
    _write_task_status(
        {
            "attempted_at": int(time.time()),
            "success": success,
            "summary": summary,
            "detail": detail,
        }
    )
    append_ui_log(f"auto-task | {'success' if success else 'failed'} | {summary}")
    append_ui_log(f"auto-task-detail | {detail}")
    return summary + "\n" + detail


def _enforce_config_permissions(path: Path) -> None:
    try:
        if path.exists():
            current = stat.S_IMODE(path.stat().st_mode)
            if current != CONFIG_FILE_MODE:
                path.chmod(CONFIG_FILE_MODE)
    except OSError:
        pass


def normalize_kuma_url(url: str) -> str:
    parsed = urlparse(url.strip())
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path}"
    return base.rstrip("/")


def validate_kuma_url(url: str) -> Optional[str]:
    parsed = urlparse(url.strip())
    if parsed.scheme not in ALLOWED_SCHEMES:
        return f"Scheme must be http or https, got '{parsed.scheme}'"
    if not parsed.hostname:
        return "No hostname in URL"
    if not KUMA_PUSH_PATH_PATTERN.match(parsed.path or ""):
        return f"Path must match /api/push/<token>, got '{parsed.path}'"
    return None


def kuma_token_label(url: str) -> str:
    parsed = urlparse(url.strip())
    m = re.match(r"^/api/push/([A-Za-z0-9_-]+)$", parsed.path or "")
    if not m:
        return "(invalid token path)"
    token = m.group(1)
    if len(token) <= 10:
        return token
    return f"{token[:5]}...{token[-4:]}"


def load_config() -> Dict[str, Any]:
    path = get_config_path()
    if not path.exists():
        _migrate_config_if_needed(path)
    if not path.exists():
        return {"monitors": []}
    _enforce_config_permissions(path)
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  Config error: {e}")
        return {"monitors": []}

    changed = False
    if "ui_bind_host" not in cfg:
        cfg["ui_bind_host"] = "0.0.0.0"
        changed = True
    if "ui_bind_port" not in cfg:
        cfg["ui_bind_port"] = 8787
        changed = True
    norm_ui_host = _normalize_ui_bind_host(cfg.get("ui_bind_host", "0.0.0.0"))
    if norm_ui_host != str(cfg.get("ui_bind_host", "0.0.0.0")):
        cfg["ui_bind_host"] = norm_ui_host
        changed = True
    old_ui_port_raw = cfg.get("ui_bind_port", 8787)
    try:
        old_ui_port = int(old_ui_port_raw if old_ui_port_raw is not None else 8787)
    except (TypeError, ValueError):
        old_ui_port = 8787
    norm_ui_port = _normalize_ui_bind_port(cfg.get("ui_bind_port", 8787))
    if norm_ui_port != old_ui_port:
        cfg["ui_bind_port"] = norm_ui_port
        changed = True
    internet_mode = _normalize_internet_check_mode(cfg.get("internet_check_mode", "tcp-connect"))
    if internet_mode != str(cfg.get("internet_check_mode", "tcp-connect") or "tcp-connect").strip().lower():
        cfg["internet_check_mode"] = internet_mode
        changed = True
    internet_timeout_ms = _normalize_internet_check_timeout_ms(cfg.get("internet_check_timeout_ms", 1500))
    old_internet_timeout_raw = cfg.get("internet_check_timeout_ms", 1500)
    try:
        old_internet_timeout = int(old_internet_timeout_raw if old_internet_timeout_raw is not None else 1500)
    except (TypeError, ValueError):
        old_internet_timeout = 1500
    if internet_timeout_ms != old_internet_timeout:
        cfg["internet_check_timeout_ms"] = internet_timeout_ms
        changed = True
    internet_port_profile = _normalize_internet_check_port_profile(cfg.get("internet_check_port_profile", "dns"))
    if internet_port_profile != str(cfg.get("internet_check_port_profile", "dns") or "dns").strip().lower():
        cfg["internet_check_port_profile"] = internet_port_profile
        changed = True
    internet_custom_port = _normalize_internet_check_custom_port(cfg.get("internet_check_custom_port", 53))
    old_internet_custom_port_raw = cfg.get("internet_check_custom_port", 53)
    try:
        old_internet_custom_port = int(old_internet_custom_port_raw if old_internet_custom_port_raw is not None else 53)
    except (TypeError, ValueError):
        old_internet_custom_port = 53
    if internet_custom_port != old_internet_custom_port:
        cfg["internet_check_custom_port"] = internet_custom_port
        changed = True
    internet_targets = _internet_check_targets_display(
        _parse_internet_check_targets(
            cfg.get("internet_check_targets", ""),
            port_profile=internet_port_profile,
            custom_port=internet_custom_port,
        )
    )
    if internet_targets != str(cfg.get("internet_check_targets", "") or "").strip():
        cfg["internet_check_targets"] = internet_targets
        changed = True
    internet_dns_servers = _internet_check_targets_display(
        _parse_internet_check_targets(
            cfg.get("internet_check_dns_servers", DEFAULT_INTERNET_CHECK_DNS_SERVERS),
            port_profile="dns",
            custom_port=53,
        )
    )
    if internet_dns_servers != str(cfg.get("internet_check_dns_servers", "") or "").strip():
        cfg["internet_check_dns_servers"] = internet_dns_servers
        changed = True
    monitors = [m for m in cfg.get("monitors", []) if isinstance(m, dict)]
    for monitor in monitors:
        cleaned = normalize_kuma_url(monitor.get("kuma_url", ""))
        if cleaned != monitor.get("kuma_url", ""):
            monitor["kuma_url"] = cleaned
            changed = True
        mode = str(monitor.get("check_mode", "smart")).lower()
        if mode == "both":
            monitor["check_mode"] = "smart"
            changed = True
        elif mode not in CHECK_MODES:
            monitor["check_mode"] = "smart"
            changed = True

    # Normalize legacy duplicate monitor names: keep the newest definition by name.
    seen: set[str] = set()
    dedup_rev: List[Dict[str, Any]] = []
    for m in reversed(monitors):
        name = str(m.get("name", "")).strip()
        if not name:
            name = f"{str(m.get('check_mode', 'smart')).lower()}-unix-check"
            m["name"] = name
            changed = True
        if name in seen:
            changed = True
            continue
        seen.add(name)
        dedup_rev.append(m)
    deduped = list(reversed(dedup_rev))
    if deduped != monitors:
        cfg["monitors"] = deduped
        changed = True

    if _enforce_rollout_agent_config(cfg):
        changed = True

    if changed:
        save_config(cfg, reapply_cron=False)
    return cfg


def save_config(cfg: Dict[str, Any], reapply_cron: bool = True) -> None:
    if isinstance(cfg.get("peers"), list):
        cfg["peers"] = _dedupe_peers_by_instance_id(cfg["peers"])
    path = get_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / ".unix-monitor.json.tmp"
    try:
        fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, CONFIG_FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.replace(str(tmp_path), str(path))
    except OSError:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    _enforce_config_permissions(path)
    if reapply_cron and cfg.get("cron_enabled"):
        apply_cron_schedule(cfg)


def _find_python3() -> str:
    if sys.executable and os.path.isabs(sys.executable):
        return sys.executable
    import shutil

    found = shutil.which("python3")
    return found or "/usr/bin/python3"


def build_cron_line(script_path: Path, interval_minutes: int) -> str:
    py = _find_python3()
    work_dir = script_path.parent
    if interval_minutes < 60:
        expr = f"*/{interval_minutes} * * * *"
    elif interval_minutes == 60:
        expr = "0 * * * *"
    else:
        expr = f"0 */{max(1, interval_minutes // 60)} * * *"
    return f"{expr} cd {work_dir} && {py} {script_path} --run {CRON_MARKER}"


def get_current_crontab() -> Tuple[str, bool]:
    try:
        out = subprocess.check_output(["crontab", "-l"], text=True, stderr=subprocess.DEVNULL)
        return out, True
    except subprocess.CalledProcessError:
        return "", True
    except (FileNotFoundError, PermissionError, OSError):
        return "", False


def write_crontab(content: str) -> bool:
    try:
        p = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
        p.communicate(content)
        return p.returncode == 0
    except (FileNotFoundError, PermissionError, OSError):
        return False


def remove_cron_entry() -> bool:
    content, ok = get_current_crontab()
    if not ok:
        return False
    lines = [l for l in content.splitlines() if CRON_MARKER not in l]
    return write_crontab("\n".join(l for l in lines if l.strip()) + "\n")


def add_cron_entry(interval_minutes: int) -> bool:
    content, ok = get_current_crontab()
    if not ok:
        return False
    line = build_cron_line(get_script_path(), interval_minutes)
    lines = [l for l in content.splitlines() if CRON_MARKER not in l]
    lines.append(line)
    return write_crontab("\n".join(l for l in lines if l.strip()) + "\n")


def apply_cron_schedule(cfg: Dict[str, Any]) -> bool:
    if not cfg.get("cron_enabled"):
        return remove_cron_entry()
    return add_cron_entry(int(cfg.get("cron_interval_minutes", 60)))


def _run_cmd(cmd: List[str], timeout_sec: int = 20, env: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
    try:
        kwargs: Dict[str, Any] = dict(capture_output=True, text=True, timeout=timeout_sec, check=False)
        if env is not None:
            kwargs["env"] = {**os.environ, **env}
        p = subprocess.run(cmd, **kwargs)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "Timeout"
    except Exception as e:
        return 1, f"{type(e).__name__}: {e}"


# Inject the monolith command runner into the extracted peer payload-crypto
# helpers (behavior-preserving: the openssl-CLI encryption fallback shells out
# through the same _run_cmd as before).
_peer_crypto.configure(run_cmd=_run_cmd)

# Inject the monolith config loader + UI logger into the extracted mTLS peer
# transport (behavior-preserving: _peer_http_request reads config and appends
# to the UI log exactly as before).
_peer_transport.configure(load_config=load_config, append_ui_log=append_ui_log)
# Same injection for the config-backup crypto family (openssl-CLI encryption
# fallback shells out through the same _run_cmd as before).
_backup_crypto.configure(run_cmd=_run_cmd)


_RENDER_CACHE: Dict[str, Dict[str, Any]] = {}
_RENDER_CACHE_LOCK = threading.Lock()


def _get_cached_render_value(
    key: str,
    ttl_sec: int,
    loader: Callable[[], Any],
    default_value: Optional[Any] = None,
) -> Any:
    now = time.time()
    with _RENDER_CACHE_LOCK:
        entry = _RENDER_CACHE.get(key)
        if not isinstance(entry, dict):
            entry = {"ts": 0.0, "value": default_value, "refreshing": False}
            _RENDER_CACHE[key] = entry

        ts = float(entry.get("ts", 0.0) or 0.0)
        if (now - ts) < float(max(1, ttl_sec)):
            return entry.get("value")

        if entry.get("refreshing"):
            return entry.get("value")

        entry["refreshing"] = True

    def _refresh() -> None:
        try:
            value = loader()
            with _RENDER_CACHE_LOCK:
                cur = _RENDER_CACHE.get(key)
                if isinstance(cur, dict):
                    cur["value"] = value
                    cur["ts"] = time.time()
                    cur["refreshing"] = False
        except Exception:
            with _RENDER_CACHE_LOCK:
                cur = _RENDER_CACHE.get(key)
                if isinstance(cur, dict):
                    cur["refreshing"] = False

    threading.Thread(target=_refresh, daemon=True).start()
    return entry.get("value")


def _latency_ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)


def _severity(status: str) -> int:
    return {"up": 0, "warning": 1, "down": 2}.get(status, 2)


def _has_native_storage_probe() -> Tuple[bool, str]:
    rc, out = _run_cmd(["synospace", "--help"], timeout_sec=6)
    if rc == 0:
        return True, ""
    if rc == 127:
        return False, "native storage probe unavailable on this host; using Unix fallback checks"
    if rc == 124:
        return False, "native storage probe timed out; using Unix fallback checks"
    detail = out.strip() or f"exit code {rc}"
    return False, f"native storage probe unavailable ({detail}); using Unix fallback checks"


def _check_storage_fallback(debug: bool = False) -> Tuple[str, List[str]]:
    status = "up"
    lines: List[str] = []
    fs_stats: List[Tuple[int, str, str]] = []

    df_scope = "local filesystems"
    rc, out = _run_cmd(["df", "-P", "-l"], timeout_sec=8)
    if rc != 0:
        df_scope = "all filesystems"
        rc, out = _run_cmd(["df", "-P"], timeout_sec=12)
    if rc != 0:
        if rc == 124:
            return "warning", ["Fallback df timed out while collecting storage usage"]
        return "down", [f"Fallback df failed: {out.strip()}"]

    for line in out.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 6:
            continue
        fs, used, mpoint = cols[0], cols[4], cols[5]
        if not used.endswith("%"):
            continue
        try:
            pct = int(used.rstrip("%"))
        except ValueError:
            continue
        fs_stats.append((pct, mpoint, fs))
        if pct >= 98:
            status = "down"
            lines.append(f"FS {mpoint} ({fs}): {pct}% used (critical)")
        elif pct >= 90 and _severity(status) < _severity("warning"):
            status = "warning"
            lines.append(f"FS {mpoint} ({fs}): {pct}% used (warning)")

    md_path = Path("/proc/mdstat")
    if md_path.exists():
        text = md_path.read_text(encoding="utf-8", errors="ignore")
        degraded = re.findall(r"\[[U_]+\]", text)
        bad = [token for token in degraded if "_" in token]
        if bad:
            status = "down"
            lines.append(f"mdraid degraded: {' '.join(sorted(set(bad)))}")
        if re.search(r"\b(recovery|resync|reshape|check)\b", text):
            if _severity(status) < _severity("warning"):
                status = "warning"
            lines.append("mdraid maintenance/rebuild in progress")

    fs_count = len(fs_stats)
    if fs_stats:
        top_pct, top_mp, top_fs = sorted(fs_stats, reverse=True)[0]
        lines.insert(0, f"Fallback probe ({df_scope}): scanned {fs_count} filesystems, max usage {top_pct}% on {top_mp} ({top_fs})")
        nas_volumes = sorted([(pct, mpoint, fs) for (pct, mpoint, fs) in fs_stats if NAS_VOLUME_PATTERN.match(mpoint)], key=lambda x: x[1])
        other_mounts = sorted([(pct, mpoint, fs) for (pct, mpoint, fs) in fs_stats if not NAS_VOLUME_PATTERN.match(mpoint)], key=lambda x: x[1])

        if nas_volumes:
            lines.append("NAS volumes checked:")
            for pct, mpoint, fs in nas_volumes:
                lines.append(f"  {mpoint} ({fs}) used={pct}%")
        else:
            lines.append("NAS volumes checked: none detected")

        if other_mounts:
            lines.append("Other mounts checked:")
            for pct, mpoint, fs in other_mounts:
                lines.append(f"  {mpoint} ({fs}) used={pct}%")
    else:
        lines.insert(0, "Fallback probe: no usable filesystems from df output")

    if not lines:
        lines.append("Fallback storage checks OK (usage/RAID)")
    if debug:
        print(f"    [storage:fallback] status={status}")
    return status, lines


def _detect_synology_devices() -> Dict[str, List[str]]:
    sata_devices = sorted(str(p) for p in Path("/dev").glob("sata[0-9]*") if p.is_block_device())
    if sata_devices:
        block_devices: List[str] = []
    else:
        block_devices = sorted(
            str(p) for p in Path("/dev").glob("sd*") if re.match(r"^/dev/sd[a-z]$", str(p))
        )
    scsi_devices = sorted(str(p) for p in Path("/dev").glob("sg*") if re.match(r"^/dev/sg[0-9]+$", str(p)))
    return {
        "sata": sata_devices,
        "block": block_devices,
        "scsi": scsi_devices,
    }


def _detect_nvme_devices() -> List[str]:
    rc, out = _run_cmd(["nvme", "list"], timeout_sec=8)
    if rc != 0:
        return []
    devs = []
    for line in out.splitlines():
        first = line.strip().split()[0] if line.strip() else ""
        if re.match(r"^/dev/nvme[0-9]+n[0-9]+$", first):
            devs.append(first)
    return sorted(set(devs))


def _missing_letter_devices(devices: List[str], first_expected: str) -> List[str]:
    present = set(devices)
    missing: List[str] = []
    letters = sorted([d[-1] for d in devices if re.match(r"^/dev/sd[a-z]$", d)])
    if not letters:
        return missing
    first = min(letters)
    last = max(letters)
    for code in range(ord(first), ord(last) + 1):
        dev = f"/dev/sd{chr(code)}"
        if dev == first_expected:
            continue
        if dev not in present:
            missing.append(dev)
    return missing


def _missing_numeric_devices(devices: List[str], prefix: str) -> List[str]:
    nums = sorted(int(re.search(r"(\d+)$", d).group(1)) for d in devices if re.search(r"(\d+)$", d))
    if not nums:
        return []
    missing = []
    for n in range(min(nums), max(nums) + 1):
        dev = f"{prefix}{n}"
        if dev not in devices:
            missing.append(dev)
    return missing


def check_smart(configured_devices: List[str], debug: bool = False) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    if os.name != "posix" or not sys.platform.startswith("linux"):
        return "down", ["SMART check supports Linux hosts only"], _latency_ms(t0)
    is_root = os.geteuid() == 0

    if not is_root:
        cache = _read_smart_cache()
        if cache:
            checked_at = int(cache.get("checked_at", 0) or 0)
            age = max(0, int(time.time()) - checked_at)
            if age <= SMART_CACHE_MAX_AGE_SEC:
                c_status = str(cache.get("status", "warning"))
                c_lines = [str(x) for x in cache.get("lines", []) if str(x).strip()]
                if not c_lines:
                    c_lines = ["SMART cache present but empty."]
                c_lines.insert(0, f"Using root SMART helper cache (age={age}s)")
                append_ui_log(f"smart-check | using root helper cache | age_sec={age} | status={c_status}")
                return c_status, c_lines, _latency_ms(t0)
            append_ui_log(f"smart-check | helper cache stale | age_sec={age}")
        else:
            append_ui_log("smart-check | helper cache missing")

    rc, out = _run_cmd(["smartctl", "--version"], timeout_sec=6)
    if rc != 0:
        return "down", [f"smartctl unavailable: {out.strip()}"], _latency_ms(t0)

    detected = _detect_synology_devices()
    auto_devices = detected["sata"] + detected["block"] + detected["scsi"]
    target_devices = configured_devices if configured_devices else auto_devices
    nvme_devices = _detect_nvme_devices()
    status = "up"
    lines: List[str] = []
    checked_any = 0
    permission_blocked = 0
    failed_any = 0

    if not is_root:
        lines.append("SMART running without root; some devices may be inaccessible")
        append_ui_log("smart-check | non-root execution detected")

    if not target_devices and not nvme_devices:
        return "down", ["No SATA/block/SCSI/NVMe devices detected"], _latency_ms(t0)

    # Preserve original behavior: detect sequence gaps that often mean missing disks.
    for missing in _missing_letter_devices(detected["block"], "/dev/sda"):
        lines.append(f"Disk {missing}: MISSING (expected but not detected)")
        status = "down"
    for missing in _missing_numeric_devices(detected["scsi"], "/dev/sg"):
        if missing != "/dev/sg0":
            lines.append(f"Disk {missing}: MISSING (expected but not detected)")
            status = "down"

    for dev in target_devices:
        rc, info = _run_cmd(["smartctl", "-H", dev], timeout_sec=20)
        if re.search(r"permission denied|operation not permitted", info, flags=re.IGNORECASE):
            permission_blocked += 1
            lines.append(f"Disk {dev}: permission denied")
            append_ui_log(f"smart-check | {dev} | permission denied")
            continue
        ok = bool(re.search(r"\bPASSED\b|SMART Health Status:\s*OK", info, flags=re.IGNORECASE))
        if debug:
            print(f"    [smart] {dev}: rc={rc} ok={ok}")
        checked_any += 1
        if ok:
            lines.append(f"Disk {dev}: PASSED (healthy)")
        else:
            failed_any += 1
            msg = info.strip().splitlines()[-1] if info.strip() else "health check failed"
            lines.append(f"Disk {dev}: FAILED ({msg})")
            append_ui_log(f"smart-check | {dev} | FAILED | detail={msg}")

    if nvme_devices:
        rc, _ = _run_cmd(["nvme", "version"], timeout_sec=6)
        if rc != 0:
            status = "down"
            lines.append("NVMe tool unavailable: install nvme-cli")
        else:
            for dev in nvme_devices:
                rc, info = _run_cmd(["nvme", "smart-log", dev], timeout_sec=15)
                if re.search(r"permission denied|operation not permitted", info, flags=re.IGNORECASE):
                    permission_blocked += 1
                    lines.append(f"NVMe {dev}: permission denied")
                    append_ui_log(f"smart-check | {dev} | permission denied")
                    continue
                match = re.search(r"critical_warning\s*:\s*([0-9xa-fA-F]+)", info)
                critical = (match.group(1).lower() if match else "unknown")
                healthy = critical in ("0", "0x0")
                if debug:
                    print(f"    [nvme] {dev}: rc={rc} critical_warning={critical}")
                checked_any += 1
                if rc == 0 and healthy:
                    lines.append(f"NVMe {dev}: PASSED (healthy)")
                else:
                    failed_any += 1
                    lines.append(f"NVMe {dev}: FAILED (critical_warning={critical})")
                    append_ui_log(f"smart-check | {dev} | FAILED | critical_warning={critical}")

    if failed_any > 0:
        status = "down"
    elif permission_blocked > 0:
        status = "warning"
        lines.append("SMART partially unavailable due to permissions")
    elif checked_any == 0:
        status = "warning"
        lines.append("No SMART data collected")

    if not lines:
        lines.append("SMART checks OK")
    return status, lines, _latency_ms(t0)


def run_smart_helper() -> int:
    if os.geteuid() != 0:
        print("ERROR: --run-smart-helper requires root")
        append_ui_log("smart-helper | failed | requires root")
        return 1
    status, lines, _ = check_smart([], debug=False)
    payload = {
        "checked_at": int(time.time()),
        "status": status,
        "lines": lines,
    }
    _write_smart_cache(payload)
    append_ui_log(f"smart-helper | cache updated | status={status} | lines={len(lines)}")
    print(f"SMART helper cache updated: status={status}, lines={len(lines)}")

    # Also collect backup status while running as root
    try:
        bk = _collect_backup_status()
        _write_backup_cache(bk)
        bk_overall = bk.get("overall", "unknown")
        pkg_names = ", ".join(p.get("label", p.get("id", "?")) for p in bk.get("packages", []))
        append_ui_log(f"backup-helper | cache updated | overall={bk_overall} | packages=[{pkg_names}]")
        for bt in bk.get("tasks", []):
            t_name = bt.get("name", "?")
            t_status = bt.get("status", "?")
            t_source = bt.get("source", "?")
            t_parts = [f"task [{t_status.upper()}] {t_name} (via {t_source})"]
            for fk in ("api_status", "last_result", "state", "error", "last_error"):
                fv = bt.get(fk, "")
                if fv and str(fv) not in ("0", "none", ""):
                    t_parts.append(f"{fk}={fv}")
            append_ui_log(f"backup-helper |   {' | '.join(t_parts)}")
        if not bk.get("tasks"):
            append_ui_log("backup-helper |   (no backup tasks detected)")
        print(f"Backup helper cache updated: overall={bk_overall}, tasks={len(bk.get('tasks', []))}, packages={len(bk.get('packages', []))}")
    except Exception as exc:
        append_ui_log(f"backup-helper | error in smart-helper: {type(exc).__name__}: {exc}")
        print(f"Backup helper error: {exc}")

    return 0


def run_system_log_helper() -> int:
    if os.geteuid() != 0:
        print("ERROR: --run-system-log-helper requires root")
        append_ui_log("system-log-helper | failed | requires root")
        return 1
    source = ""
    raw = ""
    for p in (Path("/var/log/messages"), Path("/var/log/syslog")):
        if p.exists():
            source = str(p)
            raw = _tail_text_file(p, max_lines=400)
            break
    if not source:
        source = "(none)"
        raw = "No system log file found."
    errors = _extract_error_lines(raw, max_lines=140)
    payload = {
        "checked_at": int(time.time()),
        "source": source,
        "errors": errors,
    }
    _write_system_log_cache(payload)
    append_ui_log("system-log-helper | cache updated")
    print("System log helper cache updated.")
    return 0


# ---------------------------------------------------------------------------
#  Backup monitoring
# ---------------------------------------------------------------------------


def _detect_backup_packages() -> List[Dict[str, Any]]:
    """Detect installed backup packages."""
    pkgs: List[Dict[str, Any]] = []
    known = [
        ("HyperBackup", "Hyper Backup"),
        ("ActiveBackup", "Active Backup for Business"),
        ("ActiveBackupOffice365", "Active Backup for Microsoft 365"),
        ("ActiveBackupGSuite", "Active Backup for Google Workspace"),
        ("SnapshotReplication", "Snapshot Replication"),
        ("USBCopy", "USB Copy"),
        ("CloudSync", "Cloud Sync"),
    ]
    for pkg_id, label in known:
        try:
            pkg_dir = Path(f"/var/packages/{pkg_id}")
            if not pkg_dir.exists():
                continue
        except OSError:
            continue
        version = ""
        try:
            rc, out = _run_cmd(["synopkg", "version", pkg_id], timeout_sec=5)
            if rc == 0 and out.strip():
                version = out.strip()
        except Exception:
            pass
        pkgs.append({"id": pkg_id, "label": label, "version": version})
    return pkgs


def _read_backup_logs(max_lines: int = 600) -> str:
    """Read backup log files."""
    log_paths = [
        Path("/var/log/synolog/synobackup.log"),
        Path("/var/packages/HyperBackup/var/log/synolog/synobackup.log"),
        Path("/var/log/synolog/synobackup.log.1"),
        Path("/var/packages/HyperBackup/target/log/synolog/synobackup.log"),
        Path("/var/log/synolog/backup.log"),
    ]
    all_lines: List[str] = []
    for p in log_paths:
        try:
            if not p.exists():
                continue
            all_lines.extend(_read_tail_lines(p, max_lines=max_lines))
        except OSError:
            continue
    # Also try synologtool to get log entries from Synology's log database
    for log_cmd in (
        ["synologtool", "log", "--get", "--type", "backup", "--limit", "50"],
        ["synologtool", "log", "--get", "--limit", "100"],
    ):
        try:
            rc, out = _run_cmd(log_cmd, timeout_sec=10)
            if rc == 0 and out.strip():
                for ln in out.splitlines():
                    if "backup" in ln.lower() or "task" in ln.lower():
                        all_lines.append(ln)
        except Exception:
            pass
    if not all_lines:
        return ""
    tail = "".join(all_lines[-max_lines:]).strip()
    return tail


def _read_tail_lines(path: Path, max_lines: int = 120, max_bytes: int = 262_144) -> List[str]:
    """Read only the tail of a text file (bounded bytes + line count)."""
    if max_lines <= 0:
        return []
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            if file_size <= 0:
                return []

            remaining = min(file_size, max_bytes)
            chunk_size = 4096
            chunks: List[bytes] = []
            newline_count = 0
            while remaining > 0 and newline_count <= max_lines:
                to_read = min(chunk_size, remaining)
                remaining -= to_read
                f.seek(file_size - (remaining + to_read), os.SEEK_SET)
                chunk = f.read(to_read)
                if not chunk:
                    break
                chunks.append(chunk)
                newline_count += chunk.count(b"\n")

            data = b"".join(reversed(chunks))
        text = data.decode("utf-8", errors="ignore")
        lines = text.splitlines(keepends=True)
        return lines[-max_lines:] if len(lines) > max_lines else lines
    except OSError:
        return []


def _parse_backup_log_tasks(log_text: str) -> Dict[str, Dict[str, Any]]:
    """Parse backup log for task statuses keyed by task name.

    Backup logs use formats like:
      Backup task [My Task Name] finished successfully. [12345]
      Backup task [My Task Name] has started
      Datensicherungsaufgabe [My Task Name] fehlgeschlagen
      Backup integrity check for [My Task Name] has started
    We specifically look for "task [Name]" or "aufgabe [Name]" patterns
    and filter out numeric-only or too-short bracket content.
    """
    tasks: Dict[str, Dict[str, Any]] = {}
    task_name_pattern = re.compile(
        r'(?:backup\s+task|task|aufgabe|integrity\s+check\s+(?:for\s+)?)\s*\[([^\]]{3,})\]',
        re.IGNORECASE,
    )
    bracket_pattern = re.compile(r'\[([^\]]{3,})\]')
    _status_keywords = [
        ("finished successfully", "success"), ("erfolgreich", "success"),
        ("has been completed", "success"), ("completed successfully", "success"),
        ("error_detect", "warning"),  # C2 Backup state - before "error" to avoid false failed
        ("has failed", "failed"), ("failed", "failed"), ("fehlgeschlagen", "failed"),
        ("no response", "failed"), ("error", "failed"),
        ("has started", "running"), ("started", "running"), ("gestartet", "running"),
        ("cancelled", "cancelled"), ("abgebrochen", "cancelled"),
        ("partially completed", "partial"), ("teilweise", "partial"),
        ("suspend", "cancelled"),
    ]
    for line in log_text.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue
        m = task_name_pattern.search(line_stripped)
        if not m:
            lower_check = line_stripped.lower()
            has_result_keyword = any(kw in lower_check for kw, _ in _status_keywords if _ in ("failed", "success", "warning"))
            if has_result_keyword:
                bm = bracket_pattern.search(line_stripped)
                if bm:
                    candidate = bm.group(1).strip()
                    if candidate and not candidate.isdigit() and len(candidate) >= 3:
                        m = bm
            if not m:
                continue
        task_name = m.group(1).strip()
        if not task_name or task_name.isdigit():
            continue
        lower = line_stripped.lower()
        status = "unknown"
        for kw, st in _status_keywords:
            if kw in lower:
                status = st
                break
        ts_match = re.match(r'(\d{4}[/-]\d{2}[/-]\d{2}\s+\d{2}:\d{2}:\d{2})', line_stripped)
        if not ts_match:
            # Try tab-separated format: "info\t2026/02/20\t12:00:00\t..."
            ts_match = re.search(r'(\d{4}[/-]\d{2}[/-]\d{2})\t(\d{2}:\d{2}:\d{2})', line_stripped)
            if ts_match:
                ts_str = f"{ts_match.group(1)} {ts_match.group(2)}"
            else:
                ts_str = ""
        else:
            ts_str = ts_match.group(1)
        ts_epoch = 0
        if ts_str:
            try:
                ts_epoch = int(time.mktime(time.strptime(ts_str.replace("/", "-"), "%Y-%m-%d %H:%M:%S")))
            except Exception:
                pass
        if task_name not in tasks or ts_epoch >= tasks[task_name].get("ts", 0):
            tasks[task_name] = {"status": status, "ts": ts_epoch, "line": line_stripped[:300]}
    return tasks


def _query_hyperbackup_task_detail(task_id: int) -> Tuple[Dict[str, Any], str]:
    """Query detailed status for a single Hyper Backup task.

    Tries multiple API endpoints and versions to get last_bkp_result, last_bkp_time, etc.
    Returns (detail_dict, debug_log).
    """
    debug_parts: List[str] = []
    _apis = [
        ("SYNO.Backup.Task", "status", "1", f"task_id={task_id}"),
        ("SYNO.Backup.Task", "get", "1", f"task_id={task_id}"),
        ("SYNO.Backup.Task", "status", "2", f"task_id={task_id}"),
        ("SYNO.Backup.Task", "get", "2", f"task_id={task_id}"),
        ("SYNO.Backup.Repository", "get", "1", f"repo_id={task_id}"),
    ]
    for api, method, ver, extra in _apis:
        try:
            rc, out = _run_cmd(
                ["synowebapi", "-s", "--exec",
                 f"api={api}", f"method={method}", f"version={ver}", extra],
                timeout_sec=10,
            )
            snippet = out[:300] if out else "(empty)"
            debug_parts.append(f"{api}/{method}/v{ver}: rc={rc} -> {snippet}")
            if rc == 0 and out.strip():
                data = json.loads(out)
                if data.get("success") is False:
                    continue
                d = data.get("data", data)
                if isinstance(d, dict) and d:
                    useful_keys = {"last_bkp_result", "last_bkp_time", "next_bkp_time",
                                   "last_bkp_error", "error", "state", "status", "result"}
                    if any(k in d for k in useful_keys):
                        return d, "\n".join(debug_parts)
        except Exception as exc:
            debug_parts.append(f"{api}/{method}/v{ver}: exception {type(exc).__name__}: {exc}")
    return {}, "\n".join(debug_parts)


def _query_hyperbackup_api() -> Tuple[List[Dict[str, Any]], str]:
    """Query SYNO.Backup.Task API for Hyper Backup tasks (requires root).

    First lists tasks, then queries each one individually for detailed status.
    Returns (task_list_with_detail, raw_response_snippet) for debugging.
    """
    try:
        rc, out = _run_cmd(
            ["synowebapi", "-s", "--exec",
             "api=SYNO.Backup.Task", "method=list", "version=1"],
            timeout_sec=15,
        )
        raw_snippet = f"rc={rc} body={out[:500]}" if out else f"rc={rc} (empty)"
        if rc != 0 or not out.strip():
            return [], raw_snippet
        data = json.loads(out)
        task_list = data.get("data", {}).get("task_list", [])
        if not task_list:
            task_list = data.get("data", {}).get("task", [])
        if not task_list and isinstance(data.get("data"), list):
            task_list = data["data"]

        enriched = []
        detail_logs: List[str] = []
        for t in task_list:
            tid = t.get("task_id", t.get("id", 0))
            if tid:
                detail, detail_debug = _query_hyperbackup_task_detail(int(tid))
                detail_logs.append(f"task_id={tid}: {detail_debug}")
                if detail:
                    merged = dict(t)
                    merged.update(detail)
                    enriched.append(merged)
                    continue
            enriched.append(t)
        if detail_logs:
            raw_snippet += "\n--- detail queries ---\n" + "\n".join(detail_logs)
        return enriched, raw_snippet
    except Exception as exc:
        return [], f"error: {type(exc).__name__}: {exc}"


def _collect_backup_status() -> Dict[str, Any]:
    """Collect comprehensive backup status (best run as root)."""
    packages = _detect_backup_packages()
    log_text = _read_backup_logs()
    log_tasks = _parse_backup_log_tasks(log_text)
    if log_text:
        last_5 = log_text.strip().splitlines()[-5:]
        append_ui_log(f"backup-helper | log tail ({len(log_text.splitlines())} lines): {' // '.join(l.strip()[:100] for l in last_5)}")
    else:
        append_ui_log("backup-helper | no backup log content found")
    api_tasks, api_raw_snippet = _query_hyperbackup_api()
    append_ui_log(f"backup-helper | api returned {len(api_tasks)} tasks")
    for at in api_tasks:
        enriched_keys = [k for k in ("last_bkp_result", "last_bkp_time", "next_bkp_time", "last_bkp_error") if k in at]
        append_ui_log(f"backup-helper | api task '{at.get('name','?')}': state={at.get('state','?')} status={at.get('status','?')} enriched_keys={enriched_keys}")
    api_raw_summary = []
    for at in api_tasks:
        api_raw_summary.append({k: at[k] for k in sorted(at.keys())})

    tasks: List[Dict[str, Any]] = []
    seen_names: set = set()

    _FAIL_WORDS = ("fail", "error", "err", "broken", "crash", "fehlgeschlagen")
    _SUCCESS_WORDS = ("done", "success", "ok", "erfolgreich")
    _CANCEL_WORDS = ("cancel", "suspend", "abgebrochen")

    for at in api_tasks:
        name = str(at.get("name", "") or "").strip()
        if not name:
            continue
        seen_names.add(name)
        api_status = str(at.get("status", "") or "").lower()
        last_result = str(at.get("last_bkp_result", "") or "").lower()
        result_field = str(at.get("result", "") or "").lower()
        state_field = str(at.get("state", "") or "").lower()
        error_field = str(at.get("error", at.get("error_code", "")) or "")
        last_error = str(at.get("last_bkp_error", at.get("last_error", "")) or "").lower()
        last_bkp_time = at.get("last_bkp_time", 0)
        next_bkp_time = at.get("next_bkp_time", 0)
        all_vals = f"{api_status} {last_result} {result_field} {state_field} {last_error}"
        status = "unknown"
        if api_status in ("backingup", "resuming"):
            status = "running"
        elif state_field == "error_detect":
            status = "warning"
        elif any(w in all_vals for w in _FAIL_WORDS):
            status = "failed"
        elif str(error_field) not in ("0", "", "none", "None") and error_field:
            status = "failed"
        elif any(w in all_vals for w in _SUCCESS_WORDS):
            status = "success"
        elif any(w in all_vals for w in _CANCEL_WORDS):
            status = "cancelled"
        elif "partial" in all_vals:
            status = "partial"
        elif api_status in ("idle",):
            status = "success"
        log_info = log_tasks.get(name, {})
        if log_info.get("status") == "failed" and status in ("success", "unknown"):
            status = "failed"
        elif log_info.get("status") == "success" and status == "unknown":
            status = "success"
        if status == "unknown" and state_field == "backupable":
            if last_bkp_time:
                status = "success"
            else:
                # A configured backup task with no prior run is pending, not degraded.
                status = "pending"
        task_entry: Dict[str, Any] = {
            "name": name,
            "source": "api",
            "status": status,
            "api_status": api_status,
            "last_result": last_result,
            "state": state_field,
            "error": str(error_field),
            "last_error": last_error,
        }
        if last_bkp_time:
            task_entry["last_bkp_time"] = int(last_bkp_time)
        if next_bkp_time:
            task_entry["next_bkp_time"] = int(next_bkp_time)
        tasks.append(task_entry)

    for tname, tinfo in log_tasks.items():
        if tname in seen_names:
            continue
        tasks.append({
            "name": tname,
            "source": "log",
            "status": tinfo["status"],
            "ts": tinfo.get("ts", 0),
        })

    overall = "up"
    if not tasks and not packages:
        overall = "unknown"
    else:
        for t in tasks:
            s = t.get("status", "unknown")
            if s == "failed":
                overall = "down"
                break
            elif s in ("partial", "cancelled", "warning"):
                if overall != "down":
                    overall = "warning"
            elif s == "running":
                if overall == "up":
                    overall = "up"
            elif s == "unknown":
                if overall == "up":
                    overall = "warning"

    log_task_summary = []
    for tname, tinfo in log_tasks.items():
        log_task_summary.append({"name": tname, "status": tinfo.get("status", "?"), "line": tinfo.get("line", "")[:200]})

    return {
        "checked_at": int(time.time()),
        "overall": overall,
        "packages": packages,
        "tasks": tasks,
        "_debug_api_raw": api_raw_summary,
        "_debug_api_response": api_raw_snippet[:2000],
        "_debug_log_tasks": log_task_summary,
        "_debug_log_lines": len(log_text.splitlines()) if log_text else 0,
    }


def run_backup_helper() -> int:
    """Root helper to collect backup status and write cache."""
    if os.geteuid() != 0:
        print("ERROR: --run-backup-helper requires root")
        append_ui_log("backup-helper | failed | requires root")
        return 1
    payload = _collect_backup_status()
    _write_backup_cache(payload)
    overall = payload.get("overall", "unknown")
    pkg_names = ", ".join(p.get("label", p.get("id", "?")) for p in payload.get("packages", []))
    append_ui_log(f"backup-helper | cache updated | overall={overall} | packages=[{pkg_names}]")
    for bt in payload.get("tasks", []):
        t_name = bt.get("name", "?")
        t_status = bt.get("status", "?")
        t_source = bt.get("source", "?")
        t_parts = [f"task [{t_status.upper()}] {t_name} (via {t_source})"]
        for fk in ("api_status", "last_result", "state", "error", "last_error"):
            fv = bt.get(fk, "")
            if fv and fv not in ("0", "none", ""):
                t_parts.append(f"{fk}={fv}")
        append_ui_log(f"backup-helper |   {' | '.join(t_parts)}")
    if not payload.get("tasks"):
        append_ui_log("backup-helper |   (no backup tasks detected)")
    print(f"Backup helper cache updated: overall={overall}, tasks={len(payload.get('tasks', []))}")
    return 0


def _probe_backup(source_platform: str = "unix") -> Tuple[str, List[str], float]:
    """Check backup status, reading from privileged backup-helper cache or direct probing."""
    t0 = time.time()
    lines: List[str] = []

    cache = _read_backup_cache()
    if cache:
        checked_at = int(cache.get("checked_at", 0) or 0)
        age = max(0, int(time.time()) - checked_at)
        checked_ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(checked_at)) if checked_at else "never"
        if age > BACKUP_CACHE_MAX_AGE_SEC:
            lines.append(f"STALE CACHE ({age}s)")

        packages = cache.get("packages", [])
        pkg_names = ", ".join(p.get("label", p.get("id", "?")) for p in packages) if packages else "none"
        lines.append(f"Scan: {checked_ts} | Packages: {pkg_names}")

        tasks = cache.get("tasks", [])
        if tasks:
            count_failed = sum(1 for t in tasks if t.get("status") == "failed")
            count_pending = sum(1 for t in tasks if t.get("status") == "pending")
            count_running = sum(1 for t in tasks if t.get("status") == "running")
            lines.append(
                f"Task summary: total={len(tasks)} | failed={count_failed} | pending={count_pending} | running={count_running}"
            )
        if tasks:
            for t in tasks:
                name = t.get("name", "?")
                st = t.get("status", "unknown")
                icon = {
                    "success": "OK",
                    "failed": "FAIL",
                    "running": "RUN",
                    "partial": "PARTIAL",
                    "cancelled": "CANCEL",
                    "warning": "WARN",
                    "pending": "PENDING",
                }.get(st, "?")
                detail_parts = []
                lbt = t.get("last_bkp_time", 0)
                nbt = t.get("next_bkp_time", 0)
                le = t.get("last_error", "")
                state_val = t.get("state", "")
                if st == "failed":
                    if le and le not in ("none", "", "0"):
                        detail_parts.append(f"error={le}")
                    elif state_val and state_val not in ("none", ""):
                        detail_parts.append(f"state={state_val}")
                elif st == "pending":
                    if nbt:
                        detail_parts.append(f"next={time.strftime('%m/%d %H:%M', time.localtime(int(nbt)))}")
                    else:
                        detail_parts.append("awaiting first run")
                else:
                    if lbt:
                        detail_parts.append(f"last={time.strftime('%m/%d %H:%M', time.localtime(int(lbt)))}")
                    if nbt:
                        detail_parts.append(f"next={time.strftime('%m/%d %H:%M', time.localtime(int(nbt)))}")
                detail = f" ({', '.join(detail_parts)})" if detail_parts else ""
                lines.append(f"[{icon}] {name}{detail}")
        else:
            lines.append("No backup tasks discovered via Hyper Backup API/logs")
            if packages:
                lines.append("Check helper permissions or whether tasks are visible to this account")

        overall = str(cache.get("overall", "unknown"))
        status = {"up": "up", "down": "down", "warning": "warning"}.get(overall, "warning")
        latency = round((time.time() - t0) * 1000, 1)
        return status, lines, latency

    # No cache: try direct detection (limited without root)
    is_synology_ctx = _normalize_source_platform(source_platform) == "synology"
    if is_synology_ctx:
        lines.append("WARNING: no root helper cache, direct probe (limited)")
    else:
        lines.append("WARNING: no backup-helper cache; limited check without elevated privileges")
    try:
        packages = _detect_backup_packages()
        if packages:
            pkg_names = ", ".join(p.get("label", p.get("id", "?")) for p in packages)
            lines.append(f"Packages ({len(packages)}): {pkg_names}")
        else:
            lines.append("Packages: none detected")

        log_text = _read_backup_logs()
        if log_text:
            log_tasks = _parse_backup_log_tasks(log_text)
            if log_tasks:
                failed = False
                warning = False
                lines.append(f"Tasks ({len(log_tasks)}, from logs only):")
                for tname, tinfo in log_tasks.items():
                    s = tinfo.get("status", "unknown")
                    icon = {"success": "OK", "failed": "FAIL", "running": "RUN", "partial": "PARTIAL", "cancelled": "CANCEL"}.get(s, "?")
                    log_line = tinfo.get("line", "")[:120]
                    lines.append(f"  [{icon}] {tname} | {log_line}")
                    if s == "failed":
                        failed = True
                    elif s in ("partial", "cancelled", "warning", "unknown"):
                        warning = True
                status = "down" if failed else ("warning" if warning else "up")
            else:
                lines.append("No backup task entries found in logs")
                status = "warning"
        else:
            if is_synology_ctx:
                lines.append("Backup logs not accessible (root helper needed)")
                lines.append("Run the elevated helper task in DSM Task Scheduler to enable full backup monitoring")
            else:
                lines.append("Backup logs not accessible without root (Hyper Backup logs are typically root-only)")
                lines.append(
                    "Run `sudo unix-monitor.py --run-backup-helper` on a schedule "
                    "(install.sh can install unix-monitor-backup-helper.service / .timer)"
                )
            status = "warning" if packages else "up"
    except Exception as exc:
        lines.append(f"Direct probe failed: {type(exc).__name__}: {exc}")
        if is_synology_ctx:
            lines.append("Root helper needed for full backup monitoring")
        else:
            lines.append("Elevated backup helper required for full backup monitoring")
        status = "warning"

    latency = round((time.time() - t0) * 1000, 1)
    return status, lines, latency


def check_storage(debug: bool = False) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    ok_tools, err = _has_native_storage_probe()
    if not ok_tools:
        append_ui_log(f"storage-check | native probe unavailable | reason={err}")
        fb_status, fb_lines = _check_storage_fallback(debug=debug)
        fb_lines.insert(0, err)
        return fb_status, fb_lines, _latency_ms(t0)

    rc, out = _run_cmd(["synospace", "--enum"], timeout_sec=20)
    if rc != 0 or not out.strip():
        err_text = out.strip() or "no output"
        if "PermissionError" in err_text or "Permission denied" in err_text:
            append_ui_log(f"storage-check | synospace permission denied | rc={rc} | detail={err_text}")
            fb_status, fb_lines = _check_storage_fallback(debug=debug)
            fb_lines.insert(0, "Native storage probe permission denied; using Unix fallback checks")
            return fb_status, fb_lines, _latency_ms(t0)
        append_ui_log(f"storage-check | synospace failed | rc={rc} | detail={err_text}")
        return "down", [f"Failed to retrieve storage status: {err_text}"], _latency_ms(t0)

    status = "up"
    lines: List[str] = []

    if re.search(r"Status:\s*\[(degraded|repairing|raid_parity_checking)\]", out):
        status = "warning"
        lines.append("Storage pools or volumes are repairing/parity checking")

    rebuild = re.search(r"(raid building mode=\[rebuilding\]\s*\([0-9]+/[0-9]+\))", out)
    if rebuild:
        if _severity(status) < _severity("warning"):
            status = "warning"
        lines.append(f"RAID rebuild in progress: {rebuild.group(1)}")

    if re.search(r"raid status=\[degraded\]", out):
        status = "down"
        lines.append("One or more RAID arrays are degraded")

    if not lines:
        lines.append("All storage pools, volumes, and RAID arrays are healthy")
    append_ui_log(f"storage-check | synospace OK | status={status} | lines={len(lines)}")
    if debug:
        print(f"    [storage] synospace lines: {len(out.splitlines())}")
    return status, lines, _latency_ms(t0)


def get_mounts() -> List[Tuple[str, str, str]]:
    result: List[Tuple[str, str, str]] = []
    try:
        with open("/proc/mounts", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    device, mpoint, fstype = parts[0], parts[1], parts[2]
                    if mpoint.startswith(("/sys", "/proc", "/dev/pts", "/run")):
                        continue
                    if fstype in ("sysfs", "proc", "devtmpfs", "tmpfs", "cgroup", "cgroup2"):
                        continue
                    result.append((device, mpoint, fstype))
    except FileNotFoundError:
        pass
    return result


def check_mount_accessible(mount_point: str) -> Tuple[bool, Optional[str], float]:
    resolved = os.path.realpath(mount_point)
    if resolved != os.path.normpath(mount_point):
        return False, "Symlink or path traversal detected", 0.0
    path = Path(resolved)
    if not path.exists():
        return False, "Path does not exist", 0.0
    if not path.is_dir():
        return False, "Not a directory", 0.0
    t0 = time.perf_counter()
    try:
        os.statvfs(mount_point)
        return True, None, _latency_ms(t0)
    except PermissionError:
        return False, "Permission denied (statvfs)", _latency_ms(t0)
    except OSError as e:
        return False, str(e), _latency_ms(t0)


def check_mounts_status(
    mounts: List[Tuple[str, str, str]],
    debug: bool = False,
) -> Tuple[str, List[str], float]:
    ok_list: List[str] = []
    fail_list: List[Tuple[str, str]] = []
    max_latency_ms = 0.0

    for _dev, mpoint, fstype in mounts:
        ok, err, lat_ms = check_mount_accessible(mpoint)
        max_latency_ms = max(max_latency_ms, lat_ms)
        if debug:
            res = "OK" if ok else f"FAIL: {err or 'unreachable'}"
            print(f"    [mount] {mpoint} ({fstype}) -> {res} ({lat_ms:.2f}ms)")
        if ok:
            ok_list.append(f"{mpoint} ({fstype})")
        else:
            fail_list.append((mpoint, err or "unreachable"))

    if not fail_list:
        status = "up"
        lines = [f"All {len(ok_list)} mount(s) healthy", *ok_list]
    elif not ok_list:
        status = "down"
        lines = [f"All {len(fail_list)} mount(s) down", *[f"{m}: {e}" for m, e in fail_list]]
    else:
        status = "warning"
        lines = [f"{len(ok_list)} OK, {len(fail_list)} down", *[f"{m}: {e}" for m, e in fail_list]]
    return status, lines, max_latency_ms


def check_host(mode: str, devices: List[str], debug: bool = False) -> Tuple[str, str, float]:
    return check_host_with_monitor(mode, devices, monitor={}, debug=debug)


def _probe_ping(host: str) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    target = (host or "").strip()
    if not target:
        return "down", ["Ping target host is missing."], _latency_ms(t0)
    for ping_bin in ("/bin/ping", "/usr/bin/ping", "ping"):
        rc, out = _run_cmd([ping_bin, "-c", "1", "-W", "2", target], timeout_sec=5)
        if rc == 0:
            return "up", [f"Ping target {target} is reachable."], _latency_ms(t0)
        if "Operation not permitted" not in out and "not found" not in out:
            detail = out.strip().splitlines()[-1] if out.strip() else "no output"
            return "down", [f"Ping target {target} is unreachable: {detail}"], _latency_ms(t0)
    try:
        with socket.create_connection((target, 80), timeout=3):
            return "up", [f"Ping target {target} is reachable (TCP fallback port 80)."], _latency_ms(t0)
    except OSError:
        pass
    try:
        with socket.create_connection((target, 443), timeout=3):
            return "up", [f"Ping target {target} is reachable (TCP fallback port 443)."], _latency_ms(t0)
    except OSError:
        pass
    return "down", [f"Ping target {target} is unreachable (ICMP not permitted, TCP 80/443 failed)."], _latency_ms(t0)


def _probe_port(host: str, port: int) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    target = (host or "").strip()
    if not target:
        return "down", ["Port probe host is missing."], _latency_ms(t0)
    if port < 1 or port > 65535:
        return "down", [f"Port probe has invalid port: {port}"], _latency_ms(t0)
    try:
        with socket.create_connection((target, int(port)), timeout=3):
            return "up", [f"Port {port} on {target} is open."], _latency_ms(t0)
    except OSError as e:
        return "down", [f"Port {port} on {target} is closed/unreachable: {type(e).__name__}: {e}"], _latency_ms(t0)


def _probe_dns(name: str, dns_server: str = "") -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    target = (name or "").strip()
    server = (dns_server or "").strip()
    if not target:
        return "down", ["DNS monitor domain/hostname is missing."], _latency_ms(t0)
    if server:
        rc, out = _run_cmd(["nslookup", target, server], timeout_sec=6)
        if rc == 0:
            return "up", [f"DNS lookup resolved {target} via {server}."], _latency_ms(t0)
        detail = out.strip().splitlines()[-1] if out.strip() else "no output"
        return "down", [f"DNS lookup failed for {target} via {server}: {detail}"], _latency_ms(t0)
    try:
        answers = socket.getaddrinfo(target, None)
        ips = sorted({str(x[4][0]) for x in answers if x and len(x) > 4 and x[4]})
        if ips:
            return "up", [f"DNS lookup resolved {target}: {', '.join(ips[:4])}"], _latency_ms(t0)
        return "down", [f"DNS lookup returned no addresses for {target}"], _latency_ms(t0)
    except OSError as e:
        return "down", [f"DNS lookup failed for {target}: {type(e).__name__}: {e}"], _latency_ms(t0)


def _split_service_names(raw: str) -> List[str]:
    vals = [x.strip() for x in str(raw or "").replace(";", ",").split(",")]
    uniq: List[str] = []
    for name in vals:
        if name and name not in uniq:
            uniq.append(name)
    return uniq


def _service_state_systemd(name: str) -> Optional[Tuple[str, str]]:
    cand = [name]
    if not name.endswith(".service"):
        cand.append(f"{name}.service")
    for unit in cand:
        rc, out = _run_cmd(["systemctl", "is-active", unit], timeout_sec=5)
        txt = (out or "").strip().splitlines()
        status = txt[-1].strip().lower() if txt else ""
        if rc == 0 and status in ("active", "running"):
            return "up", f"{unit}: active"
        if status:
            if status in ("inactive", "failed", "deactivating", "activating", "unknown", "not-found"):
                return "down", f"{unit}: {status}"
            return "warning", f"{unit}: {status}"
    return None


def _service_state_sysv(name: str) -> Optional[Tuple[str, str]]:
    rc, out = _run_cmd(["service", name, "status"], timeout_sec=8)
    low = (out or "").lower()
    if rc == 0 and ("running" in low or "started" in low):
        return "up", f"{name}: running"
    if "unrecognized service" in low or "not-found" in low or "not found" in low:
        return "down", f"{name}: not found"
    if "stopped" in low or "inactive" in low or "dead" in low or rc != 0:
        detail = (out or "").strip().splitlines()
        tail = detail[-1].strip() if detail else "not running"
        return "down", f"{name}: {tail}"
    return None


def _probe_service(monitor: Dict[str, Any]) -> Tuple[str, List[str], float]:
    t0 = time.perf_counter()
    names = _split_service_names(str(monitor.get("service_names", "") or ""))
    desc_filter = str(monitor.get("service_description_filter", "") or "").strip().lower()
    selected = list(names)
    if not selected and desc_filter:
        rc, out = _run_cmd(
            ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
            timeout_sec=10,
        )
        if rc == 0:
            for ln in (out or "").splitlines():
                row = ln.strip()
                if not row:
                    continue
                parts = row.split(None, 4)
                unit = parts[0] if parts else ""
                desc = parts[4] if len(parts) >= 5 else ""
                if unit and desc_filter in (unit + " " + desc).lower():
                    base = unit[:-8] if unit.endswith(".service") else unit
                    if base and base not in selected:
                        selected.append(base)
    if not selected:
        return "down", ["Service mode requires service names or a matching description filter."], _latency_ms(t0)

    worst = "up"
    lines: List[str] = []
    for name in selected:
        st = _service_state_systemd(name) or _service_state_sysv(name)
        if st is None:
            st = ("warning", f"{name}: unable to determine status")
        s, detail = st
        lines.append(f"{name}: {detail}")
        if _severity(s) > _severity(worst):
            worst = s
    return worst, lines, _latency_ms(t0)


def check_host_with_monitor(mode: str, devices: List[str], monitor: Dict[str, Any], debug: bool = False) -> Tuple[str, str, float]:
    worst = "up"
    max_latency = 0.0
    sections: List[str] = []
    source_platform = _monitor_source_platform(monitor)

    if mode == "mount":
        mounts_data = monitor.get("mounts", [])
        mounts = [
            (x.get("device", "?"), x.get("mount_point", ""), x.get("fstype", "?"))
            for x in mounts_data if x.get("mount_point")
        ]
        if not mounts:
            mounts = get_mounts()
        m_status, m_lines, m_lat = check_mounts_status(mounts, debug=debug)
        max_latency = max(max_latency, m_lat)
        if _severity(m_status) > _severity(worst):
            worst = m_status
        sections.append("Mounts:\n" + "\n".join(f"  - {x}" for x in m_lines))

    if mode == "smart":
        s_status, s_lines, s_lat = check_smart(devices, debug=debug)
        max_latency = max(max_latency, s_lat)
        if _severity(s_status) > _severity(worst):
            worst = s_status
        sections.append("SMART:\n" + "\n".join(f"  - {x}" for x in s_lines))

    if mode == "storage":
        st_status, st_lines, st_lat = check_storage(debug=debug)
        max_latency = max(max_latency, st_lat)
        if _severity(st_status) > _severity(worst):
            worst = st_status
        sections.append("Storage:\n" + "\n".join(f"  - {x}" for x in st_lines))

    if mode == "ping":
        p_status, p_lines, p_lat = _probe_ping(str(monitor.get("probe_host", "")))
        max_latency = max(max_latency, p_lat)
        if _severity(p_status) > _severity(worst):
            worst = p_status
        sections.append("Ping:\n" + "\n".join(f"  - {x}" for x in p_lines))

    if mode == "port":
        host = str(monitor.get("probe_host", ""))
        try:
            port = int(monitor.get("probe_port", 0) or 0)
        except (TypeError, ValueError):
            port = 0
        p_status, p_lines, p_lat = _probe_port(host, port)
        max_latency = max(max_latency, p_lat)
        if _severity(p_status) > _severity(worst):
            worst = p_status
        sections.append("Port:\n" + "\n".join(f"  - {x}" for x in p_lines))

    if mode == "dns":
        target = str(monitor.get("dns_name", ""))
        server = str(monitor.get("dns_server", ""))
        d_status, d_lines, d_lat = _probe_dns(target, server)
        max_latency = max(max_latency, d_lat)
        if _severity(d_status) > _severity(worst):
            worst = d_status
        sections.append("DNS:\n" + "\n".join(f"  - {x}" for x in d_lines))

    if mode == "backup":
        b_status, b_lines, b_lat = _probe_backup(source_platform=source_platform)
        max_latency = max(max_latency, b_lat)
        if _severity(b_status) > _severity(worst):
            worst = b_status
        if len(b_lines) > 8:
            hidden = len(b_lines) - 8
            b_lines = b_lines[:8] + [f"... and {hidden} more line(s)"]
        sections.append("Backup:\n" + "\n".join(f"  - {x}" for x in b_lines))

    if mode == "service":
        svc_status, svc_lines, svc_lat = _probe_service(monitor)
        max_latency = max(max_latency, svc_lat)
        if _severity(svc_status) > _severity(worst):
            worst = svc_status
        sections.append("Service:\n" + "\n".join(f"  - {x}" for x in svc_lines))

    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    check_title = _check_title_for_platform(source_platform)
    msg = f"{check_title} ({mode}) = {worst} @ {now}\n" + "\n".join(sections)
    return worst, msg, max_latency


def push_to_kuma(url: str, status: str, message: str, ping_ms: float, debug: bool = False) -> bool:
    """Push heartbeat to Uptime Kuma. Kuma only accepts status 'up' or 'down' (anything else becomes down).
    We map 'warning' -> 'up' so degraded-but-not-down shows green; the message conveys the warning."""
    kuma_status = "up" if status == "warning" else status
    base = normalize_kuma_url(url)
    compact_msg = _compact_kuma_message(message)
    full = f"{base}?status={kuma_status}&msg={quote(compact_msg)}&ping={ping_ms}"
    if debug:
        print(f"    [push] GET {base}?status=...&msg=...&ping={ping_ms}")
    try:
        parsed = urlparse(full)
        host = parsed.hostname or parsed.netloc.split(":")[0]
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=10, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        ok = resp.status in (200, 201, 204)
        if debug:
            print(f"    [push] response: HTTP {resp.status}")
        conn.close()
        return ok
    except Exception as e:
        if debug:
            print(f"    [push] error: {type(e).__name__}: {e}")
        return False


def _compact_kuma_message(message: str, max_len: int = 600) -> str:
    raw = str(message or "").replace("\r", "\n")
    lines = [ln.strip() for ln in raw.split("\n") if ln.strip()]
    if not lines:
        return "monitor: unknown"

    header = lines[0]
    mode_match = re.search(r"\(([^)]+)\)", header)
    mode = (mode_match.group(1).strip().lower() if mode_match else "monitor")
    status_match = re.search(r"\)\s*=\s*([a-z]+)\s*@", header, flags=re.IGNORECASE)
    status = (status_match.group(1).strip().lower() if status_match else "unknown")

    details: List[str] = []
    for ln in lines[1:]:
        if ln.endswith(":"):
            continue
        cleaned = ln.lstrip("- ").strip()
        if not cleaned:
            continue
        cleaned = re.sub(r"\s{2,}", " ", cleaned)
        details.append(cleaned)

    reason = ""
    if mode == "storage":
        reasons = [d for d in details if "native storage probe unavailable" in d.lower() or "fallback probe" in d.lower()]
        reason = reasons[0] if reasons else (details[0] if details else "")
        facts = details[:3]
    elif mode == "smart":
        reason = details[0] if details else ""
        facts = details[:4]
    elif mode == "backup":
        reason = details[0] if details else ""
        facts = details[:3]
    elif mode == "service":
        down_items = [d for d in details if "not_found" in d.lower() or "stopped" in d.lower() or "paused" in d.lower()]
        reason = down_items[0] if down_items else (details[0] if details else "")
        facts = down_items[:3] if down_items else details[:3]
    elif mode in {"ping", "port", "dns"}:
        reason = details[0] if details else ""
        facts = details[:2]
    else:
        reason = details[0] if details else ""
        facts = details[:2]

    if details and len(facts) < len(details):
        facts.append(f"+{len(details) - len(facts)} more")

    parts = [f"{mode}: {status}"]
    if reason:
        parts.append(reason)
    if facts:
        parts.append("; ".join(facts))
    compact = " | ".join(parts)
    if len(compact) > max_len:
        compact = compact[: max_len - 3] + "..."
    return compact


def prompt(text: str, default: Optional[str] = None) -> str:
    if default is not None:
        val = input(f"{text} [{default}]: ").strip()
        return val if val else default
    return input(f"{text}: ").strip()


def prompt_with_back(text: str, default: Optional[str] = None) -> Optional[str]:
    val = prompt(text, default)
    return None if (val and val.lower() in BACK_KEYS) else (val or "")


def confirm_save(action: str = "apply") -> bool:
    raw = prompt(f"{action}? (s)ave / (b)ack discard", "b").strip().lower() or "b"
    return raw in ("s", "save", "y", "yes")


def prompt_multi_indices(max_n: int, text: str) -> Optional[List[int]]:
    while True:
        raw = input(f"{text} (0=back, a=all): ").strip().lower()
        if raw in BACK_KEYS:
            return None
        if raw == "a":
            return list(range(1, max_n + 1))
        try:
            vals = [int(x.strip()) for x in raw.split(",") if x.strip()]
            if any(v < 1 or v > max_n for v in vals):
                raise ValueError
            return sorted(set(vals))
        except ValueError:
            print("Enter numbers like 1,3 or use 'a' for all.")


def add_monitor() -> None:
    print("\n--- Add monitor ---")
    print(CHANGES_NOTICE)
    mode = prompt_with_back("Check mode: mount / smart / storage / ping / port / dns / backup / service", "mount")
    if mode is None:
        return
    mode = (mode or "mount").lower()
    if mode not in CHECK_MODES:
        print("Invalid mode.")
        return

    devices: List[str] = []
    monitor_mounts: List[Dict[str, str]] = []
    if mode == "mount":
        mounts = get_mounts()
        if not mounts:
            print("No mounts found.")
            return
        print("\nDetected mounts:")
        for i, (_dev, mpoint, fstype) in enumerate(mounts, 1):
            print(f"  [{i}] {mpoint} ({fstype})")
        idxs = prompt_multi_indices(len(mounts), "Select mount(s)")
        if idxs is None:
            return
        monitor_mounts = [
            {"device": mounts[i - 1][0], "mount_point": mounts[i - 1][1], "fstype": mounts[i - 1][2]}
            for i in idxs
        ]
    if mode == "smart":
        detected = _detect_synology_devices()
        candidates = detected["sata"] + detected["block"] + detected["scsi"]
        if not candidates:
            print("No SATA/block/SCSI devices detected. Script will auto-detect at runtime.")
        else:
            print("\nDetected SMART devices:")
            for i, d in enumerate(candidates, 1):
                print(f"  [{i}] {d}")
            idxs = prompt_multi_indices(len(candidates), "Select device(s) for SMART")
            if idxs is None:
                return
            devices = [candidates[i - 1] for i in idxs]
    probe_host = ""
    probe_port = 0
    dns_name = ""
    dns_server = ""
    service_names = ""
    service_description_filter = ""
    if mode == "ping":
        probe_host = (prompt_with_back("Ping target host/IP", "") or "").strip()
        if not probe_host:
            print("Ping target is required.")
            return
    if mode == "port":
        probe_host = (prompt_with_back("Port probe host/IP", "") or "").strip()
        probe_port_raw = (prompt_with_back("Port probe TCP port", "443") or "443").strip()
        try:
            probe_port = int(probe_port_raw)
        except ValueError:
            probe_port = 0
        if not probe_host or probe_port < 1 or probe_port > 65535:
            print("Valid host and port are required.")
            return
    if mode == "dns":
        dns_name = (prompt_with_back("DNS hostname/domain", "") or "").strip()
        dns_server = (prompt_with_back("DNS server (optional, empty=system resolver)", "") or "").strip()
        if not dns_name:
            print("DNS hostname/domain is required.")
            return
    if mode == "service":
        service_names = (prompt_with_back("Service names (comma-separated, optional with description filter)", "") or "").strip()
        service_description_filter = (prompt_with_back("Service description filter (optional with service names)", "") or "").strip()
        if not service_names and not service_description_filter:
            print("Service mode requires service names and/or a description filter.")
            return

    kuma_url = prompt_with_back("Kuma push URL (https://host/api/push/TOKEN)", "")
    if kuma_url is None or not kuma_url:
        print("URL required.")
        return
    if not kuma_url.startswith(("http://", "https://")):
        kuma_url = "https://" + kuma_url
    kuma_url = normalize_kuma_url(kuma_url)
    err = validate_kuma_url(kuma_url)
    if err:
        print(f"Invalid URL: {err}")
        return

    name = prompt_with_back("Monitor name", f"{mode}-unix-check")
    if name is None:
        return
    print(
        f"\nName: {name}\nMode: {mode}\nDevices: {', '.join(devices) if devices else '(auto)'}"
        f"\nMounts: {', '.join(m['mount_point'] for m in monitor_mounts) if monitor_mounts else '(none)'}\nURL: {kuma_url}"
    )
    if not confirm_save("Add monitor"):
        print("Discarded.")
        return

    cfg = load_config()
    cfg.setdefault("monitors", []).append(
        {
            "name": name,
            "check_mode": mode,
            "devices": devices,
            "mounts": monitor_mounts,
            "kuma_url": kuma_url,
            "probe_host": probe_host,
            "probe_port": probe_port,
            "dns_name": dns_name,
            "dns_server": dns_server,
            "service_names": service_names,
            "service_description_filter": service_description_filter,
        }
    )
    save_config(cfg)
    print(f"Added monitor '{name}'.")


def run_check(debug: Optional[bool] = None, interactive: bool = True) -> None:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    dbg = debug if debug is not None else cfg.get("debug", False)
    if interactive:
        print("\n--- Run check ---")
    if dbg:
        print("  [debug] enabled")
    if not monitors:
        print("  No monitors configured. Add one first.")
    for m in monitors:
        name = m.get("name", "?")
        mode = str(m.get("check_mode", "smart")).lower()
        if mode not in CHECK_MODES:
            mode = "smart"
        devices = [str(x) for x in m.get("devices", [])]
        url = m.get("kuma_url", "")
        if not url:
            print(f"  x {name}: no Kuma URL")
            continue
        status, msg, lat = check_host_with_monitor(mode, devices, monitor=m, debug=dbg)
        ok = push_to_kuma(url, status, msg, lat, debug=dbg)
        recorded_status = status if ok else "warning"
        _record_history(str(name), mode, recorded_status, lat)
        line = f"{'ok' if ok else 'x'} {name}: {status} (ping={lat:.2f}ms) push {'OK' if ok else 'FAILED'}"
        _set_monitor_state(
            str(name),
            "Automatic monitor check completed" if ok else "Automatic monitor check completed with errors",
            line,
            level="ok" if ok else "err",
        )
        append_ui_log(
            f"scheduled-check | {name} | mode={mode} | status={status} | ping_ms={lat:.2f} | push={'OK' if ok else 'FAILED'}"
        )
        print(f"  {'ok' if ok else 'x'} {name}: {status} (ping={lat:.2f}ms) push {'OK' if ok else 'FAILED'}")
    if interactive:
        print("\n  (Press Enter to go back)")
        input()


def list_configured() -> None:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    print("\n--- Configured monitors ---")
    if not monitors:
        print("  No monitors configured.")
    for i, m in enumerate(monitors, 1):
        print(f"  [{i}] {m.get('name', '?')}")
        print(f"      Mode: {m.get('check_mode', 'smart')}")
        print(f"      Devices: {', '.join(m.get('devices', [])) or '(auto)'}")
        print(f"      URL: {m.get('kuma_url', '?')}")
    print("\n  (Press Enter to go back)")
    input()


def remove_monitor() -> None:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    if not monitors:
        print("No monitors configured.")
        return
    print("\n--- Remove monitor ---")
    print(CHANGES_NOTICE)
    for i, m in enumerate(monitors, 1):
        print(f"  [{i}] {m.get('name', '?')} ({m.get('check_mode', 'smart')})")
    raw = prompt("Number to remove (0=back)", "")
    if not raw or raw.lower() in BACK_KEYS:
        return
    try:
        idx = int(raw)
        if not (1 <= idx <= len(monitors)):
            print("Invalid number.")
            return
    except ValueError:
        print("Invalid number.")
        return
    target = monitors[idx - 1]
    print(f"Remove '{target.get('name', '?')}'?")
    if not confirm_save("Remove monitor"):
        print("Discarded.")
        return
    monitors.pop(idx - 1)
    cfg["monitors"] = monitors
    save_config(cfg)
    print("Removed.")


def manage_cron() -> None:
    cfg = load_config()
    enabled = cfg.get("cron_enabled", False)
    interval = int(cfg.get("cron_interval_minutes", 60))
    content, ok = get_current_crontab()
    has = ok and CRON_MARKER in content
    print("\n--- Automatic checks (cron) ---")
    print(CHANGES_NOTICE)
    if not ok:
        print("  crontab unavailable - manual setup required.")
    print(f"  Status: {'Enabled' if enabled or has else 'Disabled'} (every {interval} min)")
    print("\n  a) Enable automatic checks\n  b) Disable automatic checks\n  c) Change interval\n  d) Back")
    choice = prompt("Choice", "d").strip().lower()
    if choice == "a":
        if not cfg.get("monitors"):
            print("Add at least one monitor first.")
            return
        raw = prompt_with_back(f"Check interval (minutes, min {INTERVAL_MIN})", str(interval))
        if raw is None:
            return
        try:
            interval = max(INTERVAL_MIN, min(INTERVAL_MAX, int(raw)))
        except ValueError:
            interval = 60
        print(f"Enable cron every {interval} minutes")
        if not confirm_save("Enable automatic checks"):
            print("Discarded.")
            return
        cfg["cron_enabled"] = True
        cfg["cron_interval_minutes"] = interval
        applied = ok and add_cron_entry(interval)
        save_config(cfg)
        print("Automatic checks enabled.")
        if not applied:
            print("Add this line manually via crontab -e:")
            print(" ", build_cron_line(get_script_path(), interval))
    elif choice == "b":
        if not confirm_save("Disable automatic checks"):
            print("Discarded.")
            return
        cfg["cron_enabled"] = False
        save_config(cfg)
        remove_cron_entry()
        print("Automatic checks disabled.")
    elif choice == "c":
        raw = prompt_with_back(f"New interval (minutes, min {INTERVAL_MIN})", str(interval))
        if raw is None:
            return
        try:
            new_interval = max(INTERVAL_MIN, min(INTERVAL_MAX, int(raw)))
        except ValueError:
            print("Invalid number.")
            return
        if not confirm_save("Change interval"):
            print("Discarded.")
            return
        cfg["cron_interval_minutes"] = new_interval
        save_config(cfg)
        print(f"Interval set to {new_interval} minutes.")


def test_push() -> None:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    if not monitors:
        print("\n  No monitors configured.")
        print("\n  (Press Enter to go back)")
        input()
        return
    print("\n--- Test push ---")
    for i, m in enumerate(monitors, 1):
        print(f"  [{i}] {m.get('name', '?')}")
    raw = prompt("Select monitor (0=back, a=all)", "a").strip().lower()
    if raw in BACK_KEYS:
        return
    targets: List[Dict[str, Any]] = []
    if raw == "a":
        targets = monitors
    else:
        try:
            idx = int(raw)
            if 1 <= idx <= len(monitors):
                targets = [monitors[idx - 1]]
        except ValueError:
            pass
    if not targets:
        print("Invalid selection.")
        return
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    msg = f"Test push @ {now} - {BRAND_NAME} unix-monitor connectivity check"
    for m in targets:
        ok = push_to_kuma(m.get("kuma_url", ""), "up", msg, 0, debug=True)
        print(f"  {'ok' if ok else 'x'} {m.get('name', '?')}: push {'OK' if ok else 'FAILED'}")
    print("\n  (Press Enter to go back)")
    input()


def toggle_debug() -> None:
    cfg = load_config()
    cfg["debug"] = not cfg.get("debug", False)
    save_config(cfg)
    print(f"\n  Debug mode: {'ON' if cfg['debug'] else 'OFF'}")


def toggle_update_from_main() -> None:
    """Toggle update_from_main: when ON, updates fetch from main branch instead of latest release."""
    cfg = load_config()
    cfg["update_from_main"] = not cfg.get("update_from_main", False)
    save_config(cfg, reapply_cron=False)
    on_off = "ON" if cfg["update_from_main"] else "OFF"
    print(f"\n  Update from main (testing): {on_off}")
    print("  Future updates will use " + ("main branch" if cfg["update_from_main"] else "latest release") + ".")


def _peering_message_banner(message: str) -> str:
    if not str(message or "").strip():
        return ""
    return f"<div class='ok' style='margin-top:8px;white-space:pre-wrap;'>{html.escape(message)}</div>"


def _peering_info_panel(
    *,
    peering_message: str,
    role: str,
    master_port: int,
    master_host: str,
    peering_token: str,
    sec: Dict[str, Any],
    approval_status: str = "",
) -> str:
    """All peering status/info banners in one place (above action buttons)."""
    parts: List[str] = []
    if str(approval_status or "").strip() == "pending":
        parts.append(
            "<div style='padding:10px 12px;border:1px solid rgba(245,158,11,.45);border-radius:8px;"
            "background:rgba(245,158,11,.10);font-size:12px;color:#fbbf24;'>"
            "<strong>Waiting for master approval.</strong> This agent contacted the hosted master and is listed under "
            "<em>Pending pairing</em>. Push and register stay blocked until the operator approves (or batch-approves) "
            "on the master.</div>"
        )
    elif str(approval_status or "").strip() == "rejected":
        parts.append(
            "<div style='padding:10px 12px;border:1px solid rgba(239,68,68,.45);border-radius:8px;"
            "background:rgba(239,68,68,.10);font-size:12px;color:#f87171;'>"
            "<strong>Pairing rejected by master.</strong> Contact the operator or retry sync after they clear the "
            "rejection — a new contact attempt opens a fresh pending pairing.</div>"
        )
    if str(peering_message or "").strip():
        parts.append(_peering_message_banner(peering_message))
    if role != "standalone":
        parts.append(
            "<div style='padding:8px 10px;border:1px solid rgba(16,185,129,.3);border-radius:8px;"
            "background:rgba(16,185,129,.06);font-size:11px;color:#10b981;'>"
            "Peering auto-detects HTTPS and uses it when available."
            "</div>"
        )
    if role == "agent":
        parts.append(
            "<div style='padding:10px 12px;border:1px solid rgba(47,128,237,.4);border-radius:8px;"
            "background:rgba(47,128,237,.08);font-size:12px;'>"
            "<strong>Agent setup (3 steps):</strong>"
            "<ol style='margin:6px 0 0 0;padding-left:18px;'>"
            "<li>On the <b>master</b>, copy the peering token shown there.</li>"
            "<li>Paste it in the token field above &mdash; it must match the master <i>exactly</i>.</li>"
            "<li>Confirm master host, callback host, and ports above, then Save.</li>"
            "</ol></div>"
        )
    if role == "master":
        parts.append(
            "<div style='padding:10px 12px;border:1px solid rgba(16,185,129,.3);border-radius:8px;"
            "background:rgba(16,185,129,.06);font-size:12px;'>"
            "<strong>Master:</strong> Copy this token and share it with each agent. Agents must paste it exactly."
            "</div>"
        )
    if role == "agent" and master_host and peering_token and int(master_port) in (8080, 80, 443):
        parts.append(
            "<div class='muted' style='font-size:11px;padding:8px 10px;"
            "border:1px solid rgba(47,128,237,.35);border-radius:8px;background:rgba(47,128,237,.08);'>"
            "<strong>Hosted master:</strong> use <b>Test connection</b> then <b>Sync now</b> — certificate is optional. "
            "Master must listen on LAN (HOSTED_BIND_IP=0.0.0.0), not localhost-only.</div>"
        )
    if role == "agent" and master_host and peering_token and not sec.get("instance_cert_ok"):
        parts.append(
            "<div class='muted' style='font-size:11px;'>"
            "CSR signing needs a master with CA enabled. Skip certificate request for hosted token-only peering."
            "</div>"
        )
    if not parts:
        return ""
    return (
        "<div class='peering-info-strip' style='margin-top:12px;display:flex;flex-direction:column;gap:8px;'>"
        + "".join(parts)
        + "</div>"
    )


def _render_peering_card(cfg: Dict[str, Any], peering_message: str = "", peering_diagnostics: str = "") -> str:
    instance_id = _get_instance_id(cfg)
    instance_name = str(cfg.get("instance_name", "") or "")
    role = _cfg_peer_role(cfg)
    peering_token = str(cfg.get("peering_token", "") or "")
    _master_host, _master_port = _parse_peer_host_port(
        cfg.get("peer_master_url", ""), _peer_master_port(cfg)
    )
    _cb_host, _cb_port = _parse_peer_host_port(
        cfg.get("agent_callback_url", ""), _peer_agent_port(cfg)
    )
    master_host = _master_host
    agent_callback_host = _cb_host
    master_port = _peer_master_port(cfg)
    agent_port = _peer_agent_port(cfg)
    peers = cfg.get("peers", [])
    if not isinstance(peers, list):
        peers = []

    last_sync = int(cfg.get("last_peer_sync", 0) or 0)
    last_sync_result = str(cfg.get("last_peer_sync_result", "") or "")
    last_sync_latency = cfg.get("last_peer_sync_latency_ms")
    last_sync_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_sync)) if last_sync else "never"

    token_display = peering_token or "not set"

    # mTLS security status
    sec = _get_mtls_security_status(cfg)

    role_opts = ""
    for r in _peer_roles():
        sel = "selected" if r == role else ""
        role_opts += f"<option value='{r}' {sel}>{r.capitalize()}</option>"

    role_lock_reason = _peer_role_change_blocked_reason(cfg)
    role_select_disabled = bool(role_lock_reason)
    if _rollout_agent_mode():
        role_select_block = (
            "<div class='muted' style='font-size:12px;padding:8px 10px;border:1px solid rgba(47,128,237,.35);"
            "border-radius:8px;background:rgba(47,128,237,.08);'>"
            "<strong>Rollout agent</strong> — connects to a hosted master only. "
            "Standalone and master modes are not available in this edition.</div>"
            "<input type='hidden' name='peer_role' value='agent'>"
        )
        role_lock_note = ""
    elif role_lock_reason == "agent":
        role_lock_note = (
            "<div class='muted' style='font-size:11px;margin-top:6px;max-width:560px;line-height:1.45;'>"
            "Role is locked while this agent is connected to a master (stored master certificate or a successful sync). "
            "Use <strong>Disconnect from master</strong> below to unlock, then pick another role.</div>"
        )
    elif role_lock_reason == "master":
        role_lock_note = (
            "<div class='muted' style='font-size:11px;margin-top:6px;max-width:560px;line-height:1.45;'>"
            "Role is locked while configured peers exist. Remove <strong>every</strong> agent in "
            "<strong>Peering cleanup</strong> (below in this form) first, then change role.</div>"
        )
    else:
        role_lock_note = ""
    if _rollout_agent_mode():
        pass
    elif role_select_disabled:
        role_select_block = (
            f"<input type='hidden' name='peer_role' value='{html.escape(role)}'>"
            f"<select aria-disabled='true' disabled "
            f"style='opacity:.65;cursor:not-allowed;' title='Role change is disabled until requirements above are met.'>"
            f"{role_opts}</select>"
        )
    else:
        role_select_block = f"<select name='peer_role'>{role_opts}</select>"
    agent_disconnect_html = ""
    if role == "agent" and _peer_agent_bound_to_master(cfg) and not _rollout_agent_mode():
        agent_disconnect_html = (
            "<div style='margin-top:10px;padding:10px 12px;border:1px solid rgba(245,158,11,.35);border-radius:8px;"
            "background:rgba(245,158,11,.06);'>"
            "<div class='muted' style='font-size:11px;margin-bottom:8px;line-height:1.45;'>"
            "To switch to Master, disconnect first. Switching to Standalone clears master host, token, and stored trust.</div>"
            "<form method='post' action='/peer/agent-disconnect-master' style='margin:0;' "
            "onsubmit=\"return confirm('Disconnect from master? Clears stored master certificate and last sync status.');\">"
            "<button type='submit' style='border-color:#f59e0b;color:#f59e0b;background:transparent;'>"
            "Disconnect from master</button></form></div>"
        )

    live_panel_html = ""
    master_peer_actions_html = ""
    now = int(time.time())
    valid_peers = [p for p in peers if _is_valid_peer_instance_id(str(p.get("instance_id", "") or ""))] if peers else []
    online = 0
    offline = 0
    peer_monitor_count = sum(int(p.get("monitor_count", 0) or 0) for p in peers) if peers else 0
    last_sync_ts = int(cfg.get("last_peer_sync", 0) or 0)
    last_sync_txt = time.strftime("%H:%M:%S", time.localtime(last_sync_ts)) if last_sync_ts else "never"
    peer_rows = ""
    if peers:
        seen_peer_row: set[str] = set()
        for p in peers:
            pid = str(p.get("instance_id", "") or "").strip()
            if not _is_valid_peer_instance_id(pid):
                continue
            if pid in seen_peer_row:
                continue
            seen_peer_row.add(pid)
            pname = str(p.get("instance_name", "") or pid[:8])
            last_seen = int(p.get("last_seen", 0) or 0)
            age = now - last_seen if last_seen else 9999
            pstatus = "online" if age < PEER_HEALTH_TIMEOUT_SEC else "offline"
            mc = int(p.get("monitor_count", 0) or 0)
            p_url = str(p.get("url", "") or "")
            p_latency = p.get("latency_ms")
            # Keep initial page render non-blocking; status-json polling updates this live.
            p_open_url = _peer_url_for_open(p_url)
            pclass = "ok" if pstatus == "online" else "err"
            if pstatus == "online":
                online += 1
            else:
                offline += 1
            seen_short = time.strftime("%H:%M:%S", time.localtime(last_seen)) if last_seen else "never"
            lat_txt = f"{p_latency} ms" if p_latency else "-"
            p_version = str(p.get("version", "") or "")
            pbtn = "padding:6px 12px;font-size:12px;border-radius:8px;font-weight:600;white-space:nowrap;cursor:pointer;line-height:1.2;border:1px solid #36517a;background:transparent;color:#c8dbf8;"
            update_supported, source_platform, update_block_reason = _peer_update_capability(cfg, pid)
            unknown_update_allowed = _is_unknown_update_override_enabled(cfg, pid)
            update_btn = (
                f"<button type='button' class='agent-update-btn' data-peer-id='{html.escape(pid)}' data-peer-name='{html.escape(pname)}' style='{pbtn}'>Update</button>"
                if update_supported
                else f"<button type='button' class='agent-update-btn' disabled title='{html.escape(update_block_reason)}' style='{pbtn}opacity:.55;cursor:not-allowed;'>Update</button>"
            )
            if source_platform == "unknown":
                toggle_value = "0" if unknown_update_allowed else "1"
                toggle_label = "Block unknown updates" if unknown_update_allowed else "Allow unknown updates"
                hint_inner = _peer_update_options_hint_inner_html(cfg, pid)
                update_options_cell = (
                    f"<details class='peer-update-policy-menu'>"
                    f"<summary class='peer-update-policy-summary' title='{html.escape('Unclear platform: open for details and to allow or block remote updates.')}' style='{pbtn}'>update-options</summary>"
                    f"<div class='peer-update-policy-panel'>{hint_inner}"
                    f"<form method='post' action='/peer/update-unknown-policy' style='margin:0;'>"
                    f"<input type='hidden' name='peer_id' value='{html.escape(pid)}'>"
                    f"<input type='hidden' name='allow_unknown_update' value='{toggle_value}'>"
                    f"<button type='submit' class='peer-update-policy-submit' style='{pbtn}width:100%;text-align:left;display:block;'>{toggle_label}</button>"
                    f"</form>"
                    f"</div>"
                    f"</details>"
                )
            else:
                update_options_cell = "<span class=\"peer-action-placeholder peer-action-col-update-options\" aria-hidden=\"true\"></span>"
            open_cell = (
                f"<a href='{html.escape(p_open_url)}' target='_blank' rel='noopener noreferrer' "
                f"style='{pbtn}text-decoration:none;display:inline-block;text-align:center;'>"
                f"Open</a>"
            ) if p_open_url else "<span class=\"peer-action-placeholder peer-action-col-open\" aria-hidden=\"true\"></span>"
            version_badge = f"<span class='badge muted-badge' data-role='peer-version'>v{html.escape(p_version)}</span>" if p_version else ""
            synced_badge = f"<span class='badge muted-badge' data-role='peer-synced'>Synced: {html.escape(seen_short)}</span>"
            peer_rows += (
                f"<div class='peer-row' data-peer-id='{html.escape(pid)}' data-peer-url='{html.escape(p_url)}' "
                f"style='border:1px solid rgba(42,61,90,.35);border-radius:8px;background:rgba(15,23,38,.6);padding:10px 12px;margin-bottom:8px;'>"
                f"<div style='display:flex;align-items:center;gap:10px;flex-wrap:wrap;'>"
                f"<span class='badge {pclass}' style='min-width:56px;text-align:center;'>{pstatus}</span>"
                f"<strong style='flex:1;font-size:13px;'>{html.escape(pname)}</strong>"
                f"{synced_badge}"
                f"<span class='badge muted-badge' data-role='peer-monitors'>{mc} monitors</span>"
                f"{version_badge}"
                f"</div>"
                f"<div style='display:flex;align-items:center;gap:8px;margin-top:6px;'>"
                f"<span class='muted' style='font-size:11px;'>Last seen: {html.escape(seen_short)} ({lat_txt})</span>"
                f"<span class='muted' style='font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>{html.escape(p_url or 'no URL')}</span>"
                f"</div>"
                f"<div class='peer-actions-row'>"
                f"<form method='post' action='/peer/update-peer-url' style='margin:0;display:flex;gap:4px;align-items:center;min-width:0;'>"
                f"<input type='hidden' name='peer_id' value='{html.escape(pid)}'>"
                f"<input name='peer_url' value='{html.escape(_peer_url_for_input_display(p_url))}' placeholder='Hostname or host:port' style='flex:1;padding:4px 6px;font-size:11px;'>"
                f"<button type='submit' style='{pbtn}'>Set URL</button>"
                f"</form>"
                f"<form method='post' action='/peer/sync-one' style='margin:0;'>"
                f"<input type='hidden' name='peer_id' value='{html.escape(pid)}'>"
                f"<button type='submit' style='{pbtn}'>Sync</button>"
                f"</form>"
                f"{update_btn}"
                f"{update_options_cell}"
                f"{open_cell}"
                f"<form method='post' action='/peer/remove' style='margin:0;'>"
                f"<input type='hidden' name='peer_id' value='{html.escape(pid)}'>"
                f"<button type='submit' onclick=\"return confirm('Remove this agent?')\" "
                f"style='{pbtn}border-color:#ef4444;color:#ef4444;'>Remove</button>"
                f"</form>"
                f"</div>"
                f"</div>"
            )
    no_agents_hint = ""
    if not peers and role == "master":
        no_agents_hint = "<div class='muted' style='font-size:12px;text-align:center;padding:12px 0;'>No agents registered yet. Click <b>Add agent</b> to register one, or agents will appear here automatically once they push data.</div>"
    if role == "master":
        master_peer_actions_html = (
            f"<div style='display:flex;gap:8px;margin-top:10px;align-items:center;justify-content:flex-start;flex-wrap:wrap;'>"
            f"<button type='submit' formaction='/peer/sync-now' formmethod='post'>Sync all agents</button>"
            f"<button type=\"button\" onclick=\"window._openAddAgent && window._openAddAgent(this)\">Add agent</button>"
            f"</div>"
        )
        live_panel_html = (
            f"<div style='margin-top:16px;border:1px solid var(--border);border-radius:10px;background:var(--card-soft);padding:12px;'>"
            f"<div id='peer-header' style='display:flex;align-items:center;gap:10px;margin-bottom:8px;'>"
            f"<strong style='font-size:14px;'>Connected Agents</strong>"
            f"<span id='peer-online-badge' class='badge ok'>{online} online</span>"
            f"<span id='peer-offline-badge' class='badge err' style='{'display:none' if not offline else ''}'>{offline} offline</span>"
            f"<span id='peer-remote-count' class='muted' style='margin-left:auto;'>Remote monitors: {peer_monitor_count}</span>"
            f"</div>"
            f"<div id='peer-live-panel'>"
            + peer_rows + no_agents_hint
            + f"</div>"
            f"</div>"
        )

    agent_fields = ""
    peering_agent_actions_html = ""
    peering_save_actions_html = ""
    if role == "agent":
        agent_fields = f"""
          <label>Master's peering token <span class="muted">(copy from master's Peering card)</span></label>
          <input name="peering_token" value="{html.escape(peering_token)}" placeholder="Paste the master's token here" style="margin-top:6px;">
          <label>Master host <span class="muted">(hostname or IP, no http/https/port)</span></label>
          <input name="peer_master_url" value="{html.escape(master_host)}" placeholder="Hostname or IP of the master">
          <label>Agent callback host <span class="muted">(this NAS hostname or IP for master to reach you)</span></label>
          <input name="agent_callback_url" value="{html.escape(agent_callback_host)}" placeholder="This host's hostname or IP">
          <label>Master port <span class="muted">(master API/UI, e.g. 8080 for hosted master)</span></label>
          <input name="peer_master_port" type="number" value="{master_port}" placeholder="Default 8787" min="1" max="65535" style="max-width:120px;">
          <label>Agent callback port <span class="muted">(this agent's UI/API port)</span></label>
          <input name="peer_agent_port" type="number" value="{agent_port}" placeholder="Default 8787" min="1" max="65535" style="max-width:120px;">
        """
        peering_agent_actions_html = f"""
        <div class="button-row peering-action-row" style="gap:8px;margin-top:10px;flex-wrap:wrap;">
          <button type="submit" form="peering-save-form">Save peering settings</button>
          <button type="submit" form="peering-save-form" formaction="/peer/test-connection" formmethod="post">Test connection to master</button>
          <form method="post" action="/peer/sync-now" style="margin:0;display:inline-flex;">
            <button type="submit">Sync now</button>
          </form>
        </div>
        """
    elif role == "master":
        peering_save_actions_html = """
        <div class="button-row peering-action-row" style="margin-top:10px;">
          <button type="submit" form="peering-save-form">Save peering settings</button>
        </div>
        """
    else:
        peering_save_actions_html = """
        <div class="button-row peering-action-row" style="margin-top:10px;">
          <button type="submit" form="peering-save-form">Save peering settings</button>
        </div>
        """

    # Build security status panel
    _sec_style = "border:1px solid rgba(42,61,90,.35);border-radius:8px;background:rgba(15,23,38,.6);padding:10px 12px;margin-top:12px;"
    _sec_badge_style = "display:inline-block;padding:3px 8px;border-radius:6px;font-size:11px;font-weight:600;"
    if sec["mtls_active"]:
        _sec_level = f"<span style='{_sec_badge_style}background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.3);'>mTLS Active</span>"
    elif sec["ca_exists"]:
        _sec_level = f"<span style='{_sec_badge_style}background:rgba(245,158,11,.15);color:#f59e0b;border:1px solid rgba(245,158,11,.3);'>TLS Only (instance cert missing)</span>"
    elif peering_token and role != "standalone":
        _sec_level = f"<span style='{_sec_badge_style}background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3);'>Encrypted Payload (no TLS)</span>"
    else:
        _sec_level = ""

    _sec_rows = ""
    _signing_badge = ""
    if sec["signing_active"]:
        _signing_badge = f"<span style='{_sec_badge_style}background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.3);'>Request Signing Active</span>"
    elif role != "standalone" and sec["openssl_available"] and sec["instance_cert_ok"]:
        _signing_badge = f"<span style='{_sec_badge_style}background:rgba(245,158,11,.15);color:#f59e0b;border:1px solid rgba(245,158,11,.3);'>Signing Ready</span>"
    if role != "standalone":
        _sec_rows += f"<div style='display:flex;align-items:center;gap:8px;flex-wrap:wrap;'>"
        _sec_rows += f"<span class='muted' style='font-size:12px;'>Security:</span> {_sec_level} {_signing_badge}"
        _sec_rows += f"<span class='muted' style='font-size:11px;'>OpenSSL: {'available' if sec['openssl_available'] else 'not found'}</span>"
        _sec_rows += f"</div>"
        _sec_rows += f"<div class='muted' style='font-size:11px;margin-top:4px;'>Request signing provides identity verification through any reverse proxy.</div>"
        if sec["ca_exists"]:
            fp = sec["ca_fingerprint"]
            _sec_rows += f"<div class='muted' style='font-size:11px;margin-top:6px;'>CA Fingerprint: <code style='font-size:10px;word-break:break-all;'>{html.escape(fp[:48])}...</code></div>"
        if role == "agent" and sec.get("has_master_cert"):
            _sec_rows += f"<div class='muted' style='font-size:11px;margin-top:4px;color:#10b981;'>Master certificate: stored (response verification enabled)</div>"
        elif role == "agent" and not sec.get("has_master_cert") and sec["instance_cert_ok"]:
            _sec_rows += f"<div class='muted' style='font-size:11px;margin-top:4px;color:#f59e0b;'>Master certificate: not yet received (re-request cert to obtain it)</div>"

    # Master: CA management + signed agents
    _sec_actions_master = ""
    if role == "master":
        if not sec["ca_exists"]:
            _sec_actions_master = (
                "<div style='margin-top:8px;'>"
                "<form method='post' action='/peer/generate-ca' style='margin:0;'>"
                "<button type='submit'>Generate CA certificate</button>"
                "</form>"
                "<div class='muted' style='font-size:11px;margin-top:4px;'>Creates a private CA to sign agent certificates for mTLS.</div>"
                "</div>"
            )
        else:
            if not sec["instance_cert_ok"]:
                _sec_actions_master += (
                    "<div style='margin-top:8px;'>"
                    "<form method='post' action='/peer/generate-server-cert' style='margin:0;'>"
                    "<button type='submit'>Generate server certificate</button>"
                    "</form>"
                    "<div class='muted' style='font-size:11px;margin-top:4px;'>Required for TLS. Restart the addon after generating.</div>"
                    "</div>"
                )
            signed = sec["signed_agents"]
            if signed:
                _agent_certs = ""
                for a in signed:
                    prow = _peer_entry_for_instance_id(cfg, a)
                    if prow is None:
                        lbl_html = (
                            "<div class='muted' style='font-size:11px;margin-top:4px;'>"
                            "No matching peer row yet (agent must register or push).</div>"
                        )
                    else:
                        pname = str(prow.get("instance_name", "") or "").strip()
                        purl = str(prow.get("url", "") or "").strip()
                        url_line = ""
                        if purl:
                            url_line = (
                                f"<div class='muted' style='font-size:11px;margin-top:2px;word-break:break-all;'>"
                                f"{html.escape(purl)}</div>"
                            )
                        if pname:
                            lbl_html = (
                                f"<div style='font-size:11px;margin-top:4px;color:#b8cae3;'>"
                                f"<strong>{html.escape(pname)}</strong></div>"
                                f"{url_line}"
                            )
                        else:
                            lbl_html = (
                                "<div class='muted' style='font-size:11px;margin-top:4px;'>"
                                "No display name saved yet.</div>"
                                f"{url_line}"
                            )
                    _agent_certs += (
                        f"<div style='display:flex;align-items:flex-start;gap:8px;margin-top:8px;'>"
                        f"<div style='flex:1;min-width:0;'>"
                        f"<div class='muted' style='font-size:11px;word-break:break-all;'>"
                        f"Instance ID: <code>{html.escape(_display_peer_instance_id(a))}</code></div>"
                        f"{lbl_html}"
                        f"</div>"
                        f"<form method='post' action='/peer/revoke-agent-cert' style='margin:0;flex-shrink:0;'>"
                        f"<input type='hidden' name='agent_id' value='{html.escape(a)}'>"
                        f"<button type='submit' style='padding:6px 12px;font-size:12px;border:1px solid #ef4444;color:#ef4444;background:transparent;border-radius:8px;font-weight:600;cursor:pointer;line-height:1.2;'"
                        f" onclick=\"return confirm('Revoke certificate for this agent?')\">Revoke</button></form>"
                        f"</div>"
                    )
                _sec_actions_master += (
                    f"<div style='margin-top:8px;'>"
                    f"<div class='muted' style='font-size:12px;font-weight:600;'>Signed Agent Certificates ({len(signed)})</div>"
                    f"<div class='muted' style='font-size:11px;margin-top:4px;'>Each certificate matches the agent instance ID below; "
                    f"names come from the configured peer list when the agent has registered or pushed.</div>"
                    f"{_agent_certs}"
                    f"</div>"
                )

    # Agent: cert request status + re-request button
    _sec_actions_agent = ""
    if role == "agent":
        _req_btn = (
            "<form method='post' action='/peer/request-cert' style='margin:0;display:inline-block;'>"
            "<button type='submit'>Re-request certificate</button>"
            "</form>"
        )
        if sec["instance_cert_ok"] and sec["ca_exists"]:
            _sec_actions_agent = (
                f"<div style='margin-top:8px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;'>"
                f"<span class='muted' style='font-size:11px;color:#10b981;'>Certificate: signed by master CA</span>"
                f"{_req_btn}"
                f"</div>"
            )
        elif master_host and peering_token:
            _sec_actions_agent = (
                "<div style='margin-top:8px;'>"
                "<div class='muted' style='font-size:11px;'>"
                "Certificate is requested automatically after the master approves pairing and push succeeds. "
                "Use the button below to retry manually.</div>"
                "<form method='post' action='/peer/request-cert' style='margin:8px 0 0;'>"
                "<button type='submit'>Request certificate from master</button>"
                "</form>"
                "</div>"
            )

    security_panel = ""
    if role != "standalone":
        security_panel = (
            f"<div style='{_sec_style}'>"
            f"<div style='font-size:13px;font-weight:600;margin-bottom:6px;'>Connection Security</div>"
            f"{_sec_rows}"
            f"{_sec_actions_master}"
            f"{_sec_actions_agent}"
            f"</div>"
        )

    # Token section: role-specific labels and actions
    if role == "master":
        token_section = f"""
          <label>Peering Token <span class="muted">(agents must use this exact token)</span></label>
          <div style="margin-top:4px;"><code style="word-break:break-all;font-size:11px;">{html.escape(token_display)}</code></div>
          <input name="peering_token" placeholder="Or paste to replace" style="margin-top:6px;">
          <div style="display:flex;gap:8px;margin-top:10px;align-items:center;">
            <button type="submit" formaction="/peer/generate-token" formmethod="post">Generate new token</button>
          </div>
        """
    elif role == "agent":
        token_section = ""
    else:
        token_section = ""  # standalone: no peering token

    peer_cleanup_html = ""
    if role == "master":
        reg_ids = sorted(_registered_peer_instance_ids(cfg))
        peers_by_id: Dict[str, Dict[str, Any]] = {}
        for p in (cfg.get("peers", []) or []):
            if not isinstance(p, dict):
                continue
            pid = str(p.get("instance_id", "") or "").strip()
            if _is_valid_peer_instance_id(pid):
                peers_by_id[pid] = p
        peer_cleanup_rows = ""
        _rm_btn_style = (
            "padding:6px 12px;font-size:12px;border:1px solid #ef4444;color:#ef4444;"
            "background:transparent;border-radius:8px;font-weight:600;cursor:pointer;line-height:1.2;"
        )
        for pid in reg_ids:
            prow = peers_by_id.get(pid, {})
            pname = str(prow.get("instance_name", "") or "").strip()
            if pname:
                name_html = (
                    f"<div style='font-size:11px;margin-top:4px;color:#b8cae3;'>"
                    f"<strong>{html.escape(pname)}</strong></div>"
                )
            else:
                name_html = (
                    "<div class='muted' style='font-size:11px;margin-top:4px;'>"
                    "No display name saved yet.</div>"
                )
            peer_cleanup_rows += (
                f"<div style='display:flex;align-items:flex-start;gap:8px;margin-top:8px;'>"
                f"<div style='flex:1;min-width:0;'>"
                f"<div class='muted' style='font-size:11px;word-break:break-all;'>"
                f"Instance ID: <code>{html.escape(_display_peer_instance_id(pid))}</code></div>"
                f"{name_html}"
                f"</div>"
                f"<form method='post' action='/peer/remove' style='margin:0;flex-shrink:0;'>"
                f"<input type='hidden' name='peer_id' value='{html.escape(pid)}'>"
                f"<button type='submit' style='{_rm_btn_style}'"
                f" onclick=\"return confirm('Remove this agent from configuration and delete its cache file?')\">"
                f"Remove</button></form>"
                f"</div>"
            )
        if not peer_cleanup_rows:
            peer_cleanup_rows = (
                "<div class='muted' style='font-size:11px;margin-top:6px;'>No agents in the peer list yet.</div>"
            )
        peer_cleanup_html = f"""
        <div style="margin-top:14px;padding:12px;border:1px solid rgba(245,158,11,.28);border-radius:10px;background:rgba(245,158,11,.07);">
          <strong style="font-size:13px;">Peering cleanup</strong>
          <div class="muted" style="margin-top:6px;font-size:11px;line-height:1.45;">
            Remove stale agents from Overview / Create Monitor, delete leftover snapshot files, or merge duplicate peer rows.
          </div>
          <div style="margin-top:10px;">
            <div class="muted" style="font-size:12px;font-weight:600;">Configured peers ({len(reg_ids)})</div>
            <div class="muted" style="font-size:11px;margin-top:4px;">Each row is one agent; Remove deletes its configuration entry and cached snapshot.</div>
            {peer_cleanup_rows}
          </div>
          <div class="button-row" style="margin-top:12px;flex-wrap:wrap;gap:8px;">
            <form method="post" action="/peer/prune-orphan-snapshots" style="margin:0;" onsubmit="return confirm('Delete cached snapshot files for any instance ID not in the list above?');">
              <button type="submit">Prune orphan snapshot files</button>
            </form>
            <form method="post" action="/peer/dedupe-peers" style="margin:0;">
              <button type="submit">Deduplicate peer list</button>
            </form>
          </div>
          <form method="post" action="/peer/remove" style="margin-top:10px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;" onsubmit="return confirm('Remove this instance ID from configuration and delete its cache file?');">
            <label class="muted" style="font-size:12px;margin:0;">Remove by instance ID</label>
            <input name="peer_id" placeholder="Paste full instance UUID" style="min-width:220px;flex:1;max-width:min(100%,420px);">
            <button type="submit" style="border-color:#ef4444;color:#ef4444;">Remove</button>
          </form>
        </div>
        """

    peering_diagnostics_text = (peering_diagnostics or "").strip() or (
        "Run 'Test connection to master' or 'Sync now' to capture diagnostics."
    )
    peering_info_html = _peering_info_panel(
        peering_message=peering_message,
        role=role,
        master_port=master_port,
        master_host=master_host,
        peering_token=peering_token,
        sec=sec,
        approval_status=str(cfg.get("peer_master_approval_status", "") or ""),
    )

    return f"""
      <div class="card" id="peering-card">
        <h3>{"Hosted fleet agent" if _rollout_agent_mode() else "Multi-Instance Peering"}</h3>
        <div class="muted">{"Push monitor status to your hosted master. Configure master URL and peering token below." if _rollout_agent_mode() else "Connect multiple instances for cross-network monitoring. Agents push results to a master dashboard."}</div>
        <div class="muted" style="margin-top:6px;display:flex;flex-wrap:wrap;align-items:center;gap:8px;">
          <span>Instance ID: <code id="peer-instance-id">{html.escape(_display_peer_instance_id(instance_id))}</code></span>
          <button type="button" class="btn secondary copy-peer-instance-id-btn" style="padding:4px 10px;font-size:12px;line-height:1.2;">Copy</button>
        </div>
        {security_panel}
        {agent_disconnect_html}
        <form id="peering-save-form" method="post" action="/peer/save-settings">
          <div>
            <label>Role</label>
            {role_select_block}
            {role_lock_note}
          </div>
          {master_peer_actions_html}
          {token_section}
          {agent_fields}
        </form>
        {peering_info_html}
        {peering_agent_actions_html}
        {peering_save_actions_html}
        <div class="muted" style="margin-top:10px;">Peering diagnostics</div>
        <pre class="code" style="margin-top:6px;max-height:14rem;overflow:auto;">{html.escape(peering_diagnostics_text)}</pre>
        {peer_cleanup_html}
        {live_panel_html}
      </div>
    """


def _render_setup_html(
    message: str = "",
    error: str = "",
    action_output: str = "",
    elevated_check_message: str = "",
    elevated_check_output: str = "",
    log_filter: str = "all",
    log_date: str = "all",
    log_time_scope: str = "all",
    log_time_from: str = "",
    log_time_to: str = "",
    edit_target: str = "",
    create_mode: bool = False,
    diag_view: str = "logs",
    show_setup_popup: bool = False,
    monitor_action_name: str = "",
    monitor_action_message: str = "",
    monitor_action_output: str = "",
    automation_message: str = "",
    automation_output: str = "",
    security_message: str = "",
    security_output: str = "",
    peering_message: str = "",
    peering_diagnostics: str = "",
    ssl_warning: str = "",
    ui_view: str = "overview",
    highlight_channel: str = "",
    log_source: str = "local",
    diagnose_agent: bool = False,
    open_server_panel: str = "",
    export_backup_error: str = "",
    import_backup_error: str = "",
) -> str:
    cfg = load_config()
    browser_instance_name = str(cfg.get("instance_name", "") or "").strip()
    if not browser_instance_name:
        browser_instance_name = str(cfg.get("instance_id", "") or "").strip()[:8]
    monitors = cfg.get("monitors", [])
    interval = int(cfg.get("cron_interval_minutes", 60))
    cron_enabled = bool(cfg.get("cron_enabled", False))
    history = _load_history()
    monitor_state = _load_monitor_state()

    edit_monitor = _find_monitor_by_name(monitors, edit_target) if edit_target else None
    if create_mode and not edit_monitor:
        current_name = "smart-unix-check"
        current_mode = "smart"
        current_url = ""
    else:
        current_name = (
            str(edit_monitor.get("name", ""))
            if edit_monitor
            else (monitors[0].get("name", "unix-main") if monitors else "unix-main")
        )
        current_mode = (
            str(edit_monitor.get("check_mode", "smart"))
            if edit_monitor
            else (monitors[0].get("check_mode", "smart") if monitors else "smart")
        )
        current_url = (
            str(edit_monitor.get("kuma_url", ""))
            if edit_monitor
            else (monitors[0].get("kuma_url", "") if monitors else "")
        )
    current_probe_host = str(edit_monitor.get("probe_host", "")) if edit_monitor else ""
    current_probe_port = str(edit_monitor.get("probe_port", "")) if edit_monitor else ""
    current_dns_name = str(edit_monitor.get("dns_name", "")) if edit_monitor else ""
    current_dns_server = str(edit_monitor.get("dns_server", "")) if edit_monitor else ""
    current_service_names = str(edit_monitor.get("service_names", "")) if edit_monitor else ""
    current_service_desc_filter = str(edit_monitor.get("service_description_filter", "")) if edit_monitor else ""
    edit_original_name = str(edit_monitor.get("name", "")) if edit_monitor else ""
    current_interval = int(edit_monitor.get("interval", edit_monitor.get("cron_interval_minutes", cfg.get("cron_interval_minutes", 5)))) if edit_monitor else 5
    current_cron_enabled = bool(edit_monitor.get("cron_enabled", cfg.get("cron_enabled", True))) if edit_monitor else True
    _cm = str(current_mode or "smart").strip().lower()
    modal_ph_display = "block" if _cm in ("ping", "port") else "none"
    modal_pp_display = "block" if _cm == "port" else "none"
    modal_dns_display = "block" if _cm == "dns" else "none"
    modal_service_display = "block" if _cm == "service" else "none"

    status_html = ""
    # Elevated check result: only show in Setup & Elevated Access section, not at top
    from_elevated_check = bool(elevated_check_message or elevated_check_output)
    if message and not monitor_action_name and not from_elevated_check:
        status_html += f"<div class='ok'>{html.escape(message)}</div>"
    if error and not monitor_action_name and not from_elevated_check:
        status_html += f"<div class='err'>{html.escape(error)}</div>"
    if action_output and not monitor_action_name and not from_elevated_check:
        status_html += f"<pre>{html.escape(action_output)}</pre>"
    if ssl_warning:
        status_html = f"<div class='err'>{html.escape(ssl_warning)}</div>" + status_html
    peer_role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
    local_source_name = browser_instance_name or "Local"
    available_sources: List[Tuple[str, str]] = [("local", local_source_name)]
    if peer_role == "master":
        peer_snapshot_name_by_id: Dict[str, str] = {}
        for snap in _load_all_peer_snapshots():
            snap_id = str(snap.get("instance_id", "") or "").strip()
            if not _is_valid_peer_instance_id(snap_id):
                continue
            snap_name = str(snap.get("instance_name", "") or "").strip()
            if snap_name:
                peer_snapshot_name_by_id[snap_id] = snap_name
        seen_peer_src: set[str] = set()
        for sp in (cfg.get("peers", []) or []):
            sp_id = str(sp.get("instance_id", "") or "").strip()
            if not _is_valid_peer_instance_id(sp_id):
                continue
            if sp_id in seen_peer_src:
                continue
            seen_peer_src.add(sp_id)
            sp_name = str(peer_snapshot_name_by_id.get(sp_id, "") or sp.get("instance_name", "") or sp_id[:8])
            available_sources.append((sp_id, sp_name))

    source_map = {sid: sname for sid, sname in available_sources}
    log_source = (log_source or "local").strip()
    if log_source not in source_map:
        log_source = "local"
    source_label = log_source
    source_name = source_map.get(source_label, local_source_name)
    source_is_remote = source_label != "local"
    log_date_norm = _normalize_log_date(log_date)
    log_time_norm = _normalize_log_time_scope(log_time_scope)
    log_time_from_norm = _normalize_log_time_hhmm(log_time_from)
    log_time_to_norm = _normalize_log_time_hhmm(log_time_to)

    agent_log_async = False
    if source_is_remote and diag_view in ("logs", "task", "config", "cache", "history", "paths", "system"):
        if diagnose_agent:
            log_text = _diagnose_agent_diag_connection(cfg, source_label)
        else:
            log_text = "Loading agent logs..."
            agent_log_async = True
    else:
        log_text = _build_diag_text(
            cfg,
            history,
            diag_view=diag_view,
            log_filter=log_filter,
            log_date=log_date_norm,
            log_time_scope=log_time_norm,
            log_time_from=log_time_from_norm,
            log_time_to=log_time_to_norm,
        )
    scheduler_cache_key = (
        "scheduler:"
        + str(cfg.get("scheduler_backend", "cron"))
        + ":"
        + str(int(cfg.get("cron_interval_minutes", 60) or 60))
        + ":"
        + ("1" if bool(cfg.get("cron_enabled", False)) else "0")
    )
    automation_data = _get_cached_render_value(
        scheduler_cache_key,
        ttl_sec=8,
        loader=lambda: _scheduler_status_data(cfg),
        default_value={
            "raw_text": "Loading scheduler status...",
            "scheduler_process": "loading",
            "scheduler_timer": "loading",
            "timer_next": "loading",
            "timer_last": "loading",
        },
    )
    automation_status = str(automation_data.get("raw_text", ""))
    auth_state = _load_auth_state()
    recovery_unused = _count_unused_recovery(auth_state)
    request_interface = _request_interface_host()
    server_ip = request_interface or _get_cached_render_value(
        "server_ip",
        ttl_sec=60,
        loader=lambda: _detect_primary_server_ip(),
        default_value="n/a",
    )
    all_ips = _get_cached_render_value(
        "system_ips",
        ttl_sec=60,
        loader=lambda: _list_system_ips(),
        default_value=[],
    )
    ui_bind_host = _normalize_ui_bind_host(cfg.get("ui_bind_host", "0.0.0.0"), all_ips)
    ui_bind_port = _normalize_ui_bind_port(cfg.get("ui_bind_port", 8787))
    internet_settings = _internet_check_settings_from_cfg(cfg)
    bind_host_options = _ui_bind_host_options(all_ips)
    bind_scope_text = (
        "All interfaces (0.0.0.0)"
        if ui_bind_host == "0.0.0.0"
        else ("Localhost only (127.0.0.1)" if ui_bind_host == "127.0.0.1" else f"Specific interface ({ui_bind_host})")
    )
    bind_options_html = "".join(
        f"<option value='{html.escape(ip)}'{' selected' if ip == ui_bind_host else ''}>{html.escape('All interfaces (0.0.0.0)' if ip == '0.0.0.0' else ('Localhost only (127.0.0.1)' if ip == '127.0.0.1' else ip))}</option>"
        for ip in bind_host_options
    )
    ntp_info = _get_cached_render_value(
        "ntp_sync_details",
        ttl_sec=120,
        loader=lambda: _ntp_sync_details(),
        default_value={"synced": "unknown", "service": "unknown", "source": "unknown", "detail": "Loading NTP details..."},
    )
    peer_last_sync = int(cfg.get("last_peer_sync", 0) or 0)
    peer_last_sync_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(peer_last_sync)) if peer_last_sync else "never"
    now_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    last_login_ip = str(auth_state.get("last_login_ip", "") or "n/a")
    last_login_at = int(auth_state.get("last_login_at", 0) or 0)
    last_login_at_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_login_at)) if last_login_at else "never"
    login_history = auth_state.get("login_history", []) if isinstance(auth_state.get("login_history", []), list) else []
    login_lines: List[str] = []
    for ev in reversed(login_history[-8:]):
        if not isinstance(ev, dict):
            continue
        ts = int(ev.get("ts", 0) or 0)
        ts_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "unknown"
        ip = str(ev.get("ip", "unknown") or "unknown")
        state = str(ev.get("state", "unknown") or "unknown")
        login_lines.append(f"{ts_text} | {ip} | {state}")
    if not login_lines:
        login_lines = ["No login history recorded yet."]

    elevated_ok, elevated_msg = get_smart_helper_status()
    elevated_css = "ok" if elevated_ok else "err"
    helper_script_path = str(get_smart_helper_script_path())
    task_status = _read_task_status()
    task_hint = _detect_task_hint()
    if task_status:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(task_status.get("attempted_at", 0) or 0)))
        task_state = "SUCCESS" if task_status.get("success") else "FAILED"
        task_summary = str(task_status.get("summary", ""))
        task_detail = str(task_status.get("detail", ""))
        task_status_text = f"Last auto-create: {task_state} @ {ts}\n{task_summary}\n{task_detail}\n{task_hint}"
    else:
        task_status_text = f"No auto-create attempt yet.\n{task_hint}"

    setup_open_attr = " open" if (from_elevated_check or not elevated_ok) else ""
    setup_state_text = "Setup complete - section collapsed by default." if elevated_ok else "Setup required - complete the steps below."
    setup_state_css = "ok" if elevated_ok else "err"

    # Build monitor status map from history.
    monitor_latest: Dict[str, Dict[str, Any]] = {}
    for e in history:
        name = str(e.get("monitor", ""))
        if name:
            monitor_latest[name] = e

    def status_class(status: str) -> str:
        return {"up": "st-up", "warning": "st-warning", "down": "st-down"}.get(status, "st-unknown")

    def status_pct(status: str) -> int:
        return {"up": 100, "warning": 55, "down": 15}.get(status, 0)

    def status_label(status: str) -> str:
        return status.upper() if status in ("up", "warning", "down") else "UNKNOWN"

    # Overview gauges are scoped to the selected source context.
    source_snapshot = _build_live_snapshot_for_source(source_label)
    source_label = str(source_snapshot.get("source_id", source_label) or "local")
    source_name = str(source_snapshot.get("source_name", source_name) or source_name)
    source_is_remote = source_label != "local"
    source_channels = source_snapshot.get("channels", {}) if isinstance(source_snapshot.get("channels", {}), dict) else {}
    source_monitors = source_snapshot.get("monitors", []) if isinstance(source_snapshot.get("monitors", []), list) else []
    channels_order = ("smart", "storage", "ping", "port", "dns", "backup", "service")
    source_monitor_channels = {
        str(m.get("mode", m.get("check_mode", "smart"))).lower()
        for m in source_monitors
        if isinstance(m, dict)
    }
    overview_channels = [c for c in channels_order if c in source_channels or c in source_monitor_channels]
    if not overview_channels:
        overview_channels = ["smart", "storage"]

    channel_cards: List[str] = []
    for channel in overview_channels:
        ch_data = source_channels.get(channel, {}) if isinstance(source_channels.get(channel, {}), dict) else {}
        st = str(ch_data.get("status", "unknown"))
        pct = int(ch_data.get("pct", status_pct(st)) or status_pct(st))
        last_ts = int(ch_data.get("ts", 0) or 0)
        ts_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_ts)) if last_ts else "n/a"
        history_statuses = ch_data.get("history_statuses", []) if isinstance(ch_data.get("history_statuses", []), list) else []
        dots = "".join(
            f"<span class='dot {status_class(str(x))}' title='{html.escape(str(x))}'></span>"
            for x in history_statuses[-20:]
        ) or "<span class='muted'>no history</span>"
        mapped = []
        for m in source_monitors:
            mode = str(m.get("mode", m.get("check_mode", "smart"))).lower()
            if mode == channel:
                mapped.append(str(m.get("name", "?")))
        mapped_count = len(mapped)
        if mapped_count == 0:
            mapped_text = "Monitors: 0"
        else:
            mapped_text = f"Monitors: {mapped_count}"
        mapped_title = ", ".join(mapped) if mapped else "No mapped monitors"
        is_hl = (highlight_channel == channel)
        channel_cards.append(
            f"<div class='overview-card {'hl-channel' if is_hl else ''}' data-channel='{channel}'>"
            f"<h4>{channel.capitalize()} Monitoring</h4>"
            f"<a class='gauge-link' href='/?view=overview&diag_view=logs&log_filter={channel}&highlight={channel}&source={html.escape(source_label)}&log_date={html.escape(log_date_norm)}&log_time_scope={html.escape(log_time_norm)}'>"
            f"<div class='gauge {status_class(st)}' data-role='gauge' style='--pct:{pct}'>"
            f"<div class='gauge-center'><div class='gauge-value' data-role='gauge-value'>{status_label(st)}</div><div class='gauge-sub' data-role='gauge-sub'>{pct}%</div></div>"
            "</div>"
            "</a>"
            f"<div class='muted' data-role='channel-last'>Last update: {html.escape(ts_text)}</div>"
            f"<div class='muted' title='{html.escape(mapped_title)}'>{html.escape(mapped_text)}</div>"
            f"<div class='history-dots' data-role='channel-dots'>{dots}</div>"
            "</div>"
        )
    overview_html = "".join(channel_cards)

    # Current-server section follows selected source context.
    display_source_name = source_name if source_name else local_source_name
    display_server_ip = server_ip
    display_now_text = now_text
    display_runtime_version = VERSION
    display_last_login_ip = last_login_ip
    display_last_login_at_text = last_login_at_text
    if source_is_remote:
        remote_snap = _load_peer_snapshot(source_label)
        peer_cfg = next(
            (p for p in (cfg.get("peers", []) or []) if str(p.get("instance_id", "") or "").strip() == source_label),
            None,
        )
        peer_url = str(peer_cfg.get("url", "") or "") if isinstance(peer_cfg, dict) else ""
        peer_host, _peer_port = _parse_peer_host_port(peer_url, PEER_DEFAULT_PORT)
        display_server_ip = peer_host or "remote"
        remote_version = str((remote_snap or {}).get("version", "") or "").strip()
        if remote_version:
            display_runtime_version = remote_version
        pushed_at = int((remote_snap or {}).get("pushed_at", 0) or 0)
        display_now_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pushed_at)) if pushed_at else "n/a"
        remote_login_ip = str((remote_snap or {}).get("last_login_ip", "") or "").strip()
        remote_login_at = int((remote_snap or {}).get("last_login_at", 0) or 0)
        display_last_login_ip = remote_login_ip or "n/a (remote)"
        display_last_login_at_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(remote_login_at)) if remote_login_at else "n/a (remote)"

    # Setup steps with integrated screenshots.
    guide_images = get_task_guide_images()
    step_defs: List[Tuple[str, str, str, str]] = [
        ("STEP 1", "Open Task Scheduler", "Control Panel -> Task Scheduler.", "task-scheduler-guide.png"),
        ("STEP 2", "Set User root", "In General tab set user to root.", "task-step-general.png"),
        ("STEP 3", "Set Schedule", "Set repeat schedule (recommended every 5 minutes).", "task-step-schedule.png"),
        ("STEP 4", "Set Command", "Use helper script command shown below.", "task-step-command.png"),
        ("STEP 5", "Run Once", "Run the task once in DSM before access check.", ""),
        ("STEP 6", "Validate", "Press Check elevated access now.", ""),
    ]
    step_cards: List[str] = []
    gallery_urls: List[str] = []
    for step_num, title, desc, img_name in step_defs:
        img_html = ""
        p = guide_images.get(img_name) if img_name else None
        if p and p.exists():
            gallery_index = len(gallery_urls)
            gallery_urls.append(f"/guide-image?name={img_name}")
            img_html = (
                "<div class='guide-card'>"
                f"<a class='screenshot-link' href='#' data-gallery-index='{gallery_index}'>"
                f"<div class='img-wrap zoom-wrap'><img class='zoom-img' src='/guide-image?name={html.escape(img_name)}' alt='{html.escape(title)}'></div>"
                "</a>"
                f"<div class='guide-label'>{html.escape(title)}</div>"
                "</div>"
            )
        step_cards.append(
            "<div class='step-box'>"
            f"<div class='step-num'>{html.escape(step_num)}</div>"
            f"<div class='step-title'>{html.escape(title)}</div>"
            f"<div class='step-desc'>{html.escape(desc)}</div>"
            f"{img_html}"
            "</div>"
        )
    step_cards_html = "".join(step_cards)

    # Build lookup of master-side remote monitor configs (keyed by name) for Kuma tokens.
    remote_monitor_cfg: Dict[str, Dict[str, Any]] = {}
    if peer_role == "master":
        for m in monitors:
            if m.get("_remote_peer"):
                remote_monitor_cfg[str(m.get("name", ""))] = m

    # Local monitor cards.
    local_cards: List[str] = []
    for m in monitors:
        if m.get("_remote_peer"):
            continue
        name = str(m.get("name", "?"))
        mode = str(m.get("check_mode", "smart"))
        url = str(m.get("kuma_url", ""))
        token_label = kuma_token_label(url)
        latest = monitor_latest.get(name, {})
        st = str(latest.get("status", "unknown"))
        ping = latest.get("ping_ms", "n/a")
        tsv = int(latest.get("ts", 0) or 0)
        ts_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tsv)) if tsv else "never"
        auto_enabled = bool(m.get("cron_enabled", cfg.get("cron_enabled", False)))
        auto_badge = f"<span class='badge {'st-up' if auto_enabled else 'st-warning'}'>auto {'ON' if auto_enabled else 'OFF'}</span>"
        action_payload = monitor_state.get(name, {})
        action_banner = str(action_payload.get("banner", "") or "")
        action_output = str(action_payload.get("output", "") or "")
        action_level = "err" if str(action_payload.get("level", "ok")) == "err" else "ok"
        if monitor_action_name and monitor_action_name == name:
            action_banner = monitor_action_message or action_banner or "Action completed"
            action_output = monitor_action_output or action_output
            action_level = "err" if action_level == "err" else "ok"
        monitor_action_html = (
            f"<div class='{action_level}'>{html.escape(action_banner)}</div>"
            + (f"<pre>{html.escape(action_output)}</pre>" if action_output else "")
            if action_banner or action_output
            else ""
        )
        local_cards.append(
            f"<div class='monitor-card {'hl-monitor' if (highlight_channel and highlight_channel == str(mode).lower()) else ''}' data-monitor='{html.escape(name)}' data-mode='{html.escape(str(mode).lower())}'>"
            + f"<div class='monitor-head'><div class='monitor-title'>{html.escape(name)}</div><div style='display:flex;align-items:center;gap:6px;justify-content:flex-end;text-align:right;'>{auto_badge}<span class='badge monitor-status-badge {status_class(st)}'>{status_label(st)}</span></div></div>"
            + f"<div class='monitor-meta' data-role='monitor-primary'>Mode: {html.escape(mode)} | Interval: {m.get('interval', cfg.get('cron_interval_minutes', 5))}m | Last ping: {html.escape(str(ping))} ms | Last run: {html.escape(ts_text)}</div>"
            + f"<div class='monitor-meta token-row'>Token: <code>{html.escape(token_label)}</code></div>"
            + f"<div data-role='monitor-live'>{monitor_action_html}</div>"
            + "<div class='button-row'>"
            + f"<button onclick=\"monitorAction('/run-check-monitor','{html.escape(name)}',this)\">Run check</button>"
            + f"<button onclick=\"monitorAction('/test-push-monitor','{html.escape(name)}',this)\">Test push</button>"
            + f"<button onclick=\"monitorAction('/edit-monitor','{html.escape(name)}',this)\">Edit</button>"
            + f"<button class='btn-remove' onclick=\"if(confirm('Delete monitor?'))monitorAction('/delete-monitor','{html.escape(name)}',this)\">Delete</button>"
            + "</div>"
            + "</div>"
        )

    # Remote / agent monitor cards (grouped by agent host / origin).
    remote_by_host: Dict[str, Dict[str, Any]] = {}
    if peer_role == "master":
        reg_peer_ids = _registered_peer_instance_ids(cfg)
        peers_list_for_remote = cfg.get("peers", []) if isinstance(cfg.get("peers", []), list) else []
        for tp in peers_list_for_remote:
            if not isinstance(tp, dict):
                continue
            tp_id = str(tp.get("instance_id", "") or "").strip()
            if not tp_id or tp_id not in reg_peer_ids:
                continue
            tp_name = str(tp.get("instance_name", "") or tp_id[:8])
            remote_by_host.setdefault(
                tp_id,
                {
                    "name": tp_name,
                    "legacy": _is_legacy_peer(tp),
                    "platform": str(tp.get("source_platform", "") or "unknown"),
                    "cards": [],
                },
            )
        for snap in _load_all_peer_snapshots():
            snap_iid = str(snap.get("instance_id", "") or "").strip()
            if not snap_iid or snap_iid not in reg_peer_ids:
                continue
            snap_name = str(snap.get("instance_name", "") or str(snap.get("instance_id", ""))[:8])
            peer_row = _peer_entry_for_instance_id(cfg, snap_iid) or {}
            group = remote_by_host.setdefault(
                snap_iid,
                {
                    "name": snap_name,
                    "legacy": _is_legacy_peer(peer_row),
                    "platform": str(peer_row.get("source_platform", "") or "unknown"),
                    "cards": [],
                },
            )
            group["name"] = snap_name
            snap_history = snap.get("history", [])
            snap_state_raw = snap.get("state", {})
            snap_state: Dict[str, Dict[str, Any]] = {}
            if isinstance(snap_state_raw, dict):
                for mk, mv in snap_state_raw.items():
                    k = str(mk or "").strip()
                    if not k:
                        continue
                    snap_state[k] = mv if isinstance(mv, dict) else {}
            elif isinstance(snap_state_raw, list):
                # Backward-compatible read path: older peers may serialize state as a list.
                for item in snap_state_raw:
                    if not isinstance(item, dict):
                        continue
                    mk = (
                        str(item.get("monitor", "") or "").strip()
                        or str(item.get("name", "") or "").strip()
                        or str(item.get("monitor_name", "") or "").strip()
                    )
                    if not mk:
                        continue
                    snap_state[mk] = item
            snap_ml: Dict[str, Dict[str, Any]] = {}
            for e in snap_history:
                mn = str(e.get("monitor", ""))
                if mn:
                    snap_ml[mn] = e
            for pm in snap.get("monitors", []):
                pn = _peer_monitor_name(pm, "?")
                pm_mode = _peer_monitor_mode(pm)
                pl = snap_ml.get(pn, {})
                pst = str(pl.get("status", "unknown"))
                pp = pl.get("ping_ms", "n/a")
                pt = int(pl.get("ts", 0) or 0)
                pt_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pt)) if pt else "never"
                ps = snap_state.get(pn, {})
                pb = str(ps.get("banner", "") or "")
                po = str(ps.get("output", "") or "")
                plvl = "err" if str(ps.get("level", "ok")) == "err" else "ok"
                pa_html = (
                    f"<div class='{plvl}'>{html.escape(pb)}</div>"
                    + (f"<pre>{html.escape(po)}</pre>" if po else "")
                    if pb or po else ""
                )
                master_cfg = remote_monitor_cfg.get(pn, {})
                r_kuma = str(master_cfg.get("kuma_url", "") or "")
                r_token_label = kuma_token_label(r_kuma) if r_kuma else ""
                r_token_html = f"<div class='monitor-meta token-row'>Token: <code>{html.escape(r_token_label)}</code></div>" if r_token_label else ""
                card_html = (
                    f"<div class='monitor-card {'hl-monitor' if (highlight_channel and highlight_channel == pm_mode.lower()) else ''}' data-monitor='{html.escape(pn)}' data-mode='{html.escape(pm_mode.lower())}' data-agent-host='{html.escape(snap_name)}'>"
                    + f"<div class='monitor-head'><div class='monitor-title'>{html.escape(pn)}</div>"
                    + f"<span class='badge monitor-status-badge {status_class(pst)}'>{status_label(pst)}</span></div>"
                    + f"<div class='monitor-meta' data-role='monitor-primary'>Mode: {html.escape(pm_mode)} | Last ping: {html.escape(str(pp))} ms | Last run: {html.escape(pt_text)} | Origin: {html.escape(snap_name)}</div>"
                    + r_token_html
                    + f"<div data-role='monitor-live'>{pa_html}</div>"
                    + "<div class='button-row'>"
                    + f"<button class='btn-remove' onclick=\"if(confirm('Remove remote monitor from master?'))monitorAction('/delete-monitor','{html.escape(pn)}',this)\">Remove</button>"
                    + "</div>"
                    + "</div>"
                )
                group["cards"].append(card_html)
    local_monitors_html = "".join(local_cards) if local_cards else "<p class='muted'>No local monitors configured yet.</p>"
    remote_monitors_html = ""
    if peer_role == "master":
        legacy_peer_names = [
            str(g.get("name", "") or "")
            for g in remote_by_host.values()
            if bool(g.get("legacy"))
        ]
        remote_total = sum(len(g.get("cards", [])) for g in remote_by_host.values())
        legacy_banner = ""
        if legacy_peer_names:
            legacy_banner = (
                "<div class='info-callout legacy-warning-callout' style='margin-bottom:12px;'>"
                f"<strong>{len(legacy_peer_names)} legacy agent(s) connected</strong> via token peering ("
                + html.escape(", ".join(legacy_peer_names))
                + "). Monitors appear after the agent pushes a snapshot. Use <strong>Create monitor</strong> "
                "and confirm the legacy warning when targeting a legacy agent.</div>"
            )
        if not remote_by_host:
            remote_grid = (
                "<div class='monitor-grid'><div class='monitor-card'>"
                "<div class='monitor-head'><span class='monitor-title'>No agents connected</span>"
                "<span class='badge st-unknown'>offline</span></div>"
                "<div class='monitor-meta'>Pair or register an agent in <strong>Settings</strong>, then wait for the next push sync.</div>"
                "</div></div>"
            )
        else:
            host_sections: List[str] = []
            for host_id in sorted(remote_by_host.keys(), key=lambda x: str(remote_by_host[x].get("name", x)).lower()):
                group = remote_by_host[host_id]
                hcards = group.get("cards", [])
                host_name = str(group.get("name", host_id[:8]))
                legacy_badge = "<span class='badge st-warning'>legacy</span>" if group.get("legacy") else ""
                platform = str(group.get("platform", "") or "").strip()
                platform_badge = f"<span class='badge muted-badge'>{html.escape(platform)}</span>" if platform and platform != "unknown" else ""
                if hcards:
                    cards_html = "".join(hcards)
                else:
                    cards_html = (
                        "<div class='monitor-card'><div class='monitor-head'>"
                        "<span class='monitor-title'>Waiting for monitor data</span>"
                        "<span class='badge st-warning'>pending</span></div>"
                        "<div class='monitor-meta'>Agent registered but no monitors in the latest push yet. "
                        "Trigger a sync on the agent or create a monitor above.</div></div>"
                    )
                host_sections.append(
                    f"<div class='agent-host-monitor-group' data-agent-host='{html.escape(host_name)}'>"
                    f"<h4 class='agent-host-heading'>{html.escape(host_name)} "
                    f"<span class='badge muted-badge'>{len(hcards)}</span> {legacy_badge} {platform_badge}</h4>"
                    f"<div class='monitor-grid'>{cards_html}</div>"
                    f"</div>"
                )
            remote_grid = f"<div class='agent-monitors-by-host'>{''.join(host_sections)}</div>"
        remote_monitors_html = (
            f"<div class='card' style='margin-top:12px;'>"
            f"<h3>Agent Monitors <span class='badge muted-badge'>{remote_total}</span></h3>"
            f"<div class='muted' style='margin-bottom:8px;'>Monitors running on remote agent instances. Status is updated via peering sync. "
            f"Kuma push is handled by the master.</div>"
            f"{legacy_banner}"
            f"{remote_grid}"
            f"</div>"
        )

    checked_cron = "checked" if current_cron_enabled else ""
    filter_label = {"all": "all", "smart": "smart", "storage": "storage", "ping": "ping", "port": "port", "dns": "dns", "backup": "backup", "service": "service"}.get((log_filter or "all").lower(), "all")
    diag_label = {
        "logs": "logs",
        "task": "task",
        "config": "config",
        "cache": "cache",
        "history": "history",
        "paths": "paths",
        "system": "system",
    }.get((diag_view or "logs").lower(), "logs")
    log_bytes, log_lines_total = get_ui_log_stats()
    diag_view_labels = {
        "logs": "Logs",
        "task": "Task",
        "cache": "Cache",
        "config": "Config",
        "history": "History",
        "paths": "Paths",
        "system": "System",
    }
    event_labels = {
        "all": "All events",
        "smart": "Smart",
        "storage": "Storage",
        "ping": "Ping",
        "port": "Port",
        "dns": "DNS",
        "backup": "Backup",
        "service": "Service",
    }
    date_labels = {"all": "Any date", "today": "Today", "yesterday": "Yesterday"}
    time_labels = {
        "all": "Any time",
        "15m": "Last 15 minutes",
        "1h": "Last hour",
        "6h": "Last 6 hours",
        "24h": "Last 24 hours",
    }
    _dv_human = diag_view_labels.get(diag_label, diag_label)
    _ev_human = event_labels.get(filter_label, filter_label)
    _date_human = date_labels.get(log_date_norm, log_date_norm)
    _time_human = time_labels.get(log_time_norm, log_time_norm)
    _time_exact_human = (
        (log_time_from_norm or "--:--") + " to " + (log_time_to_norm or "--:--")
        if (log_time_from_norm or log_time_to_norm)
        else "full day"
    )
    log_diag_banner = (
        "<div class='log-diag-active-banner' role='status'><strong>Viewing:</strong> "
        + html.escape(_dv_human)
        + " · "
        + html.escape(_ev_human)
        + " · "
        + html.escape(_date_human)
        + " · "
        + html.escape(_time_human + " · exact " + _time_exact_human)
        + "</div>"
    )
    if source_label == "local" and diag_label == "logs":
        log_diag_stats = (
            "<div class='log-diag-meta'>UI log file: "
            + html.escape(_fmt_ui_log_size(log_bytes))
            + f" · {log_lines_total:,} lines on disk · rolling window: up to {UI_LOG_DISPLAY_LINES} newest matching lines (scroll).</div>"
        )
    elif source_label != "local" and diag_label == "logs":
        log_diag_stats = (
            "<div class='log-diag-meta'>UI log file: remote agent (" + html.escape(source_name) + ") · size/line count shown on agent UI · rolling window: up to " + str(UI_LOG_DISPLAY_LINES) + " newest matching lines (scroll).</div>"
        )
    else:
        log_diag_stats = ""
    _dvo = "".join(
        f"<option value='{html.escape(v)}'{' selected' if diag_label == v else ''}>{html.escape(diag_view_labels[v])}</option>"
        for v in ("logs", "task", "cache", "config", "history", "paths", "system")
    )
    _evo = "".join(
        f"<option value='{html.escape(v)}'{' selected' if filter_label == v else ''}>{html.escape(event_labels[v])}</option>"
        for v in ("all", "smart", "storage", "ping", "port", "dns", "backup", "service")
    )
    _date_value = "" if log_date_norm == "all" else log_date_norm
    _tto = "".join(
        f"<option value='{html.escape(v)}'{' selected' if log_time_norm == v else ''}>{html.escape(time_labels[v])}</option>"
        for v in ("all", "15m", "1h", "6h", "24h")
    )
    _diag_view_human = diag_view_labels.get(diag_label, diag_label.title())
    _is_logs_view = diag_label == "logs"
    _event_options_html = _evo if _is_logs_view else f"<option value='all' selected>Not available for {html.escape(_diag_view_human)}</option>"
    _time_options_html = _tto if _is_logs_view else f"<option value='all' selected>Not available for {html.escape(_diag_view_human)}</option>"
    _event_disabled_attr = "" if _is_logs_view else " disabled"
    _time_disabled_attr = "" if _is_logs_view else " disabled"
    _advanced_inputs_disabled_attr = "" if _is_logs_view else " disabled"
    _advanced_summary_text = "Advanced filtering" if _is_logs_view else f"Advanced filtering (not available for {_diag_view_human})"
    _filter_note_text = (
        f"All filters are available for {_diag_view_human} view."
        if _is_logs_view
        else f"{_diag_view_human} view does not support filters. Switch to Logs view to use filtering."
    )
    log_diag_filter_form = (
        "<form method='get' action='/' class='log-diag-filter-form'>"
        "<input type='hidden' name='view' value='overview'>"
        f"<input type='hidden' name='source' value='{html.escape(source_label)}'>"
        "<div class='log-diag-filter-grid'>"
        "<div><label for='diag-view-sel'>Diagnostic view</label>"
        f"<select id='diag-view-sel' name='diag_view'>{_dvo}</select></div>"
        "<div><label for='log-filter-sel'>Event / channel</label>"
        f"<select id='log-filter-sel' name='log_filter'{_event_disabled_attr}>{_event_options_html}</select></div>"
        "<div><label for='log-time-sel'>Time window</label>"
        f"<select id='log-time-sel' name='log_time_scope'{_time_disabled_attr}>{_time_options_html}</select></div>"
        "</div>"
        "<details data-advanced-filtering='1' style='margin-top:10px;'>"
        f"<summary data-advanced-summary='1' style='cursor:pointer;'>{html.escape(_advanced_summary_text)}</summary>"
        "<div class='log-diag-filter-grid' style='margin-top:8px;'>"
        "<div><label for='log-date-inp'>Date (calendar)</label>"
        f"<input id='log-date-inp' type='date' name='log_date' value='{html.escape(_date_value)}'{_advanced_inputs_disabled_attr}></div>"
        "<div><label for='log-time-from'>Time from</label>"
        f"<input id='log-time-from' type='time' name='log_time_from' value='{html.escape(log_time_from_norm)}'{_advanced_inputs_disabled_attr}></div>"
        "<div><label for='log-time-to'>Time to</label>"
        f"<input id='log-time-to' type='time' name='log_time_to' value='{html.escape(log_time_to_norm)}'{_advanced_inputs_disabled_attr}></div>"
        "</div></details>"
        f"<div class='muted' data-log-filter-note='1' style='margin-top:6px;'>{html.escape(_filter_note_text)}</div>"
        "<div class='button-row' style='margin-top:8px;'>"
        "<button type='submit'>Apply filter</button>"
        f"<a class='btn-inline btn-inline-muted' href='/?view=overview&diag_view=logs&log_filter=all&log_date=all&log_time_scope=all&log_time_from=&log_time_to=&source={html.escape(source_label)}'>Clear filters</a>"
        "</div>"
        "</form>"
    )
    log_diag_clear_top = ""
    if diag_label == "logs":
        log_diag_clear_top = (
            "<form method='post' action='/clear-logs' class='log-diag-clear-form' style='display:inline;margin:0;'>"
            "<button type='submit' onclick=\"return confirm('Clear local logs on this instance?');\" style='border-color:#ef4444;color:#ef4444;'>Clear local logs</button></form>"
        )
        if source_label != "local":
            log_diag_clear_top += (
                "<form method='post' action='/clear-logs-remote' class='log-diag-clear-form' style='display:inline;margin:0 0 0 8px;'>"
                "<input type='hidden' name='source' value='" + html.escape(source_label) + "'>"
                "<button type='submit' onclick=\"return confirm('Clear logs on the selected remote agent?');\" style='border-color:#ef4444;color:#ef4444;'>Clear selected agent logs</button></form>"
            )
    elif diag_label == "task":
        log_diag_clear_top = (
            "<form method='post' action='/clear-task-status' class='log-diag-clear-form' style='display:inline;margin:0;'>"
            "<button type='submit' style='border-color:#ef4444;color:#ef4444;'>Clear task data</button></form>"
        )
    elif diag_label == "cache":
        log_diag_clear_top = (
            "<form method='post' action='/clear-cache' class='log-diag-clear-form' style='display:inline;margin:0;'>"
            "<button type='submit' style='border-color:#ef4444;color:#ef4444;'>Clear cache</button></form>"
        )
    elif diag_label == "history":
        log_diag_clear_top = (
            "<form method='post' action='/clear-history' class='log-diag-clear-form' style='display:inline;margin:0;'>"
            "<button type='submit' style='border-color:#ef4444;color:#ef4444;'>Clear history</button></form>"
        )
    elif diag_label == "system":
        log_diag_clear_top = (
            "<form method='post' action='/clear-system-cache' class='log-diag-clear-form' style='display:inline;margin:0;'>"
            "<button type='submit' style='border-color:#ef4444;color:#ef4444;'>Clear system logs</button></form>"
        )
    _log_pre_attrs = ""
    if agent_log_async:
        _log_pre_attrs = (
            ' data-agent-fetch="1" data-peer-id="'
            + html.escape(source_label)
            + '" data-view="'
            + html.escape(diag_label)
            + '" data-log-filter="'
            + html.escape(filter_label)
            + '" data-log-date="'
            + html.escape(log_date_norm)
            + '" data-log-time-scope="'
            + html.escape(log_time_norm)
            + '" data-log-time-from="'
            + html.escape(log_time_from_norm)
            + '" data-log-time-to="'
            + html.escape(log_time_to_norm)
            + '"'
        )
    source_tabs_html = ""
    if peer_role == "master":
        q_base = (
            f"view=overview&amp;diag_view={diag_label}&amp;log_filter={filter_label}"
            f"&amp;log_date={html.escape(log_date_norm)}&amp;log_time_scope={html.escape(log_time_norm)}"
        )
        src_chips = []
        for sid, sname in available_sources:
            src_chips.append(
                f"<a class='chip {'active' if source_label==sid else ''}' "
                f"href='?{q_base}&amp;source={html.escape(sid)}'>"
                f"{html.escape(sname)}"
                "</a>"
            )
        source_tabs_html = (
            "<div class='chip-row source-tabs' style='margin-top:8px;'>"
            + "".join(src_chips)
            + "</div>"
        )
    modal_open = bool(create_mode or edit_original_name)
    modal_title = "Edit Monitor" if edit_original_name else "Create Monitor"
    is_master = peer_role == "master"
    peers_list = cfg.get("peers", []) if is_master else []
    if not isinstance(peers_list, list):
        peers_list = []
    # Master: show "Target Instance" only when at least one peer exists (remote create). Standalone/agent: never show.
    show_monitor_target_selector = bool(is_master and peers_list and not edit_original_name)
    target_options = ""
    if show_monitor_target_selector:
        target_options = "<option value='local' selected>Local (this instance)</option>"
        seen_target_ids: set[str] = set()
        for tp in peers_list:
            tp_id = str(tp.get("instance_id", "") or "").strip()
            # Ignore malformed/stale peer IDs in the create-monitor target selector.
            if (not _is_valid_peer_instance_id(tp_id)) or tp_id in seen_target_ids:
                continue
            seen_target_ids.add(tp_id)
            tp_name = str(tp.get("instance_name", "") or tp_id[:8])
            legacy_suffix = " — legacy" if _is_legacy_peer(tp) else ""
            legacy_flag = "1" if _is_legacy_peer(tp) else "0"
            target_options += (
                f"<option value='{html.escape(tp_id)}' data-legacy-peer='{legacy_flag}'>"
                f"{html.escape(tp_name)}{legacy_suffix}</option>"
            )
    ui_view = (ui_view or "overview").strip().lower()
    if ui_view not in ("overview", "setup", "settings"):
        ui_view = "overview"
    if create_mode or edit_original_name:
        ui_view = "setup"

    stay_popup_field = "<input type='hidden' name='stay_popup' value='1'> " if show_setup_popup else ""
    gallery_urls_json = json.dumps(gallery_urls)
    elevated_check_html = ""
    if elevated_check_message:
        elevated_check_html += f"<div class='ok'>{html.escape(elevated_check_message)}</div>"
    if elevated_check_output:
        elevated_check_html += f"<pre>{html.escape(elevated_check_output)}</pre>"
    setup_card = f"""
    <details class="card"{setup_open_attr}>
      <summary>Setup & Elevated Access</summary>
      <div class="{setup_state_css}">{html.escape(setup_state_text)}</div>
      <div class="{elevated_css}">{html.escape(elevated_msg)}</div>
      {elevated_check_html}
      <h4>Quick Steps</h4>
      <div class="step-grid">
        {step_cards_html}
      </div>
      <div class="muted">Helper script command: <code>{html.escape(helper_script_path)}</code></div>
      <div class="muted"><strong>Update note:</strong> after every package update, run the DSM task once to refresh elevated cache.</div>
      <div class="button-row">
        <form method="post" action="/auto-create-task">{stay_popup_field}<button type="submit">Auto-create task (beta)</button></form>
        <form method="post" action="/check-elevated">{stay_popup_field}<button type="submit">Check elevated access now</button></form>
      </div>
      <pre>{html.escape(task_status_text)}</pre>
    </details>
    """
    setup_popup_card = setup_card.replace(f'<details class="card"{setup_open_attr}>', '<details class="card" open>')

    popup_status_html = ""
    if show_setup_popup:
        if message:
            popup_status_html += f"<div class='ok'>{html.escape(message)}</div>"
        if error:
            popup_status_html += f"<div class='err'>{html.escape(error)}</div>"
        if action_output:
            popup_status_html += f"<pre>{html.escape(action_output)}</pre>"
    setup_popup_html = (
        "<div class='modal-backdrop open'><div class='modal'>"
        + popup_status_html
        + setup_popup_card
        + "<a class='close-link' href='/'>Close</a></div></div>"
        if show_setup_popup
        else ""
    )
    nav_html = (
        "<div class='card'><div class='chip-row nav-tabs'>"
        + f"<a class='chip {'active' if ui_view=='overview' else ''}' href='/?view=overview&diag_view={diag_label}&log_filter={filter_label}&source={html.escape(source_label)}&log_date={html.escape(log_date_norm)}&log_time_scope={html.escape(log_time_norm)}'>Overview</a>"
        + f"<a class='chip {'active' if ui_view=='setup' else ''}' href='/?view=setup'>Monitor Setup</a>"
        + f"<a class='chip {'active' if ui_view=='settings' else ''}' href='/?view=settings'>Settings</a>"
        + "</div>"
        + (source_tabs_html if ui_view == "overview" else "")
        + "</div>"
    )
    source_scope_text = (
        f"Viewing remote source: {source_name} (gauges and diagnostics are scoped to this source)."
        if source_is_remote
        else (f"Viewing local source: {source_name}." if peer_role == "master" else "")
    )
    update_channel = "main" if bool(cfg.get("update_from_main", False)) else "latest"
    update_curl_cmd = (
        f"curl -sSL https://raw.githubusercontent.com/{PUBLIC_GITHUB_REPO}/main/apps/unix-monitor/install.sh"
        f" | sudo env PUBLIC_REPO={PUBLIC_GITHUB_REPO} UNIX_MONITOR_UPDATE_CHANNEL={update_channel} bash"
    )
    has_update_helper = get_update_helper_path().exists()
    has_backup = (get_script_path().parent / "unix-monitor.py.prev").exists()
    autoupdate_enabled = bool(cfg.get("autoupdate_enabled", False))
    update_from_main = bool(cfg.get("update_from_main", False))
    selected_channel = "main" if update_from_main else "latest"
    selected_channel_label = "main" if update_from_main else "latest release"
    update_check_result = _load_update_check_result() if not source_is_remote else {}
    update_check_stale = (not source_is_remote) and _update_check_needs_refresh(cfg=cfg, last=update_check_result)
    latest_version = str(update_check_result.get("public_version", "") or update_check_result.get("latest_version", "") or "")
    cached_channel = str(update_check_result.get("selected_channel", "") or "")
    effective_ref = str(update_check_result.get("effective_ref", "") or update_check_result.get("selected_ref", "") or selected_channel)
    public_label = f"{selected_channel} via {effective_ref}" if effective_ref and effective_ref != selected_channel else selected_channel
    channel_matches_cache = (cached_channel == selected_channel) or (not cached_channel and selected_channel == "latest")
    if update_check_stale or not channel_matches_cache:
        latest_version = ""
    display_runtime_version_short = _version_display_short(display_runtime_version)
    latest_version_short = _version_display_short(latest_version or "unknown")
    # Only show update available if cache says so AND current VERSION is actually older (stale cache fix after manual update)
    update_available = (not update_check_stale) and channel_matches_cache and bool(update_check_result.get("update_available")) and (
        latest_version and _version_tuple(VERSION) < _version_tuple(latest_version)
    )
    update_status_text = "checking..." if (update_check_stale or not channel_matches_cache) else "unknown (use Recheck for updates)"
    if latest_version:
        update_status_text = "update available" if update_available else "up to date"
    update_confirm = (
        f"Update now from {selected_channel_label} to v{latest_version}? Current local version is v{VERSION}. "
        "Config and data will be preserved. Page will reload after update."
        if latest_version
        else f"Run update from {selected_channel_label}? Config and data will be preserved. Page will reload after update."
    )
    package_update_btns = ""
    if not source_is_remote:
        update_ready_banner = ""
        if autoupdate_enabled and update_available and has_update_helper:
            ver_text = f" (v{html.escape(latest_version)})" if latest_version else ""
            update_ready_banner = (
                "<div class='update-ready-banner'>"
                "<span>An update is available" + ver_text + ". </span>"
                "<form method='post' action='/self-update' style='display:inline;' onsubmit='return confirm(\"" + html.escape(update_confirm) + "\");'>"
                "<button type='submit' class='btn-inline'>Update now</button></form>"
                " <form method='post' action='/settings/request-autoupdate-on-logout' style='display:inline;'>"
                "<button type='submit' class='btn-inline btn-inline-muted'>Update after logout</button></form>"
                "</div>"
            )
        enable_btn_class = "autoupdate-btn autoupdate-btn-active" if autoupdate_enabled else "autoupdate-btn"
        disable_btn_class = "autoupdate-btn autoupdate-btn-active" if not autoupdate_enabled else "autoupdate-btn"
        from_main_enable_class = "autoupdate-btn autoupdate-btn-active" if update_from_main else "autoupdate-btn"
        from_main_disable_class = "autoupdate-btn autoupdate-btn-active" if not update_from_main else "autoupdate-btn"
        autoupdate_form = (
            update_ready_banner
            + "<div class='autoupdate-row'>"
            "<form method='post' action='/settings/save-autoupdate' class='autoupdate-form' style='display:inline;'>"
            "<input type='hidden' name='autoupdate_enabled' value='1'>"
            "<button type='submit' class='" + enable_btn_class + "'>Enable autoupdate</button></form>"
            " <form method='post' action='/settings/save-autoupdate' class='autoupdate-form' style='display:inline;'>"
            "<input type='hidden' name='autoupdate_enabled' value='0'>"
            "<button type='submit' class='" + disable_btn_class + "'>Disable autoupdate</button></form>"
            "<span class='autoupdate-hint'>Check on each visit, apply if newer.</span></div>"
            + "<div class='autoupdate-row'>"
            "<form method='post' action='/settings/save-update-from-main' class='autoupdate-form' style='display:inline;'>"
            "<input type='hidden' name='update_from_main' value='1'>"
            "<button type='submit' class='" + from_main_enable_class + "'>Update from main</button></form>"
            " <form method='post' action='/settings/save-update-from-main' class='autoupdate-form' style='display:inline;'>"
            "<input type='hidden' name='update_from_main' value='0'>"
            "<button type='submit' class='" + from_main_disable_class + "'>Update from latest</button></form>"
            "<span class='autoupdate-hint'>Update source controls which public version is checked/applied.</span></div>"
        )
        package_update_btns = autoupdate_form
        if has_update_helper:
            package_update_btns += "<div class='button-row' style='margin-bottom:8px;'><form method='post' action='/self-update' style='display:inline;' onsubmit='return confirm(\"" + html.escape(update_confirm) + "\");'><button type='submit' class='btn-inline'>Update now</button></form>"
        if has_backup and has_update_helper:
            package_update_btns += " <form method='post' action='/self-rollback' style='display:inline;' onsubmit='return confirm(\"Restore previous version?\");'><button type='submit' class='btn-inline' style='border-color:#ef4444;color:#ef4444;'>Rollback</button></form>"
        if "button-row" in package_update_btns:
            package_update_btns += "</div>"
    ip_lines: List[str] = []
    if display_server_ip and display_server_ip not in ("n/a", "remote"):
        ip_lines.append(display_server_ip)
    if source_is_remote:
        if display_server_ip and display_server_ip not in ("n/a", "remote"):
            ip_lines.append("(communication endpoint used for this selected source)")
        ip_list_text = "\n".join(ip_lines) if ip_lines else "No remote communication endpoint available."
    else:
        for ip in all_ips:
            if ip not in ip_lines:
                ip_lines.append(ip)
        if "127.0.0.1" not in ip_lines:
            ip_lines.append("127.0.0.1")
        ip_list_text = "\n".join(ip_lines) if ip_lines else "No IP addresses detected."
    login_history_text = "\n".join(login_lines)
    local_specs = _collect_system_specs()
    spec_cpu = "n/a (remote source)" if source_is_remote else local_specs.get("cpu", "n/a")
    spec_ram = "n/a (remote source)" if source_is_remote else local_specs.get("ram", "n/a")
    spec_disk = "n/a (remote source)" if source_is_remote else local_specs.get("disk", "n/a")
    spec_uptime = "n/a (remote source)" if source_is_remote else local_specs.get("uptime", "n/a")
    cpu_detail_text = (
        f"CPU: {spec_cpu}\nSource: /proc/cpuinfo model/hardware\n{source_scope_text}"
        if not source_is_remote
        else f"CPU: {spec_cpu}\nDetails are available on the selected remote source UI."
    )
    ram_detail_text = (
        f"RAM (Total): {spec_ram}\nSource: /proc/meminfo MemTotal\n{source_scope_text}"
        if not source_is_remote
        else f"RAM (Total): {spec_ram}\nDetails are available on the selected remote source UI."
    )
    disk_detail_text = (
        f"Disk (Total / Free): {spec_disk}\nSource: statvfs('/')\n{source_scope_text}"
        if not source_is_remote
        else f"Disk (Total / Free): {spec_disk}\nDetails are available on the selected remote source UI."
    )
    uptime_detail_text = (
        f"Uptime: {spec_uptime}\nSource: /proc/uptime\n{source_scope_text}"
        if not source_is_remote
        else f"Uptime: {spec_uptime}\nDetails are available on the selected remote source UI."
    )
    package_panel_open = " open" if open_server_panel == "package" else ""
    package_panel_html = (
        "<div class='card server-action-panel" + package_panel_open + "' data-server-panel='package'>"
        "<h4>Unix runtime update</h4>"
        + package_update_btns
        + "<div class='button-row'>"
        + "<a class='btn-inline' href='" + html.escape(REPO_URL) + "' target='_blank' rel='noopener noreferrer'>Open GitHub repository</a>"
        + (" <form method='post' action='/settings/recheck-updates' style='display:inline;'><button type='submit' class='btn-inline btn-inline-muted'>Recheck for updates</button></form>" if not source_is_remote else "")
        + "</div>"
        + "<div class='muted'>Selected source: " + html.escape(selected_channel_label) + " | Current Unix runtime (" + html.escape(display_source_name) + "): <span title='" + html.escape(display_runtime_version) + "'>" + html.escape(display_runtime_version_short) + "</span> | Public Unix runtime (" + html.escape(public_label) + "): <span title='" + html.escape(latest_version or 'unknown') + "'>" + html.escape(latest_version_short) + "</span> | Status: " + html.escape(update_status_text) + "</div>"
        + "<pre>" + html.escape(update_curl_cmd) + "</pre>"
        + "<div class='muted'>Update: backs up, downloads latest, validates, replaces. On failure restores previous. Config and data preserved.</div>"
        + "<div class='muted'>" + html.escape(source_scope_text) + "</div></div>"
    )
    server_info_card_html = (
        "<div class='server-info-grid'>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='name'><span class='muted'>Name</span><strong>{html.escape(display_source_name)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='ip'><span class='muted'>IP</span><strong>{html.escape(display_server_ip)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='time'><span class='muted'>Time</span><strong>{html.escape(display_now_text)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='cpu'><span class='muted'>CPU</span><strong>{html.escape(spec_cpu)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='ram'><span class='muted'>RAM (Total)</span><strong>{html.escape(spec_ram)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='disk'><span class='muted'>Disk (Total / Free)</span><strong>{html.escape(spec_disk)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='uptime'><span class='muted'>Uptime</span><strong>{html.escape(spec_uptime)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='package'><span class='muted'>Unix Runtime Version</span><strong title='{html.escape(display_runtime_version)}'>{html.escape(display_runtime_version_short)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='login'><span class='muted'>Last Login Source IP</span><strong>{html.escape(display_last_login_ip)}</strong></button>"
        f"<button type='button' class='server-info-item server-info-action' data-server-action='login-time'><span class='muted'>Last Login Time</span><strong>{html.escape(display_last_login_at_text)}</strong></button>"
        "</div>"
        "<div class='server-action-panels'>"
        f"<div class='card server-action-panel' data-server-panel='name'><h4>Change server name</h4><form method='post' action='/settings/save-instance-name'><label>Instance Name</label><input name='instance_name' value='{html.escape(str(cfg.get('instance_name', '') or ''))}' placeholder='e.g. HQ-NAS'><div class='button-row'><button type='submit'>Save name</button></div></form></div>"
        f"<div class='card server-action-panel' data-server-panel='ip'><h4>System IP addresses</h4><div class='muted'>Current web UI bind: {html.escape(bind_scope_text)} on port {ui_bind_port}</div><pre>{html.escape(ip_list_text)}</pre></div>"
        f"<div class='card server-action-panel' data-server-panel='time'><h4>Time sync details</h4><pre>Current time: {html.escape(now_text)}\nLast peer sync: {html.escape(peer_last_sync_text)}\nNTP synced: {html.escape(ntp_info.get('synced', 'unknown'))}\nNTP service: {html.escape(ntp_info.get('service', 'unknown'))}\nNTP source: {html.escape(ntp_info.get('source', 'unknown'))}\n\n{html.escape(ntp_info.get('detail', ''))}</pre></div>"
        + f"<div class='card server-action-panel' data-server-panel='cpu'><h4>CPU details</h4><pre>{html.escape(cpu_detail_text)}</pre></div>"
        + f"<div class='card server-action-panel' data-server-panel='ram'><h4>RAM details</h4><pre>{html.escape(ram_detail_text)}</pre></div>"
        + f"<div class='card server-action-panel' data-server-panel='disk'><h4>Disk details</h4><pre>{html.escape(disk_detail_text)}</pre></div>"
        + f"<div class='card server-action-panel' data-server-panel='uptime'><h4>Uptime details</h4><pre>{html.escape(uptime_detail_text)}</pre></div>"
        + package_panel_html
        + f"<div class='card server-action-panel' data-server-panel='login'><h4>Recent login events (IP + state)</h4><pre>{html.escape(login_history_text)}</pre></div>"
        + f"<div class='card server-action-panel' data-server-panel='login-time'><h4>Recent login events (time + state)</h4><pre>{html.escape(login_history_text)}</pre></div>"
        + "</div>"
    )
    internet_probe = _get_cached_render_value(
        "internet_probe",
        ttl_sec=15,
        loader=lambda: _probe_internet_connectivity(internet_settings),
        default_value={"reachable": False, "detail": "Checking connectivity...", "checked_at": int(time.time())},
    )
    internet_ok = bool(internet_probe.get("reachable"))
    internet_detail = str(internet_probe.get("detail", "n/a") or "n/a")
    internet_required = peer_role != "standalone"
    internet_badge_cls = "st-up" if internet_ok else ("st-warning" if internet_required else "muted-badge")
    internet_badge_text = (
        "Online"
        if internet_ok
        else ("Offline" if internet_required else "Offline (standalone)")
    )
    internet_importance_text = (
        "If internet connectivity is unavailable, push to Kuma and sync to other servers may fail until the connection is restored. "
        "Local-only checks can still run in standalone mode."
        if internet_required
        else "Standalone mode supports local monitoring without internet. Internet is only required when remote push to Kuma, server sync, or update workflows are used."
    )
    overview_internet_card_html = f"""
      <div class="card">
        <h3>Internet Check</h3>
        <div class="server-info-grid">
          <div class="server-info-item">
            <span class="muted">Connectivity</span>
            <details style="width:100%;">
              <summary style="list-style:none;cursor:pointer;text-align:center;">
                <span class="badge {internet_badge_cls}">{html.escape(internet_badge_text)}</span>
              </summary>
              <div class="muted" style="margin-top:6px;">{html.escape(internet_detail)}</div>
            </details>
            <div class="muted" style="margin-top:6px;">Settings used: mode={html.escape(str(internet_settings.get('mode', 'tcp-connect')))} | portProfile={html.escape(str(internet_settings.get('target_port_text', 'dns:53')))} | timeout={int(internet_settings.get('timeout_ms', 1500))}ms | targets={html.escape(str(internet_settings.get('targets_text', '')))} | dnsServers={html.escape(str(internet_settings.get('dns_servers_text', '')))}</div>
          </div>
          <div class="server-info-item">
            <span class="muted">Why this matters</span>
            <strong>{html.escape(internet_importance_text)}</strong>
          </div>
        </div>
      </div>
    """
    overview_view_html = f"""
      {overview_internet_card_html}
      <div class="card">
        <h3>Current Server <span class="badge muted-badge">{html.escape(display_source_name)}</span></h3>
        <div class="muted" style="margin-bottom:8px;">{html.escape(source_scope_text)}</div>
        {server_info_card_html}
      </div>
      <div class="card">
        <h3>Monitoring Overview</h3>
        <div class="overview-grid">{overview_html}</div>
      </div>
      <div class="card">
        <h3>Logs & Diagnostics</h3>
        {log_diag_banner}
        {log_diag_stats}
        {log_diag_filter_form}
        <div class="log-diag-toolbar">
          <div class="log-diag-toolbar-left">{log_diag_clear_top}</div>
          <div class="button-row" style="margin:0;">
            <form method="get" action="/"><input type="hidden" name="view" value="overview"><input type="hidden" name="diag_view" value="{html.escape(diag_label)}"><input type="hidden" name="log_filter" value="{html.escape(filter_label)}"><input type="hidden" name="log_date" value="{html.escape(log_date_norm)}"><input type="hidden" name="log_time_scope" value="{html.escape(log_time_norm)}"><input type="hidden" name="log_time_from" value="{html.escape(log_time_from_norm)}"><input type="hidden" name="log_time_to" value="{html.escape(log_time_to_norm)}"><input type="hidden" name="source" value="{html.escape(source_label)}"><button type="submit">Refresh</button></form>
            {("<form method='get' action='/' style='margin-left:auto;'><input type='hidden' name='view' value='overview'><input type='hidden' name='diag_view' value='" + html.escape(diag_label) + "'><input type='hidden' name='log_filter' value='" + html.escape(filter_label) + "'><input type='hidden' name='log_date' value='" + html.escape(log_date_norm) + "'><input type='hidden' name='log_time_scope' value='" + html.escape(log_time_norm) + "'><input type='hidden' name='log_time_from' value='" + html.escape(log_time_from_norm) + "'><input type='hidden' name='log_time_to' value='" + html.escape(log_time_to_norm) + "'><input type='hidden' name='source' value='" + html.escape(source_label) + "'><input type='hidden' name='diagnose' value='1'><button type='submit'>Diagnose connection</button></form>") if source_label != "local" else ""}
          </div>
        </div>
        <pre id="log-diag-pre"{_log_pre_attrs}>{html.escape(log_text)}</pre>
      </div>
    """
    auto_rows = [
        ("Scheduler backend", str(automation_data.get("backend", "n/a") or "n/a")),
        ("Automatic checks (global)", "yes" if automation_data.get("global_enabled") else "no"),
        ("Global interval", f"{int(automation_data.get('global_interval_minutes', 60) or 60)} minute(s)"),
        ("Last scheduled run", str(automation_data.get("last_scheduled_run", "never") or "never")),
        ("Due now", str(automation_data.get("is_due", "n/a") or "n/a")),
        ("Scheduler process", str(automation_data.get("scheduler_process", "n/a") or "n/a")),
        ("Scheduler timer", str(automation_data.get("scheduler_timer", "n/a") or "n/a")),
        ("Timer next trigger", str(automation_data.get("timer_next", "n/a") or "n/a")),
        ("SMART elevated cache", ("active" if automation_data.get("smart_cache_active") else "inactive") + " | " + str(automation_data.get("smart_cache_message", "n/a") or "n/a")),
    ]
    automation_summary_html = (
        "<div class='server-info-grid'>"
        + "".join(
            f"<div class='server-info-item'><span class='muted'>{html.escape(label)}</span><strong>{html.escape(value)}</strong></div>"
            for label, value in auto_rows
        )
        + "</div>"
    )
    automation_mon_rows = automation_data.get("monitor_rows", []) if isinstance(automation_data.get("monitor_rows"), list) else []
    automation_state_rows: List[Tuple[str, str]] = [
        ("State source", str(automation_data.get("source", "n/a") or "n/a")),
        ("State file", str(automation_data.get("state_file", "n/a") or "n/a")),
        ("State note", str(automation_data.get("state_note", "n/a") or "n/a")),
        ("Monitor state entries", str(len(automation_mon_rows))),
    ]
    automation_state_html = (
        "<div class='server-info-grid' style='margin-top:10px;'>"
        + "".join(
            f"<div class='server-info-item'><span class='muted'>{html.escape(label)}</span><strong>{html.escape(value)}</strong></div>"
            for label, value in automation_state_rows
        )
        + "</div>"
    )
    setup_view_html = f"""
      {setup_card}
      <div class="card">
        <h3>Automation</h3>
        {"<div class='ok'>" + html.escape(automation_message) + "</div>" if automation_message else ""}
        {automation_summary_html}
        {automation_state_html}
        {"<details style='margin-top:10px;'><summary style='cursor:pointer;'>Automation command output</summary><pre>" + html.escape(automation_output) + "</pre></details>" if automation_output else ""}
        <details style="margin-top:10px;"><summary style="cursor:pointer;">Raw automation diagnostics (debug)</summary><pre>{html.escape(automation_status)}</pre></details>
        <div class="button-row">
          <form method="post" action="/run-scheduled-now"><button type="submit">Run scheduled now</button></form>
          <form method="post" action="/repair-automation"><button type="submit">Repair automation</button></form>
          <form method="post" action="/automation-status"><button type="submit">Refresh status</button></form>
        </div>
      </div>
      <div class="card">
        <h3>Monitor Setup</h3>
        <div class="muted">Create, edit, and delete monitors from this view.</div>
        <form method="post" action="/open-create" style="margin-top:10px;">
          <button type="submit">Create monitor</button>
        </form>
      </div>
      <div class="card"><h3>Local Monitors <span class="badge muted-badge">{len(local_cards)}</span></h3><div class="monitor-grid">{local_monitors_html}</div></div>
      {remote_monitors_html}
    """
    settings_view_html = f"""
      <div class="card" id="settings">
        <h3>Application Settings & Security</h3>
        {"<div class='ok'>" + html.escape(security_message) + "</div>" if security_message else ""}
        {"<pre>" + html.escape(security_output) + "</pre>" if security_output else ""}
        <form method="post" action="/settings/save-instance-name">
          <div class="field">
            <label>Instance Name</label>
            <input name="instance_name" value="{html.escape(str(cfg.get('instance_name', '') or ''))}" placeholder="e.g. HQ-NAS">
          </div>
          <div class="button-row"><button type="submit">Save instance name</button></div>
        </form>
        <form method="post" action="/settings/save-ui-bind">
          <div class="field">
            <label>Web UI bind interface/IP</label>
            <select name="ui_bind_host">{bind_options_html}</select>
          </div>
          <div class="field">
            <label>Web UI port</label>
            <input name="ui_bind_port" type="number" min="1" max="65535" value="{ui_bind_port}">
          </div>
          <div class="muted">Applies after restarting the Unix monitor UI/service.</div>
          <div class="button-row"><button type="submit">Save web UI binding</button></div>
        </form>
        <form method="post" action="/settings/save-internet-check">
          <div class="field">
            <label>Internet check mode</label>
            <select name="internet_check_mode">
              <option value="tcp-connect"{" selected" if str(internet_settings.get("mode", "tcp-connect")) == "tcp-connect" else ""}>TCP connect</option>
            </select>
          </div>
          <div class="field">
            <label>Target port profile</label>
            <select name="internet_check_port_profile">
              <option value="dns"{" selected" if str(internet_settings.get("port_profile", "dns")) == "dns" else ""}>DNS (53)</option>
              <option value="https"{" selected" if str(internet_settings.get("port_profile", "dns")) == "https" else ""}>HTTPS (443)</option>
              <option value="http"{" selected" if str(internet_settings.get("port_profile", "dns")) == "http" else ""}>HTTP (80)</option>
              <option value="custom"{" selected" if str(internet_settings.get("port_profile", "dns")) == "custom" else ""}>Custom port</option>
              <option value="from-target"{" selected" if str(internet_settings.get("port_profile", "dns")) == "from-target" else ""}>From target/URL</option>
            </select>
          </div>
          <div class="field">
            <label>Custom target port</label>
            <input name="internet_check_custom_port" type="number" min="1" max="65535" value="{int(internet_settings.get("custom_port", 53))}">
          </div>
          <div class="field">
            <label>Targets (comma separated FQDN/IP/URL; optional :port)</label>
            <input name="internet_check_targets" value="{html.escape(str(internet_settings.get("targets_text", "")))}" placeholder="https://kuma.example.com, one.one.one.one, 1.1.1.1:53">
          </div>
          <div class="field">
            <label>DNS servers to use (comma separated FQDN/IP, implicit port 53)</label>
            <input name="internet_check_dns_servers" value="{html.escape(str(internet_settings.get("dns_servers_text", "")))}" placeholder="1.1.1.1, dns.google">
          </div>
          <div class="field">
            <label>Internet check timeout per target (ms)</label>
            <input name="internet_check_timeout_ms" type="number" min="250" max="15000" value="{int(internet_settings.get("timeout_ms", 1500))}">
          </div>
          <div class="muted">Used by the Internet Check card and login connectivity probe API.</div>
          <div class="button-row"><button type="submit">Save internet check settings</button></div>
        </form>
        <form method="post" action="/auth/change-password">
          <input type="hidden" name="username" value="admin" autocomplete="username">
          <label>Change password</label>
          <div class="muted">Unused recovery codes: {recovery_unused}</div>
          <div class="row">
            <div class="input-with-action">
              <input id="security-current-password" name="current_password" type="password" autocomplete="current-password" placeholder="Current password" required>
              <button type="button" class="btn-icon toggle-password-btn" data-target="security-current-password" aria-label="Show password">Show</button>
            </div>
            <div class="input-with-action">
              <input id="security-new-password" name="new_password" type="password" autocomplete="new-password" minlength="10" placeholder="New password" required>
              <button type="button" class="btn-icon toggle-password-btn" data-target="security-new-password" aria-label="Show password">Show</button>
            </div>
          </div>
          <div class="input-with-action">
            <input id="security-confirm-password" name="new_password_confirm" type="password" autocomplete="new-password" minlength="10" placeholder="Confirm new password" required>
            <button type="button" class="btn-icon toggle-password-btn" data-target="security-confirm-password" aria-label="Show password">Show</button>
          </div>
          <div class="button-row"><button type="submit">Update password</button></div>
        </form>
        <div class="button-row">
          <form method="post" action="/auth/regenerate-recovery"><button type="submit">Regenerate recovery codes</button></form>
        </div>
        <form method="post" action="/auth/rotate-totp">
          <label>Rotate TOTP secret (verify with current 6-digit code)</label>
          <div class="row">
            <div><input name="token" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required></div>
            <div><button type="submit">Rotate TOTP + recovery codes</button></div>
          </div>
        </form>
      </div>
      {_render_peering_card(cfg, peering_message=peering_message, peering_diagnostics=peering_diagnostics)}
      <div class="card danger-zone-card">
        <h3>Danger Zone</h3>
        <div class="muted">Restart package services from UI (web UI + scheduler loop).</div>
        <div style="margin-bottom:18px;padding:12px 0;border-bottom:1px solid var(--border);">
          <label>Export</label>
          <div class="muted" style="margin-top:4px;">Full encrypted backup or public-only settings.</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px;">
            <form method="post" action="/auth/export-backup" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0;">
              <div class="input-with-action" style="min-width:200px;">
                <input name="backup_key" id="backup_key" type="password" placeholder="Encryption key (min 12 chars)" minlength="12" required>
                <button type="button" class="btn-icon toggle-password-btn" data-target="backup_key" aria-label="Show password">Show</button>
              </div>
              <button type="button" onclick="var k=document.getElementById('backup_key');k.value=Array.from(crypto.getRandomValues(new Uint8Array(24))).map(b=>b.toString(16).padStart(2,'0')).join('');k.type='text';k.select();">Generate key</button>
              <button type="submit">Export Encrypted Backup</button>
            </form>
          </div>
          <div style="margin-top:10px;">
            <a class="close-link" href="/auth/export">Export Backup</a>
          </div>
          {f"<div class='err' style='margin-top:10px;'>{html.escape(export_backup_error)}</div>" if export_backup_error else ""}
        </div>
        <form method="post" action="/auth/import" enctype="multipart/form-data">
          <label>Import settings backup</label>
          <div class="muted" style="margin-top:4px;">Encrypted backups require the decryption key. Paste JSON or choose file.</div>
          <label>Decryption key <span class="muted">(required for encrypted backups)</span></label>
          <div class="input-with-action">
            <input id="backup-import-key" name="backup_key" type="password" placeholder="Enter the key you saved during export" style="margin-top:4px;">
            <button type="button" class="btn-icon toggle-password-btn" data-target="backup-import-key" aria-label="Show password">Show</button>
          </div>
          <label>Backup JSON</label>
          <textarea name="import_payload" rows="5" style="width:100%;margin-top:6px;box-sizing:border-box;border:1px solid #30405b;border-radius:8px;background:#0f1726;color:#d7e2f0;padding:8px;" placeholder="Paste backup JSON or use file below"></textarea>
          <label>Or import from file</label>
          <input name="import_file" type="file" accept=".json,application/json">
          {f"<div class='err' style='margin-top:10px;'>{html.escape(import_backup_error)}</div>" if import_backup_error else ""}
          <div class="button-row">
            <button type="submit">Import settings</button>
          </div>
        </form>
        <div class="muted" style="margin-top:14px;">Admin account protected by password + mandatory TOTP 2FA.</div>
        <div class="danger-zone-factory" style="margin-top:16px;">
          <h3>Factory Settings</h3>
          <div class="button-row">
            <form method="post" action="/danger-restart" onsubmit="return confirm('Restart addon now? UI will disconnect briefly.');">
              <button type="submit" style="border-color:#ef4444;color:#ef4444;">Restart addon</button>
            </form>
            <form method="post" action="/danger-reset" onsubmit="return confirm('Reset configuration? All monitors and peering will be cleared. Auth will be kept.');">
              <button type="submit" style="border-color:#ef4444;color:#ef4444;">Reset configuration</button>
            </form>
          </div>
        </div>
      </div>
    """
    active_view_html = overview_view_html if ui_view == "overview" else (setup_view_html if ui_view == "setup" else settings_view_html)
    body_layout = nav_html + active_view_html + setup_popup_html

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <link rel="icon" type="image/png" href="{html.escape(BRAND_FAVICON_URL)}">
  <title>{(html.escape(browser_instance_name) + " - ") if browser_instance_name else ""}{html.escape(PRODUCT_NAME)} - Setup</title>
  <style>
{web_render.render_main_styles()}
  </style>
</head>
<body data-ui-view="{html.escape(ui_view)}" data-diag-view="{html.escape(diag_label)}" data-log-filter="{html.escape(filter_label)}" data-log-date="{html.escape(log_date_norm)}" data-log-time-scope="{html.escape(log_time_norm)}" data-log-time-from="{html.escape(log_time_from_norm)}" data-log-time-to="{html.escape(log_time_to_norm)}" data-log-source="{html.escape(source_label)}" data-peer-role="{html.escape(peer_role)}" data-show-monitor-target="{('1' if show_monitor_target_selector else '0')}" data-form-error="{('1' if error and modal_open else '0')}" data-monitor-modal-open="{('1' if modal_open else '0')}">
  <div class="container" data-source="{html.escape(source_label)}">
    <div class="card">
      <div class="brand-head">
        <div class="top-actions">
          <form method="post" action="/auth/logout"><button class="ghost-btn" type="submit">Log out</button></form>
        </div>
        <div class="brand-center">
          <a href="{html.escape(BRAND_URL)}" target="_blank" rel="noopener noreferrer"><img class="brand-logo" src="{html.escape(BRAND_LOGO_URL)}" alt="{html.escape(BRAND_NAME)} logo"></a>
          <div class="brand-summary">All-in-one Unix monitoring: SMART, storage, backup, ping, port, DNS, secure peering, and instant Uptime Kuma alerts.</div>
        </div>
      </div>
      {status_html}
    </div>
    {body_layout}
    <div class="modal-backdrop {'open' if modal_open else ''}" id="monitor-modal">
      <div class="modal">
        <h3>{html.escape(modal_title)}</h3>
        <form method="post" action="/save" novalidate id="monitor-form">
          <input type="hidden" name="edit_original_name" value="{html.escape(edit_original_name)}">
          {"<div id='target-peer-wrap'><label>Target Instance</label><select id='target_peer' name='target_peer' onchange='window._onTargetChange && window._onTargetChange()'>" + target_options + "</select><div id='agent-kuma-info' class='muted' style='margin-top:4px;display:none;border:1px solid rgba(47,128,237,.3);background:rgba(47,128,237,.08);border-radius:6px;padding:6px 10px;font-size:12px;'>Kuma Push URL will be added to this master. The master pushes status to Kuma on behalf of the agent.</div><div id='legacy-peer-warning' class='info-callout legacy-warning-callout' style='display:none;margin-top:10px;'><strong>Legacy agent warning</strong><p style='margin:8px 0 0;'>This target connected via legacy token peering. Creating a monitor pushes <code>/api/peer/create-monitor</code> to the agent callback URL. The agent must be reachable from this master.</p><label style='display:flex;gap:8px;align-items:flex-start;margin-top:10px;'><input type='checkbox' name='acknowledge_legacy' id='acknowledge_legacy' value='1' style='width:auto;margin-top:3px;'><span>I understand this is a legacy peer and want to create the monitor anyway.</span></label></div></div>" if show_monitor_target_selector else ""}
          <label>Monitor Name <span class="required-asterisk">*</span></label>
          <input id="name" name="name" value="{html.escape(current_name)}" required minlength="2" placeholder="e.g. smart-unix-check">
          <label>Kuma Push URL <span class="required-asterisk">*</span></label>
          <input name="kuma_url" value="{html.escape(current_url)}" required placeholder="https://kuma.example.com/api/push/TOKEN">
          <div class="row">
            <div>
              <label>Check Mode</label>
              <select id="check_mode" name="check_mode">
                <option value="smart" {"selected" if current_mode == "smart" else ""}>smart</option>
                <option value="storage" {"selected" if current_mode == "storage" else ""}>storage</option>
                <option value="ping" {"selected" if current_mode == "ping" else ""}>ping</option>
                <option value="port" {"selected" if current_mode == "port" else ""}>port</option>
                <option value="dns" {"selected" if current_mode == "dns" else ""}>dns</option>
                <option value="backup" {"selected" if current_mode == "backup" else ""}>backup</option>
                <option value="service" {"selected" if current_mode == "service" else ""}>service</option>
              </select>
            </div>
            <div>
              <label>Interval (minutes)</label>
              <input name="interval" type="number" min="1" max="1440" value="{current_interval}">
            </div>
          </div>
          <div id="probe-host-wrap" style="display:{modal_ph_display};">
            <label>Probe Host (for ping/port) <span class="required-asterisk">*</span></label>
            <input name="probe_host" value="{html.escape(current_probe_host)}" placeholder="example.com or 192.168.1.10">
          </div>
          <div id="probe-port-wrap" style="display:{modal_pp_display};">
            <label>Probe Port (for port mode) <span class="required-asterisk">*</span></label>
            <input name="probe_port" type="number" min="1" max="65535" value="{html.escape(current_probe_port)}" placeholder="443">
          </div>
          <div id="dns-name-wrap" style="display:{modal_dns_display};">
            <label>DNS Name (for dns mode) <span class="required-asterisk">*</span></label>
            <input name="dns_name" value="{html.escape(current_dns_name)}" placeholder="example.com">
          </div>
          <div id="dns-server-wrap" style="display:{modal_dns_display};">
            <label>DNS Server (optional)</label>
            <input name="dns_server" value="{html.escape(current_dns_server)}" placeholder="8.8.8.8">
          </div>
          <div id="service-names-wrap" style="display:{modal_service_display};">
            <label>Service names (for service mode)</label>
            <input name="service_names" value="{html.escape(current_service_names)}" placeholder="nginx, sshd, docker">
          </div>
          <div id="service-filter-wrap" style="display:{modal_service_display};">
            <label>Service description filter (optional)</label>
            <input name="service_description_filter" value="{html.escape(current_service_desc_filter)}" placeholder="proxy, database">
          </div>
          <div class="modal-toggle-row">
            <label class="toggle-label"><input type="checkbox" name="cron_enabled" value="1" {checked_cron}> <span>Enable automatic checks</span></label>
          </div>
          <div id="monitor-form-error" class="modal-form-error" role="alert"></div>
          <div class="button-row">
            <button type="submit">{'Update monitor' if edit_original_name else 'Create monitor'}</button>
            <button type="button" class="close-link" onclick="document.getElementById('monitor-modal').classList.remove('open')">Cancel</button>
          </div>
        </form>
      </div>
    </div>
    <script>
      (function () {{
        window._syncMonitorModalFields = function () {{
          var modal = document.getElementById("monitor-modal");
          if (!modal) return;
          var modeEl = modal.querySelector("#check_mode");
          var nameEl = modal.querySelector("#name");
          var phw = modal.querySelector("#probe-host-wrap");
          var ppw = modal.querySelector("#probe-port-wrap");
          var dnw = modal.querySelector("#dns-name-wrap");
          var dsw = modal.querySelector("#dns-server-wrap");
          var snw = modal.querySelector("#service-names-wrap");
          var sfw = modal.querySelector("#service-filter-wrap");
          if (!modeEl) return;
          var m = (modeEl.value || "smart").toLowerCase();
          var showHost = (m === "ping" || m === "port");
          var showPort = (m === "port");
          var showDns = (m === "dns");
          var showService = (m === "service");
          if (phw) {{ phw.style.display = showHost ? "block" : "none"; var inp = phw.querySelector("input"); if (inp) inp.disabled = !showHost; }}
          if (ppw) {{ ppw.style.display = showPort ? "block" : "none"; var inp = ppw.querySelector("input"); if (inp) inp.disabled = !showPort; }}
          if (dnw) {{ dnw.style.display = showDns ? "block" : "none"; var inp = dnw.querySelector("input"); if (inp) inp.disabled = !showDns; }}
          if (dsw) {{ dsw.style.display = showDns ? "block" : "none"; var inp = dsw.querySelector("input"); if (inp) inp.disabled = !showDns; }}
          if (snw) {{ snw.style.display = showService ? "block" : "none"; var inp = snw.querySelector("input"); if (inp) inp.disabled = !showService; }}
          if (sfw) {{ sfw.style.display = showService ? "block" : "none"; var inp = sfw.querySelector("input"); if (inp) inp.disabled = !showService; }}
          if (nameEl) {{
            var cur = (nameEl.value || "").trim().toLowerCase();
            var autoPattern = /^(smart|storage|ping|port|dns|backup|service)-unix-check$/;
            if (!cur || autoPattern.test(cur) || cur === "unix-main") {{
              nameEl.value = (modeEl.value || "smart") + "-unix-check";
            }}
          }}
        }};
        document.addEventListener("change", function (ev) {{
          var el = ev.target;
          if (!el || el.id !== "check_mode") return;
          if (!el.closest || !el.closest("#monitor-modal")) return;
          window._syncMonitorModalFields();
        }}, false);
        window._syncMonitorModalFields();
        var monForm = document.getElementById("monitor-form");
        if (monForm) {{
          function _ensureCtxFields(form) {{
            var b = document.body;
            if (!b || !form) return;
            function hid(n, v) {{
              var inp = form.querySelector("input[name='" + n + "']");
              if (!inp) {{
                inp = document.createElement("input");
                inp.type = "hidden";
                inp.name = n;
                form.appendChild(inp);
              }}
              inp.value = String(v || "");
            }}
            hid("ui_view", b.getAttribute("data-ui-view") || "overview");
            hid("diag_view", b.getAttribute("data-diag-view") || "logs");
            hid("log_filter", b.getAttribute("data-log-filter") || "all");
            hid("log_date", b.getAttribute("data-log-date") || "all");
            hid("log_time_scope", b.getAttribute("data-log-time-scope") || "all");
            hid("log_time_from", b.getAttribute("data-log-time-from") || "");
            hid("log_time_to", b.getAttribute("data-log-time-to") || "");
            var src = b.getAttribute("data-log-source") || "local";
            hid("source", src);
            hid("log_source", src);
          }}
          function _showModalErr(msg) {{
            var err = document.getElementById("monitor-form-error");
            if (err) {{ err.textContent = msg || ""; err.classList.toggle("show", !!msg); }}
          }}
          monForm.addEventListener("submit", function (e) {{
            _ensureCtxFields(monForm);
            _showModalErr("");
            var kuma = (monForm.querySelector("input[name='kuma_url']") || {{}}).value || "";
            if (!String(kuma).trim()) {{ e.preventDefault(); e.stopImmediatePropagation(); _showModalErr("Kuma Push URL is required."); return; }}
            var nm = ((monForm.querySelector("#name") || {{}}).value || "").trim();
            if (nm.length < 2) {{ e.preventDefault(); e.stopImmediatePropagation(); _showModalErr("Monitor name must be at least 2 characters."); return; }}
            var mode = ((monForm.querySelector("#check_mode") || {{}}).value || "smart").toLowerCase();
            var probeHost = ((monForm.querySelector("input[name='probe_host']") || {{}}).value || "").trim();
            var probePort = parseInt((monForm.querySelector("input[name='probe_port']") || {{}}).value || "0", 10) || 0;
            var dnsName = ((monForm.querySelector("input[name='dns_name']") || {{}}).value || "").trim();
            var serviceNames = ((monForm.querySelector("input[name='service_names']") || {{}}).value || "").trim();
            var serviceFilter = ((monForm.querySelector("input[name='service_description_filter']") || {{}}).value || "").trim();
            if (mode === "ping" && !probeHost) {{ e.preventDefault(); e.stopImmediatePropagation(); _showModalErr("Ping mode requires a probe host."); return; }}
            if (mode === "port") {{
              if (!probeHost) {{ e.preventDefault(); e.stopImmediatePropagation(); _showModalErr("Port mode requires a probe host."); return; }}
              if (probePort < 1 || probePort > 65535) {{ e.preventDefault(); e.stopImmediatePropagation(); _showModalErr("Port mode requires a valid TCP port (1-65535)."); return; }}
            }}
            if (mode === "dns" && !dnsName) {{ e.preventDefault(); e.stopImmediatePropagation(); _showModalErr("DNS mode requires a DNS name/domain."); return; }}
            if (mode === "service" && !serviceNames && !serviceFilter) {{ e.preventDefault(); e.stopImmediatePropagation(); _showModalErr("Service mode requires service names and/or a description filter."); return; }}
            var urlCheck = kuma;
            if (!/^https?:\\/\\//i.test(urlCheck)) urlCheck = "https://" + urlCheck;
            try {{
              var pu = new URL(urlCheck);
              if (!pu.hostname) {{ e.preventDefault(); e.stopImmediatePropagation(); _showModalErr("Kuma Push URL must include a hostname."); return; }}
              if (!/^\\/api\\/push\\/[A-Za-z0-9_-]+$/.test(pu.pathname)) {{
                e.preventDefault(); e.stopImmediatePropagation();
                _showModalErr("Kuma Push URL path must be /api/push/TOKEN (e.g. https://kuma.example.com/api/push/abc123).");
                return;
              }}
            }} catch (uerr) {{
              e.preventDefault(); e.stopImmediatePropagation();
              _showModalErr("Kuma Push URL is invalid.");
            }}
          }}, true);
        }}
        window.monitorAction = function (url, name, btn) {{
          var impl = window.__monitorActionImpl;
          if (typeof impl === "function") return impl(url, name, btn);
          alert("The page did not finish loading scripts. Refresh the page and try again.");
        }};
      }})();
    </script>
    <div class="modal-backdrop" id="add-agent-modal">
      <div class="modal">
        <h3>Add Agent</h3>
        <div class="muted" style="margin-bottom:10px;">Manually register an agent instance. The agent will appear once it pushes data, or you can set its URL to enable master-initiated sync.</div>
        <form method="post" action="/peer/add-agent">
          <label>Agent Name</label>
          <input name="agent_name" placeholder="e.g. Branch-NAS" required>
          <label>Agent Instance ID <span class="muted">(from the agent's peering card)</span></label>
          <input name="agent_id" placeholder="e.g. a1b2c3d4-..." required>
          <label>Agent host <span class="muted">(optional, hostname or IP; port 8787 if omitted)</span></label>
          <input name="agent_url" placeholder="Hostname or IP (port if not 8787)">
          <div class="button-row">
            <button type="submit">Add agent</button>
            <button type="button" class="close-link" onclick="document.getElementById('add-agent-modal').classList.remove('open')">Cancel</button>
          </div>
        </form>
      </div>
    </div>
    <div class="modal-backdrop gallery-modal" id="gallery-modal">
      <div class="modal">
        <h3>Setup Screenshots</h3>
        <div class="gallery-stage"><img id="gallery-image" src="" alt="Setup screenshot"></div>
        <div class="gallery-caption" id="gallery-caption"></div>
        <div class="gallery-controls">
          <button type="button" id="gallery-prev">Previous</button>
          <button type="button" id="gallery-next">Next</button>
          <button type="button" id="gallery-close">Close</button>
        </div>
      </div>
    </div>
    <div class="modal-backdrop" id="update-modal">
      <div class="modal">
        <h3>Package update</h3>
        <div id="update-modal-content"></div>
      </div>
    </div>
    <div class="modal-backdrop" id="agent-update-modal">
      <div class="modal">
        <h3>Agent update</h3>
        <div id="agent-update-modal-content"></div>
      </div>
    </div>
    <div class="card footer-note">
      {html.escape(BRAND_COPYRIGHT)} | Author: {html.escape(BRAND_AUTHOR)} |
      <a href="{html.escape(BRAND_URL)}" target="_blank" rel="noopener noreferrer">EasySystems GmbH</a>
    </div>
    <script>
      (function () {{
        document.addEventListener("click", function (ev) {{
          var btn = ev && ev.target && ev.target.closest ? ev.target.closest(".toggle-password-btn[data-target]") : null;
          if (!btn) return;
          var targetId = btn.getAttribute("data-target") || "";
          var input = targetId ? document.getElementById(targetId) : null;
          if (!input) return;
          var show = input.type === "password";
          input.type = show ? "text" : "password";
          btn.textContent = show ? "Hide" : "Show";
          btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
        }});

        function copyTextToClipboard(text) {{
          if (navigator.clipboard && window.isSecureContext) {{
            return navigator.clipboard.writeText(text);
          }}
          return new Promise(function (resolve, reject) {{
            try {{
              var ta = document.createElement("textarea");
              ta.value = text;
              ta.setAttribute("readonly", "");
              ta.style.position = "fixed";
              ta.style.opacity = "0";
              ta.style.left = "-9999px";
              document.body.appendChild(ta);
              ta.focus();
              ta.select();
              var ok = document.execCommand("copy");
              document.body.removeChild(ta);
              if (ok) resolve();
              else reject(new Error("copy command failed"));
            }} catch (e) {{
              reject(e);
            }}
          }});
        }}
        document.addEventListener("click", function (ev) {{
          var copyBtn = ev && ev.target && ev.target.closest ? ev.target.closest(".copy-peer-instance-id-btn") : null;
          if (!copyBtn) return;
          var idEl = document.getElementById("peer-instance-id");
          if (!idEl) return;
          var idText = (idEl.textContent || "").trim();
          if (!idText) return;
          copyTextToClipboard(idText).then(function () {{
            var label = copyBtn.textContent;
            copyBtn.textContent = "Copied!";
            setTimeout(function () {{ copyBtn.textContent = label; }}, 1500);
          }}).catch(function () {{
            alert("Failed to copy. Please copy manually.");
          }});
        }});

        var bodyMeta = document.body || null;
        var uiView = bodyMeta ? (bodyMeta.getAttribute("data-ui-view") || "overview") : "overview";
        var diagView = bodyMeta ? (bodyMeta.getAttribute("data-diag-view") || "logs") : "logs";
        var logFilter = bodyMeta ? (bodyMeta.getAttribute("data-log-filter") || "all") : "all";
        var logDate = bodyMeta ? (bodyMeta.getAttribute("data-log-date") || "all") : "all";
        var logTimeScope = bodyMeta ? (bodyMeta.getAttribute("data-log-time-scope") || "all") : "all";
        var logTimeFrom = bodyMeta ? (bodyMeta.getAttribute("data-log-time-from") || "") : "";
        var logTimeTo = bodyMeta ? (bodyMeta.getAttribute("data-log-time-to") || "") : "";
        var logSource = bodyMeta ? (bodyMeta.getAttribute("data-log-source") || "local") : "local";
        var qs = new URLSearchParams();
        qs.set("view", uiView);
        qs.set("diag_view", diagView);
        qs.set("log_filter", logFilter);
        qs.set("log_date", logDate);
        qs.set("log_time_scope", logTimeScope);
        qs.set("log_time_from", logTimeFrom);
        qs.set("log_time_to", logTimeTo);
        qs.set("source", logSource);
        qs.set("log_source", logSource);
        var canonicalPath = "/?" + qs.toString();
        try {{
          if (window.location.pathname !== "/" || window.location.search !== ("?" + qs.toString())) {{
            window.history.replaceState(null, "", canonicalPath);
          }}
        }} catch (e) {{
          /* ignore history API edge-cases */
        }}
        try {{
          var restoreY = sessionStorage.getItem("synmon_scroll_y");
          if (restoreY !== null) {{
            sessionStorage.removeItem("synmon_scroll_y");
            var yVal = parseInt(restoreY, 10);
            if (!isNaN(yVal) && yVal > 0) window.scrollTo(0, yVal);
          }}
        }} catch (e) {{
          /* ignore session storage errors */
        }}
        // Async fetch agent logs (avoids blocking page load when agent is unreachable)
        var logPre = document.getElementById("log-diag-pre");
        if (logPre && logPre.getAttribute("data-agent-fetch") === "1") {{
          var peerId = logPre.getAttribute("data-peer-id") || "";
          var view = logPre.getAttribute("data-view") || "logs";
          var lf = logPre.getAttribute("data-log-filter") || "all";
          var ld = logPre.getAttribute("data-log-date") || "all";
          var lt = logPre.getAttribute("data-log-time-scope") || "all";
          var ltf = logPre.getAttribute("data-log-time-from") || "";
          var ltt = logPre.getAttribute("data-log-time-to") || "";
          if (peerId) {{
            var url = "/api/agent-diag?peer_id=" + encodeURIComponent(peerId) + "&view=" + encodeURIComponent(view) + "&log_filter=" + encodeURIComponent(lf) + "&log_date=" + encodeURIComponent(ld) + "&log_time_scope=" + encodeURIComponent(lt) + "&log_time_from=" + encodeURIComponent(ltf) + "&log_time_to=" + encodeURIComponent(ltt);
            fetch(url, {{ credentials: "same-origin" }}).then(function(r) {{ return r.json(); }}).then(function(data) {{
              if (data && data.text !== undefined) logPre.textContent = data.text;
              try {{ logPre.scrollTop = logPre.scrollHeight; }} catch (e) {{}}
            }}).catch(function(err) {{
              logPre.textContent = "Failed to load agent logs: " + (err && err.message ? err.message : String(err));
            }});
          }}
        }} else if (logPre) {{
          try {{ logPre.scrollTop = logPre.scrollHeight; }} catch (e) {{}}
        }}
        var logDiagForm = document.querySelector("form.log-diag-filter-form");
        function updateDiagFilterAvailability() {{
          if (!logDiagForm) return;
          var diagSelect = logDiagForm.querySelector("#diag-view-sel");
          if (!diagSelect) return;
          var selectedView = String(diagSelect.value || "logs").toLowerCase();
          var viewCapabilities = {{
            logs: {{ event: true, time: true, date: true, exact: true, word: true }},
            task: {{ event: false, time: false, date: false, exact: false, word: false }},
            cache: {{ event: false, time: false, date: false, exact: false, word: false }},
            config: {{ event: false, time: false, date: false, exact: false, word: false }},
            history: {{ event: false, time: false, date: false, exact: false, word: false }},
            paths: {{ event: false, time: false, date: false, exact: false, word: false }},
            system: {{ event: false, time: false, date: false, exact: false, word: false }}
          }};
          var caps = viewCapabilities[selectedView] || {{ event: false, time: false, date: false, exact: false, word: false }};
          var eventSelect = logDiagForm.querySelector("#log-filter-sel");
          var timeSelect = logDiagForm.querySelector("#log-time-sel");
          var dateInput = logDiagForm.querySelector("#log-date-inp");
          var timeFromInput = logDiagForm.querySelector("#log-time-from");
          var timeToInput = logDiagForm.querySelector("#log-time-to");
          var wordInput = logDiagForm.querySelector("#log-word-inp");
          var advancedDetails = logDiagForm.querySelector("details[data-advanced-filtering='1']");
          var advancedSummary = logDiagForm.querySelector("summary[data-advanced-summary='1']");
          var filterNote = logDiagForm.querySelector("[data-log-filter-note='1']");
          var viewLabel = selectedView.charAt(0).toUpperCase() + selectedView.slice(1);
          var hasWordControl = !!wordInput;
          var labels = {{
            event: "Event / channel",
            time: "Time window",
            date: "Date (calendar)",
            exact: "Time from/to",
            word: "Contains word"
          }};

          function setSelectAvailability(sel, enabled) {{
            if (!sel) return;
            if (!sel.dataset.logsOptionsHtml) sel.dataset.logsOptionsHtml = sel.innerHTML;
            if (enabled) {{
              if (sel.dataset.logsOptionsHtml) sel.innerHTML = sel.dataset.logsOptionsHtml;
            }} else {{
              sel.innerHTML = "<option value='all' selected>Not available for " + viewLabel + "</option>";
            }}
            sel.disabled = !enabled;
          }}

          setSelectAvailability(eventSelect, !!caps.event);
          setSelectAvailability(timeSelect, !!caps.time);
          if (dateInput) dateInput.disabled = !caps.date;
          if (timeFromInput) timeFromInput.disabled = !caps.exact;
          if (timeToInput) timeToInput.disabled = !caps.exact;
          if (wordInput) wordInput.disabled = !caps.word;

          var hasAdvancedAvailable = !!(caps.date || caps.exact || (hasWordControl && caps.word));
          if (advancedDetails && !hasAdvancedAvailable) advancedDetails.removeAttribute("open");
          if (advancedSummary) {{
            if (hasAdvancedAvailable) {{
              advancedSummary.textContent = "Advanced filtering";
            }} else {{
              advancedSummary.textContent = "Advanced filtering (not available for " + viewLabel + ")";
            }}
          }}

          if (filterNote) {{
            var controls = ["event", "time", "date", "exact"];
            if (hasWordControl) controls.push("word");
            var supported = controls.filter(function (k) {{ return !!caps[k]; }}).map(function (k) {{ return labels[k]; }});
            var unsupported = controls.filter(function (k) {{ return !caps[k]; }}).map(function (k) {{ return labels[k]; }});
            if (unsupported.length === 0) {{
              filterNote.textContent = "All filters are available for " + viewLabel + " view.";
            }} else if (supported.length === 0) {{
              filterNote.textContent = viewLabel + " view does not support filters. Switch to Logs view to use filtering.";
            }} else {{
              filterNote.textContent = "Available for " + viewLabel + ": " + supported.join(", ") + ". Unavailable: " + unsupported.join(", ") + ".";
            }}
          }}
        }}
        if (logDiagForm) {{
          var diagSelect = logDiagForm.querySelector("#diag-view-sel");
          if (diagSelect) {{
            diagSelect.addEventListener("change", function () {{
              updateDiagFilterAvailability();
            }});
          }}
          updateDiagFilterAvailability();
        }}
        function ensureUiViewField(form) {{
          if (!form || !form.querySelector) return;
          function ensureHiddenField(name, value) {{
            var input = form.querySelector("input[name='" + name + "']");
            if (!input) {{
              input = document.createElement("input");
              input.type = "hidden";
              input.name = name;
              form.appendChild(input);
            }}
            input.value = String(value || "");
          }}
          ensureHiddenField("ui_view", uiView);
          ensureHiddenField("diag_view", diagView);
          ensureHiddenField("log_filter", logFilter);
          ensureHiddenField("log_date", logDate);
          ensureHiddenField("log_time_scope", logTimeScope);
          ensureHiddenField("log_time_from", logTimeFrom);
          ensureHiddenField("log_time_to", logTimeTo);
          ensureHiddenField("source", logSource);
          ensureHiddenField("log_source", logSource);
        }}
        var postForms = document.querySelectorAll("form[method='post'], form[method='POST']");
        postForms.forEach(function(form) {{ ensureUiViewField(form); }});
        document.addEventListener("submit", function (ev) {{
          var form = ev && ev.target ? ev.target : null;
          if (!form || !form.getAttribute) return;
          if ((form.getAttribute("action") || "") !== "/auth/import") return;
          if ((form.getAttribute("method") || "").toLowerCase() !== "post") return;
          var ta = form.querySelector("textarea[name='import_payload']");
          var keyIn = form.querySelector("input[name='backup_key']");
          var raw = (ta && ta.value ? ta.value : "").trim();
          var key = (keyIn && keyIn.value ? keyIn.value : "").trim();
          if (!raw) return;
          try {{
            var j = JSON.parse(raw);
            if (j && typeof j.enc === "string" && j.enc.length > 0 && !key) {{
              ev.preventDefault();
              ev.stopImmediatePropagation();
              alert("Encrypted backup requires the decryption key.");
            }}
          }} catch (e) {{}}
        }}, true);
        var SERVER_PANEL_STATE_KEY = "unix_monitor_open_server_panel";
        function setOpenServerPanelKey(key) {{
          try {{
            if (key) localStorage.setItem(SERVER_PANEL_STATE_KEY, key);
            else localStorage.removeItem(SERVER_PANEL_STATE_KEY);
          }} catch (e) {{}}
        }}
        function getOpenServerPanelKey() {{
          try {{
            return localStorage.getItem(SERVER_PANEL_STATE_KEY) || "";
          }} catch (e) {{
            return "";
          }}
        }}
        function restoreOpenServerPanel() {{
          // Default UX: keep server action panel collapsed on fresh page load.
          setOpenServerPanelKey("");
          document.querySelectorAll(".server-action-panel.open").forEach(function(p) {{
            p.classList.remove("open");
          }});
        }}
        restoreOpenServerPanel();
        // Ensure source chips (Local, agent names) navigate reliably when clicked (handles subpath + edge cases)
        document.addEventListener("click", function(ev) {{
          var a = ev.target && ev.target.closest ? ev.target.closest("a.chip[href*='source=']") : null;
          if (a && a.getAttribute("href")) {{
            ev.preventDefault();
            window.location.href = a.getAttribute("href");
          }}
        }}, true);
        document.addEventListener("click", function(ev) {{
          var b = ev.target && ev.target.closest ? ev.target.closest(".server-info-action[data-server-action]") : null;
          if (!b) return;
          ev.preventDefault();
          ev.stopPropagation();
          var key = b.getAttribute("data-server-action");
          var panel = document.querySelector(".server-action-panel[data-server-panel='" + key + "']");
          if (!panel) return;
          var alreadyOpen = panel.classList.contains("open");
          document.querySelectorAll(".server-action-panel.open").forEach(function(p) {{ p.classList.remove("open"); }});
          if (alreadyOpen) {{
            setOpenServerPanelKey("");
          }} else {{
            panel.classList.add("open");
            setOpenServerPanelKey(key);
            panel.scrollIntoView({{ behavior: "smooth", block: "nearest" }});
          }}
        }});
        document.addEventListener("submit", function(ev) {{
          var form = ev && ev.target && ev.target.closest ? ev.target.closest("form") : null;
          if (!form) return;
          var method = (form.getAttribute("method") || "").toLowerCase();
          if (method && method !== "post") return;
          function ensureSubmitHidden(name, value) {{
            var input = form.querySelector("input[type='hidden'][name='" + name + "']");
            if (!input) {{
              input = document.createElement("input");
              input.type = "hidden";
              input.name = name;
              form.appendChild(input);
            }}
            input.value = String(value || "");
          }}
          var panel = form.closest ? form.closest(".server-action-panel[data-server-panel]") : null;
          if (panel) {{
            var panelKey = panel.getAttribute("data-server-panel") || "";
            setOpenServerPanelKey(panelKey);
            ensureSubmitHidden("server_panel", panelKey);
            return;
          }}
          var openPanel = document.querySelector(".server-action-panel.open[data-server-panel]");
          if (openPanel) {{
            var openPanelKey = openPanel.getAttribute("data-server-panel") || "";
            setOpenServerPanelKey(openPanelKey);
            ensureSubmitHidden("server_panel", openPanelKey);
          }}
        }}, true);
        // Intercept POST forms: fetch and update page without reload (except auth, danger, exports)
        document.addEventListener("submit", async function(ev) {{
          var form = ev && ev.target ? ev.target : null;
          if (!form || !form.getAttribute) return;
          if ((form.getAttribute("method") || "get").toLowerCase() !== "post") return;
          if (form.id === "monitor-form") return;
          var act = (form.getAttribute("action") || "") + "";
          var skip = /\\/(auth\\/(logout|login|setup|verify-2fa|recovery|import|export))|\\/danger-(restart|reset)|\\/self-rollback/.test(act) || (form.enctype || "").toLowerCase().indexOf("multipart") >= 0;
          if (skip) return;
          ev.preventDefault();
          ev.stopImmediatePropagation();
          ensureUiViewField(form);
          var submitBtn = form.querySelector("button[type='submit']");
          if (submitBtn) {{ submitBtn.disabled = true; submitBtn.textContent = (submitBtn.textContent || "").replace(/…$/, "") + "…"; }}
          var isSelfUpdate = (act || "").indexOf("/self-update") >= 0;
          if (isSelfUpdate) {{
            var m = document.getElementById("update-modal");
            var mContent = document.getElementById("update-modal-content");
            if (m && mContent) {{
              m.classList.add("open");
              mContent.innerHTML = "<p>Updating…</p><p class='muted'>Downloading latest version, validating, replacing.</p>";
            }}
          }}
          try {{
            var fd = new FormData(form);
            var params = new URLSearchParams();
            fd.forEach(function(v, k) {{ params.append(k, v); }});
            var r = await fetch(act, {{
              method: "POST",
              headers: {{ "Content-Type": "application/x-www-form-urlencoded" }},
              body: params.toString()
            }});
            var txt = await r.text();
            if (r.redirected && (r.url || "").indexOf("auth") >= 0) {{ location.href = r.url; return; }}
            if (isSelfUpdate) {{
              var doc = new DOMParser().parseFromString(txt, "text/html");
              var errEl = doc.querySelector(".err");
              var okEl = doc.querySelector(".ok");
              var preEl = doc.querySelector("pre");
              var m = document.getElementById("update-modal");
              var mContent = document.getElementById("update-modal-content");
              if (m && mContent) {{
                var status = "Update complete.";
                if (errEl) status = (errEl.textContent || "").trim();
                else if (okEl) status = (okEl.textContent || "").trim();
                var output = preEl ? (preEl.textContent || "").trim() : "";
                var kind = errEl ? "err" : "ok";
                var preBlock = "";
                if (output) preBlock = "<pre>" + escapeHtml(output) + "</pre>";
                mContent.innerHTML = "<p class='" + kind + "'>" + escapeHtml(status) + "</p>" + preBlock + "<p class='muted'>Reloading page in 5 seconds…</p>";
                setTimeout(function() {{ location.reload(); }}, 5000);
              }} else {{
                _updatePageFromResponse(txt);
              }}
            }} else {{
              _updatePageFromResponse(txt);
            }}
            var addAgentModal = document.getElementById("add-agent-modal");
            if (addAgentModal) addAgentModal.classList.remove("open");
          }} catch (e) {{
            if (isSelfUpdate) {{
              var m = document.getElementById("update-modal");
              var mContent = document.getElementById("update-modal-content");
              if (m && mContent) {{
                var overviewPath = "/?view=overview";
                mContent.innerHTML = "<p class='err'>Update failed: " + escapeHtml(String(e)) + "</p>"
                  + "<p style='margin-top:12px;'><button type='button' class='close-link' onclick='window.location.href=\\\"" + overviewPath + "\\\"'>Return to overview</button></p>";
              }} else {{
                location.reload();
              }}
            }} else {{
              location.reload();
            }}
          }} finally {{
            if (submitBtn) {{ submitBtn.disabled = false; submitBtn.textContent = (submitBtn.textContent || "").replace("…", ""); }}
          }}
        }}, true);
        document.addEventListener("submit", function(ev) {{
          var form = ev && ev.target ? ev.target : null;
          if (!form || !form.getAttribute) return;
          var method = (form.getAttribute("method") || "get").toLowerCase();
          if (method === "post") {{
            ensureUiViewField(form);
            try {{
              sessionStorage.setItem("synmon_scroll_y", String(Math.max(0, Math.round(window.scrollY || 0))));
            }} catch (e) {{}}
            return;
          }}
          if (method === "get") {{
            var cls = form.classList;
            var isDiagNav = (cls && cls.contains("log-diag-filter-form")) || (form.closest && form.closest(".log-diag-toolbar"));
            if (!isDiagNav) return;
            try {{
              sessionStorage.setItem("synmon_scroll_y", String(Math.max(0, Math.round(window.scrollY || 0))));
            }} catch (e) {{}}
          }}
        }}, true);
        document.addEventListener("click", async function(ev) {{
          var btn = ev && ev.target ? ev.target.closest(".agent-update-btn") : null;
          if (!btn) return;
          ev.preventDefault();
          var peerId = btn.getAttribute("data-peer-id") || "";
          var peerName = btn.getAttribute("data-peer-name") || peerId;
          if (!peerId) return;
          var modal = document.getElementById("agent-update-modal");
          var mContent = document.getElementById("agent-update-modal-content");
          if (!modal || !mContent) return;
          modal.classList.add("open");
          mContent.innerHTML = "<p>Starting update on " + escapeHtml(peerName) + "…</p>";
          btn.disabled = true;
          try {{
            var r = await fetch("/agent-update", {{
              method: "POST",
              headers: {{ "Content-Type": "application/x-www-form-urlencoded" }},
              body: "peer_id=" + encodeURIComponent(peerId)
            }});
            var rawText = "";
            try {{ rawText = await r.text(); }} catch (e) {{ rawText = String(e); }}
            var data = null;
            try {{ data = rawText ? JSON.parse(rawText) : null; }} catch (e) {{}}
            var errMsg = (data && data.error) ? String(data.error) : "Failed to start update";
            var diagLines = ["HTTP " + r.status, "Error: " + errMsg];
            if (data && data.diagnostic) diagLines.push("", data.diagnostic);
            else if (rawText && rawText.length > 0) {{
              var respSnippet = rawText.length < 400 ? rawText.replace(/\\n/g, " ").trim() : rawText.substring(0, 300) + "...";
              diagLines.push("", "Response: " + respSnippet);
            }}
            var diagBlock = "<div style='margin-top:10px;padding:10px;background:#0b1321;border:1px solid #283852;border-radius:8px;font-size:11px;font-family:monospace;white-space:pre-wrap;word-break:break-all;max-height:180px;overflow:auto;'>" + escapeHtml(diagLines.join("\\n")) + "</div>";
            if (!r.ok || !data || data.error) {{
              mContent.innerHTML = "<p class='err'>" + escapeHtml(errMsg) + "</p>" + diagBlock;
              mContent.innerHTML += "<p style='margin-top:12px;'><button type='button' class='close-link' onclick=\\"document.getElementById('agent-update-modal').classList.remove('open')\\">Close</button></p>";
              btn.disabled = false;
              return;
            }}
            var sessionId = data.session_id;
            if (!sessionId) {{
              mContent.innerHTML = "<p class='err'>No session ID returned</p>";
              mContent.innerHTML += "<p><button type='button' class='close-link' onclick=\\"document.getElementById('agent-update-modal').classList.remove('open')\\">Close</button></p>";
              btn.disabled = false;
              return;
            }}
            var pollInterval = setInterval(async function() {{
              try {{
                var sr = await fetch("/api/agent-update-status?peer_id=" + encodeURIComponent(peerId) + "&session_id=" + encodeURIComponent(sessionId), {{ credentials: "same-origin" }});
                var sraw = "";
                try {{ sraw = await sr.text(); }} catch (e) {{ sraw = String(e); }}
                var sdata = sr.ok && sraw ? (function() {{ try {{ return JSON.parse(sraw); }} catch(e) {{ return {{}}; }} }})() : {{}};
                if (sdata.error && !sdata.log) {{
                  var sdiagLines = ["HTTP " + sr.status, "Error: " + (sdata.error || "unknown")];
                  if (sraw && sraw.length > 0) {{
                    var srespSnippet = sraw.length < 400 ? sraw.replace(/\\n/g, " ").trim() : sraw.substring(0, 300) + "...";
                    sdiagLines.push("", "Response: " + srespSnippet);
                  }}
                  var sdiagBlock = "<div style='margin-top:10px;padding:10px;background:#0b1321;border:1px solid #283852;border-radius:8px;font-size:11px;font-family:monospace;white-space:pre-wrap;word-break:break-all;max-height:180px;overflow:auto;'>" + escapeHtml(sdiagLines.join("\\n")) + "</div>";
                  mContent.innerHTML = "<p class='err'>" + escapeHtml(sdata.error) + "</p>" + sdiagBlock;
                  mContent.innerHTML += "<p style='margin-top:12px;'><button type='button' class='close-link' onclick=\\"document.getElementById('agent-update-modal').classList.remove('open')\\">Close</button></p>";
                  clearInterval(pollInterval);
                  btn.disabled = false;
                  return;
                }}
                var log = sdata.log || [];
                var stage = sdata.stage || "running";
                var err = sdata.error || "";
                var html = "<p><strong>" + escapeHtml(peerName) + "</strong> – " + escapeHtml(stage) + "</p>";
                if (log.length) html += "<pre style='max-height:200px;overflow:auto;font-size:11px;'>" + escapeHtml(log.join("\\n")) + "</pre>";
                if (err) html += "<p class='err'>" + escapeHtml(err) + "</p>";
                mContent.innerHTML = html;
                if (stage === "done" || stage === "failed") {{
                  clearInterval(pollInterval);
                  html += (stage === "done" ? "<p class='ok'>Update complete. Agent may restart.</p>" : "<p class='err'>Update failed.</p>");
                  html += "<p><button type='button' class='close-link' onclick=\\"document.getElementById('agent-update-modal').classList.remove('open')\\">Close</button></p>";
                  mContent.innerHTML = html;
                  btn.disabled = false;
                  if (stage === "done") setTimeout(function() {{ refreshLive && refreshLive(); }}, 3000);
                }}
              }} catch (e) {{
                mContent.innerHTML += "<p class='err'>Poll error: " + escapeHtml(String(e)) + "</p>";
              }}
            }}, 600);
          }} catch (e) {{
            mContent.innerHTML = "<p class='err'>" + escapeHtml(String(e)) + "</p>";
            mContent.innerHTML += "<p><button type='button' class='close-link' onclick=\\"document.getElementById('agent-update-modal').classList.remove('open')\\">Close</button></p>";
            btn.disabled = false;
          }}
        }}, true);

      var zoomWraps = document.querySelectorAll(".zoom-wrap");
      zoomWraps.forEach(function (wrap) {{
        var img = wrap.querySelector(".zoom-img");
        if (!img) return;
        wrap.addEventListener("mousemove", function (ev) {{
          var r = wrap.getBoundingClientRect();
          var x = Math.max(0, Math.min(1, (ev.clientX - r.left) / Math.max(1, r.width)));
          var y = Math.max(0, Math.min(1, (ev.clientY - r.top) / Math.max(1, r.height)));
          img.style.setProperty("--ox", (x * 100).toFixed(2) + "%");
          img.style.setProperty("--oy", (y * 100).toFixed(2) + "%");
        }});
        wrap.addEventListener("mouseleave", function () {{
          img.style.setProperty("--ox", "50%");
          img.style.setProperty("--oy", "50%");
        }});
      }});

      var galleryImages = {gallery_urls_json};
      var galleryModal = document.getElementById("gallery-modal");
      var galleryImage = document.getElementById("gallery-image");
      var galleryCaption = document.getElementById("gallery-caption");
      var galleryPrev = document.getElementById("gallery-prev");
      var galleryNext = document.getElementById("gallery-next");
      var galleryClose = document.getElementById("gallery-close");
      var galleryIndex = 0;

      function renderGallery() {{
        if (!galleryImages.length || !galleryImage) return;
        galleryImage.src = galleryImages[galleryIndex];
        galleryCaption.textContent = "Image " + (galleryIndex + 1) + " of " + galleryImages.length;
      }}
      function openGallery(index) {{
        if (!galleryImages.length || !galleryModal) return;
        galleryIndex = Math.max(0, Math.min(galleryImages.length - 1, index));
        renderGallery();
        galleryModal.classList.add("open");
      }}
      function closeGallery() {{
        if (!galleryModal) return;
        galleryModal.classList.remove("open");
      }}
      function stepGallery(delta) {{
        if (!galleryImages.length) return;
        galleryIndex = (galleryIndex + delta + galleryImages.length) % galleryImages.length;
        renderGallery();
      }}

      document.querySelectorAll(".screenshot-link[data-gallery-index]").forEach(function (a) {{
        a.addEventListener("click", function (ev) {{
          ev.preventDefault();
          var idx = parseInt(a.getAttribute("data-gallery-index") || "0", 10);
          openGallery(isNaN(idx) ? 0 : idx);
        }});
      }});
      if (galleryPrev) galleryPrev.addEventListener("click", function () {{ stepGallery(-1); }});
      if (galleryNext) galleryNext.addEventListener("click", function () {{ stepGallery(1); }});
      if (galleryClose) galleryClose.addEventListener("click", closeGallery);
      if (galleryModal) {{
        galleryModal.addEventListener("click", function (ev) {{
          if (ev.target === galleryModal) closeGallery();
        }});
      }}
      document.addEventListener("keydown", function (ev) {{
        if (!galleryModal || !galleryModal.classList.contains("open")) return;
        if (ev.key === "Escape") closeGallery();
        if (ev.key === "ArrowLeft") stepGallery(-1);
        if (ev.key === "ArrowRight") stepGallery(1);
      }});

      function statusClass(status) {{
        if (status === "up") return "st-up";
        if (status === "warning") return "st-warning";
        if (status === "down") return "st-down";
        return "st-unknown";
      }}
      function statusLabel(status) {{
        if (status === "up" || status === "warning" || status === "down") return status.toUpperCase();
        return "UNKNOWN";
      }}
      function tsText(ts) {{
        if (!ts) return "never";
        var d = new Date(ts * 1000);
        function p2(n) {{ n = String(n); return n.length < 2 ? "0" + n : n; }}
        return d.getFullYear() + "-" + p2(d.getMonth() + 1) + "-" + p2(d.getDate())
          + " " + p2(d.getHours()) + ":" + p2(d.getMinutes()) + ":" + p2(d.getSeconds());
      }}
      function escapeHtml(s) {{
        return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
      }}
      function pulse(el) {{
        if (!el) return;
        el.classList.remove("pulse-hit");
        void el.offsetWidth;
        el.classList.add("pulse-hit");
      }}
      async function monitorAction(url, name, btn) {{
        var orig = btn.textContent;
        btn.disabled = true;
        btn.textContent = orig + "…";
        try {{
          var curSource = (document.body && document.body.getAttribute("data-log-source")) || "local";
          var body = "monitor_name=" + encodeURIComponent(name) + "&source=" + encodeURIComponent(curSource) + "&log_source=" + encodeURIComponent(curSource);
          var r = await fetch(url, {{
            method: "POST",
            headers: {{ "Content-Type": "application/x-www-form-urlencoded" }},
            body: body
          }});
          if (url === "/delete-monitor" && r.ok) {{
            var card = btn.closest(".monitor-card");
            if (card) card.remove();
          }}
          if (url === "/edit-monitor" && r.ok) {{
            _injectModal(await r.text());
            return;
          }}
          await refreshLive();
        }} catch (e) {{
          /* ignore */
        }} finally {{
          btn.disabled = false;
          btn.textContent = orig;
        }}
      }}

      window.__monitorActionImpl = monitorAction;

      function _updatePageFromResponse(txt) {{
        var doc = new DOMParser().parseFromString(txt, "text/html");
        var newContainer = doc.querySelector(".container");
        var newBody = doc.querySelector("body");
        var curContainer = document.querySelector(".container");
        if (newContainer && curContainer) {{
          curContainer.innerHTML = newContainer.innerHTML;
          var inContainerModal = curContainer.querySelector("#monitor-modal");
          if (inContainerModal) {{
            document.querySelectorAll("#monitor-modal").forEach(function (m) {{
              if (m !== inContainerModal) m.remove();
            }});
          }}
          if (newBody) {{
            var wantMonitorOpen = newBody.getAttribute("data-monitor-modal-open") === "1";
            var mm = curContainer.querySelector("#monitor-modal");
            if (mm) {{
              if (wantMonitorOpen) mm.classList.add("open");
              else mm.classList.remove("open");
            }}
            ["data-ui-view", "data-diag-view", "data-log-filter", "data-log-date", "data-log-time-scope", "data-log-time-from", "data-log-time-to", "data-log-source", "data-peer-role", "data-show-monitor-target", "data-form-error", "data-monitor-modal-open"].forEach(function(attr) {{
              var v = newBody.getAttribute(attr);
              if (v !== null) document.body.setAttribute(attr, v);
            }});
          }}
          try {{
            var path = window.location.pathname || "/";
            var curQs = new URLSearchParams(window.location.search || "");
            uiView = (newBody && newBody.getAttribute("data-ui-view")) || uiView || curQs.get("view") || "overview";
            diagView = (newBody && newBody.getAttribute("data-diag-view")) || diagView || curQs.get("diag_view") || "logs";
            logFilter = (newBody && newBody.getAttribute("data-log-filter")) || logFilter || curQs.get("log_filter") || "all";
            logDate = (newBody && newBody.getAttribute("data-log-date")) || logDate || curQs.get("log_date") || "all";
            logTimeScope = (newBody && newBody.getAttribute("data-log-time-scope")) || logTimeScope || curQs.get("log_time_scope") || "all";
            logTimeFrom = (newBody && newBody.getAttribute("data-log-time-from")) || logTimeFrom || curQs.get("log_time_from") || "";
            logTimeTo = (newBody && newBody.getAttribute("data-log-time-to")) || logTimeTo || curQs.get("log_time_to") || "";
            logSource = (newBody && newBody.getAttribute("data-log-source")) || logSource || curQs.get("source") || curQs.get("log_source") || "local";
            var nextQs = new URLSearchParams();
            nextQs.set("view", uiView);
            nextQs.set("diag_view", diagView);
            nextQs.set("log_filter", logFilter);
            nextQs.set("log_date", logDate);
            nextQs.set("log_time_scope", logTimeScope);
            nextQs.set("log_time_from", logTimeFrom);
            nextQs.set("log_time_to", logTimeTo);
            nextQs.set("source", logSource);
            nextQs.set("log_source", logSource);
            history.replaceState({{}}, "", path + "?" + nextQs.toString());
          }} catch (e) {{}}
          _hookModalSave();
          try {{
            restoreOpenServerPanel();
          }} catch (e) {{}}
          if (typeof refreshLive === "function") refreshLive();
          try {{
            var lp = document.getElementById("log-diag-pre");
            if (lp) lp.scrollTop = lp.scrollHeight;
          }} catch (e) {{}}
        }}
      }}

      function _injectModal(html) {{
        var doc = new DOMParser().parseFromString(html, "text/html");
        var modal = doc.querySelector(".modal-backdrop.open");
        if (modal) {{
          var existing = document.getElementById("monitor-modal");
          if (existing) existing.remove();
          document.body.insertAdjacentHTML("beforeend", modal.outerHTML);
          _hookModalSave();
        }}
      }}

      function _hookModalSave() {{
        var modal = document.getElementById("monitor-modal");
        if (!modal) return;
        if (typeof window._syncMonitorModalFields === "function") window._syncMonitorModalFields();
        var targetEl = modal.querySelector("#target_peer");
        var agentInfo = modal.querySelector("#agent-kuma-info");
        function _onTarget() {{
          if (!targetEl || !agentInfo) return;
          var isRemote = !!(targetEl.value && targetEl.value !== "local");
          agentInfo.style.display = isRemote ? "block" : "none";
          var legacyWarn = modal.querySelector("#legacy-peer-warning");
          var legacyAck = modal.querySelector("#acknowledge_legacy");
          if (legacyWarn) {{
            var opt = targetEl.options[targetEl.selectedIndex];
            var isLegacy = isRemote && opt && opt.getAttribute("data-legacy-peer") === "1";
            legacyWarn.style.display = isLegacy ? "block" : "none";
            if (legacyAck && !isLegacy) legacyAck.checked = false;
          }}
        }}
        if (targetEl) {{
          targetEl.addEventListener("change", _onTarget);
          _onTarget();
        }}
        var form = modal.querySelector("form");
        if (!form) return;
        var errEl = form.querySelector("#monitor-form-error");
        function showFormError(msg) {{
          if (errEl) {{ errEl.textContent = msg || ""; errEl.classList.toggle("show", !!msg); }}
        }}
        form.addEventListener("submit", function (e) {{
          showFormError("");
          var name = (form.querySelector("#name") || {{}}).value.trim();
          var kumaUrl = (form.querySelector("input[name='kuma_url']") || {{}}).value.trim();
          var mode = (form.querySelector("#check_mode") || {{}}).value || "smart";
          var probeHost = (form.querySelector("input[name='probe_host']") || {{}}).value.trim();
          var probePort = parseInt((form.querySelector("input[name='probe_port']") || {{}}).value, 10) || 0;
          var dnsName = (form.querySelector("input[name='dns_name']") || {{}}).value.trim();
          var serviceNames = (form.querySelector("input[name='service_names']") || {{}}).value.trim();
          var serviceFilter = (form.querySelector("input[name='service_description_filter']") || {{}}).value.trim();
          if (!name || name.length < 2) {{
            e.preventDefault();
            showFormError("Monitor name is required (min 2 characters).");
            return;
          }}
          if (!kumaUrl) {{
            e.preventDefault();
            showFormError("Kuma Push URL is required.");
            return;
          }}
          var urlCheck = kumaUrl;
          if (!urlCheck.match(/^https?:\\/\\//i)) urlCheck = "https://" + urlCheck;
          try {{
            var pu = new URL(urlCheck);
            if (!pu.hostname) {{ e.preventDefault(); showFormError("Kuma Push URL must include a hostname."); return; }}
            if (!/^\\/api\\/push\\/[A-Za-z0-9_-]+$/.test(pu.pathname)) {{
              e.preventDefault();
              showFormError("Kuma Push URL path must be /api/push/TOKEN (e.g. https://kuma.example.com/api/push/abc123).");
              return;
            }}
          }} catch (uerr) {{
            e.preventDefault();
            showFormError("Kuma Push URL is invalid.");
            return;
          }}
          if (mode === "ping" && !probeHost) {{
            e.preventDefault();
            showFormError("Ping mode requires a probe host.");
            return;
          }}
          if (mode === "port") {{
            if (!probeHost) {{ e.preventDefault(); showFormError("Port mode requires a probe host."); return; }}
            if (probePort < 1 || probePort > 65535) {{ e.preventDefault(); showFormError("Port mode requires a valid TCP port (1-65535)."); return; }}
          }}
          if (mode === "dns" && !dnsName) {{
            e.preventDefault();
            showFormError("DNS mode requires a DNS name/domain.");
            return;
          }}
          if (mode === "service" && !serviceNames && !serviceFilter) {{
            e.preventDefault();
            showFormError("Service mode requires service names and/or a description filter.");
            return;
          }}
          var targetPeerEl = form.querySelector("#target_peer");
          var legacyWarn = form.querySelector("#legacy-peer-warning");
          var legacyAck = form.querySelector("#acknowledge_legacy");
          if (targetPeerEl && legacyWarn && targetPeerEl.value && targetPeerEl.value !== "local") {{
            var opt = targetPeerEl.options[targetPeerEl.selectedIndex];
            var isLegacy = opt && opt.getAttribute("data-legacy-peer") === "1";
            if (isLegacy && legacyAck && !legacyAck.checked) {{
              e.preventDefault();
              showFormError("Confirm the legacy agent warning before creating a monitor for this peer.");
              legacyWarn.style.display = "block";
              return;
            }}
          }}
          ensureUiViewField(form);
        }});
      }}
      _hookModalSave();
      window._onTargetChange = function() {{
        var sel = document.getElementById("target_peer");
        var info = document.getElementById("agent-kuma-info");
        var legacyWarn = document.getElementById("legacy-peer-warning");
        var legacyAck = document.getElementById("acknowledge_legacy");
        if (!sel) return;
        var isRemote = !!(sel.value && sel.value !== "local");
        if (info) info.style.display = isRemote ? "block" : "none";
        if (legacyWarn) {{
          var opt = sel.options[sel.selectedIndex];
          var isLegacy = isRemote && opt && opt.getAttribute("data-legacy-peer") === "1";
          legacyWarn.style.display = isLegacy ? "block" : "none";
          if (legacyAck && !isLegacy) legacyAck.checked = false;
        }}
      }};
      if (document.getElementById("target_peer")) window._onTargetChange();

      window._openAddAgent = function(btn) {{
        var m = document.getElementById("add-agent-modal");
        if (m) m.classList.add("open");
      }};
      (function() {{
        var agentModal = document.getElementById("add-agent-modal");
        if (!agentModal) return;
        var form = agentModal.querySelector("form");
        if (!form) return;
        form.addEventListener("submit", async function(e) {{
          e.preventDefault();
          var submitBtn = form.querySelector("button[type='submit']");
          if (submitBtn) {{ submitBtn.disabled = true; submitBtn.textContent += "\u2026"; }}
          try {{
            var fd = new FormData(form);
            var params = new URLSearchParams();
            fd.forEach(function(v, k) {{ params.append(k, v); }});
            var r = await fetch(form.action, {{
              method: "POST",
              headers: {{ "Content-Type": "application/x-www-form-urlencoded" }},
              body: params.toString()
            }});
            if (r.ok) {{
              agentModal.classList.remove("open");
              form.reset();
              await refreshLive();
              location.reload();
            }}
          }} catch(ex) {{}}
          finally {{
            if (submitBtn) {{ submitBtn.disabled = false; submitBtn.textContent = submitBtn.textContent.replace("\u2026",""); }}
          }}
        }});
      }})();

      var prevChannelTs = {{}};
      var prevMonitorTs = {{}};
      var selectedHighlight = {json.dumps(highlight_channel or "")};

      function applyLiveSnapshot(data) {{
        if (!data || !data.channels || !data.monitors) return;
        Object.keys(data.channels || {{}}).forEach(function (channel) {{
          var card = document.querySelector(".overview-card[data-channel='" + channel + "']");
          var ch = data.channels[channel];
          if (!card || !ch) return;
          var gauge = card.querySelector("[data-role='gauge']");
          var gv = card.querySelector("[data-role='gauge-value']");
          var gs = card.querySelector("[data-role='gauge-sub']");
          var gl = card.querySelector("[data-role='channel-last']");
          var dots = card.querySelector("[data-role='channel-dots']");
          if (gauge) {{
            gauge.style.setProperty("--pct", String(ch.pct || 0));
            gauge.className = "gauge " + statusClass(ch.status);
          }}
          if (gv) gv.textContent = statusLabel(ch.status);
          if (gs) gs.textContent = String(ch.pct || 0) + "%";
          if (gl) gl.textContent = "Last update: " + tsText(ch.ts || 0);
          if (dots) {{
            var hs = Array.isArray(ch.history_statuses) ? ch.history_statuses : [];
            if (hs.length) {{
              dots.innerHTML = hs.map(function (s) {{ return "<span class='dot " + statusClass(s) + "'></span>"; }}).join("");
            }} else {{
              dots.innerHTML = "<span class='muted'>no history</span>";
            }}
          }}
          if ((prevChannelTs[channel] || 0) !== (ch.ts || 0) && ch.ts) {{
            pulse(gauge || card);
          }}
          prevChannelTs[channel] = ch.ts || 0;
        }});

        var cards = document.querySelectorAll(".monitor-card[data-monitor]");
        var map = {{}};
        cards.forEach(function (c) {{ map[c.getAttribute("data-monitor")] = c; }});
        cards.forEach(function (c) {{
          var mode = (c.getAttribute("data-mode") || "").toLowerCase();
          var hit = false;
          if (selectedHighlight === "smart") hit = (mode === "smart");
          if (selectedHighlight === "storage") hit = (mode === "storage");
          if (selectedHighlight === "ping") hit = (mode === "ping");
          if (selectedHighlight === "port") hit = (mode === "port");
          if (selectedHighlight === "dns") hit = (mode === "dns");
          if (selectedHighlight) c.classList.toggle("hl-monitor", hit);
        }});
        data.monitors.forEach(function (m) {{
          var card = map[m.name];
          if (!card) return;
          var badge = card.querySelector(".monitor-status-badge");
          var primary = card.querySelector("[data-role='monitor-primary']");
          var live = card.querySelector("[data-role='monitor-live']");
          if (badge) {{
            badge.className = "badge " + statusClass(m.status);
            badge.textContent = statusLabel(m.status);
          }}
          if (primary) {{
            var ping = m.ping_ms === null || m.ping_ms === undefined ? "n/a" : String(m.ping_ms);
            var originTag = (m.origin && m.origin !== "local") ? " | Origin: " + m.origin : "";
            primary.textContent = "Mode: " + (m.mode || "smart") + " | Last ping: " + ping + " ms | Last run: " + tsText(m.ts || 0) + originTag;
          }}
          if (live) {{
            var htmlParts = [];
            if (m.banner) htmlParts.push("<div class='" + (m.level === "err" ? "err" : "ok") + "'>" + escapeHtml(m.banner) + "</div>");
            if (m.output) htmlParts.push("<pre>" + escapeHtml(m.output) + "</pre>");
            live.innerHTML = htmlParts.join("");
          }}
          if ((prevMonitorTs[m.name] || 0) !== (m.ts || 0) && m.ts) {{
            pulse(card);
          }}
          prevMonitorTs[m.name] = m.ts || 0;
        }});

        var peerPanel = document.getElementById("peer-live-panel");
        if (peerPanel && data.peers) {{
          var onlineCount = 0, offlineCount = 0, remoteMon = 0;
          data.peers.forEach(function(p) {{
            if (p.status === "online") onlineCount++; else offlineCount++;
            remoteMon += (p.monitor_count || 0);
          }});
          var ob = document.getElementById("peer-online-badge");
          var fb = document.getElementById("peer-offline-badge");
          var rc = document.getElementById("peer-remote-count");
          if (ob) ob.textContent = onlineCount + " online";
          if (fb) {{ fb.textContent = offlineCount + " offline"; fb.style.display = offlineCount ? "" : "none"; }}
          if (rc) rc.textContent = "Remote monitors: " + remoteMon;
          if (data.peers.length) {{
            var defPort = 8787;
            function peerUrlForInput(u) {{
              if (!u) return "";
              var m = u.match(/^(.+):(\\d+)$/);
              if (m && parseInt(m[2], 10) === defPort) return m[1];
              return u;
            }}
            var ph = data.peers.map(function (p) {{
              var cls = p.status === "online" ? "ok" : "err";
              var latTxt = p.latency_ms ? p.latency_ms + " ms" : "-";
              var seenTxt = tsText(p.last_seen || 0);
              var pUrl = p.url || "";
              var openUrl = p.open_url || (pUrl && pUrl.indexOf("://") >= 0 ? pUrl : (pUrl ? "http://" + pUrl : ""));
              var pUrlDisplay = peerUrlForInput(pUrl);
              var pid = escapeHtml(p.instance_id || "");
              var pbs = "padding:6px 12px;font-size:12px;border-radius:8px;font-weight:600;white-space:nowrap;cursor:pointer;line-height:1.2;border:1px solid #36517a;background:transparent;color:#c8dbf8;";
              var updateSupported = !!p.update_supported;
              var sourcePlatform = String(p.source_platform || "");
              var unknownUpdateAllowed = !!p.unknown_update_allowed;
              var updateBlockReason = p.update_block_reason || "Unknown platform; update blocked by default.";
              var updateBtn;
              if (updateSupported) {{
                updateBtn = "<button type='button' class='agent-update-btn' data-peer-id='" + escapeHtml(p.instance_id || "") + "' data-peer-name='" + escapeHtml(p.instance_name || p.instance_id || "?") + "' style='" + pbs + "'>Update</button>";
              }} else {{
                updateBtn = "<button type='button' class='agent-update-btn' disabled title='" + escapeHtml(updateBlockReason) + "' style='" + pbs + "opacity:.55;cursor:not-allowed;'>Update</button>";
              }}
              var updateOptionsCell = "";
              if (sourcePlatform === "unknown") {{
                var toggleValue = unknownUpdateAllowed ? "0" : "1";
                var toggleLabel = unknownUpdateAllowed ? "Block unknown updates" : "Allow unknown updates";
                var hintExplain = "Remote updates are only offered when this master recognizes the agent as a supported Unix install. If the agent does not advertise a known platform, updates stay disabled until you allow them here.";
                var ap = String(p.agent_platform || "").trim();
                var af = String(p.agent_platform_family || "").trim();
                var detParts = [];
                if (ap) detParts.push("OS: " + ap);
                if (af) detParts.push("family: " + af);
                var det = detParts.length ? detParts.join(" · ") : "Not reported yet (wait for the next agent sync).";
                var hintHtml = "<div class='peer-update-options-hint'>"
                  + "<p class='muted' style='font-size:11px;line-height:1.4;margin:0 0 8px 0;'>" + escapeHtml(hintExplain) + "</p>"
                  + "<p style='font-size:11px;line-height:1.4;margin:0 0 10px 0;color:#c8dbf8;'>" + escapeHtml(det) + "</p>"
                  + "</div>";
                updateOptionsCell = "<details class='peer-update-policy-menu'>"
                  + "<summary class='peer-update-policy-summary' title='Unclear platform: open for details and to allow or block remote updates.' style='" + pbs + "'>update-options</summary>"
                  + "<div class='peer-update-policy-panel'>" + hintHtml
                  + "<form method='post' action='/peer/update-unknown-policy' style='margin:0;'>"
                  + "<input type='hidden' name='peer_id' value='" + escapeHtml(p.instance_id || "") + "'>"
                  + "<input type='hidden' name='allow_unknown_update' value='" + toggleValue + "'>"
                  + "<button type='submit' class='peer-update-policy-submit' style='" + pbs + "width:100%;text-align:left;display:block;'>" + toggleLabel + "</button>"
                  + "</form></div></details>";
              }} else {{
                updateOptionsCell = "<span class='peer-action-placeholder peer-action-col-update-options' aria-hidden='true'></span>";
              }}
              var openCell;
              if (openUrl) {{
                openCell = "<a href='" + escapeHtml(openUrl) + "' target='_blank' rel='noopener noreferrer' style='" + pbs + "text-decoration:none;display:inline-block;text-align:center;'>Open</a>";
              }} else {{
                openCell = "<span class='peer-action-placeholder peer-action-col-open' aria-hidden='true'></span>";
              }}
              var removeBtn = "<form method='post' action='/peer/remove' style='margin:0;'>"
                + "<input type='hidden' name='peer_id' value='" + pid + "'>"
                + "<button type='submit' onclick='return confirm(&#39;Remove this agent?&#39;)' "
                + "style='" + pbs + "border-color:#ef4444;color:#ef4444;'>Remove</button></form>";
              var versionBadge = p.version ? "<span class='badge muted-badge' data-role='peer-version'>v" + escapeHtml(p.version) + "</span>" : "";
              var syncedTime = seenTxt.split(" ").pop();
              var syncedBadge = "<span class='badge muted-badge' data-role='peer-synced'>Synced: " + syncedTime + "</span>";
              return "<div class='peer-row' data-peer-id='" + pid + "' data-peer-url='" + escapeHtml(pUrl) + "' "
                + "style='border:1px solid rgba(42,61,90,.35);border-radius:8px;background:rgba(15,23,38,.6);padding:10px 12px;margin-bottom:8px;'>"
                + "<div style='display:flex;align-items:center;gap:10px;flex-wrap:wrap;'>"
                + "<span class='badge " + cls + "' style='min-width:56px;text-align:center;'>" + escapeHtml(p.status) + "</span>"
                + "<strong style='flex:1;font-size:13px;'>" + escapeHtml(p.instance_name || p.instance_id || "?") + "</strong>"
                + syncedBadge
                + "<span class='badge muted-badge' data-role='peer-monitors'>" + (p.monitor_count || 0) + " monitors</span>"
                + versionBadge
                + "</div>"
                + "<div style='display:flex;align-items:center;gap:8px;margin-top:6px;'>"
                + "<span class='muted' style='font-size:11px;'>Last seen: " + syncedTime + " (" + latTxt + ")</span>"
                + "<span class='muted' style='font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>" + escapeHtml(pUrl || "no URL") + "</span>"
                + "</div>"
                + "<div class='peer-actions-row'>"
                + "<form method='post' action='/peer/update-peer-url' style='margin:0;display:flex;gap:4px;align-items:center;min-width:0;'>"
                + "<input type='hidden' name='peer_id' value='" + pid + "'>"
                + "<input name='peer_url' value='" + escapeHtml(pUrlDisplay) + "' placeholder='Hostname or host:port' style='flex:1;padding:4px 6px;font-size:11px;'>"
                + "<button type='submit' style='" + pbs + "'>Set URL</button>"
                + "</form>"
                + "<form method='post' action='/peer/sync-one' style='margin:0;'>"
                + "<input type='hidden' name='peer_id' value='" + pid + "'>"
                + "<button type='submit' style='" + pbs + "'>Sync</button>"
                + "</form>"
                + updateBtn
                + updateOptionsCell
                + openCell
                + removeBtn
                + "</div></div>";
            }}).join("");
            peerPanel.innerHTML = ph;
          }}
        }}
      }}

      async function refreshLive() {{
        try {{
          var srcEl = document.querySelector(".container[data-source]");
          var activeSource = (srcEl && srcEl.getAttribute("data-source")) ? srcEl.getAttribute("data-source") : "local";
          var r = await fetch("/status-json?source=" + encodeURIComponent(activeSource), {{ cache: "no-store" }});
          if (!r.ok) return;
          var data = await r.json();
          applyLiveSnapshot(data);
        }} catch (e) {{
          /* ignore transient fetch errors */
        }}
      }}
      refreshLive();
      setInterval(refreshLive, 15000);
      }})();
    </script>
  </div>
</body>
</html>
"""

def _normalize_internet_check_mode(raw: Any) -> str:
    mode = str(raw or "tcp-connect").strip().lower()
    if mode in ("tcp", "tcp-connect"):
        return "tcp-connect"
    return "tcp-connect"


def _normalize_internet_check_timeout_ms(raw: Any) -> int:
    try:
        parsed = int(raw)
    except Exception:
        parsed = 1500
    return max(250, min(15000, parsed))


def _normalize_internet_check_port_profile(raw: Any) -> str:
    profile = str(raw or "dns").strip().lower()
    if profile in INTERNET_CHECK_PORT_PROFILES:
        return profile
    return "dns"


def _normalize_internet_check_custom_port(raw: Any) -> int:
    try:
        parsed = int(raw)
    except Exception:
        parsed = 53
    return max(1, min(65535, parsed))


def _resolve_port_from_profile(
    profile: str,
    custom_port: int,
    explicit_port: Optional[int],
    scheme_hint: str,
) -> int:
    if profile == "custom":
        return custom_port
    if profile == "http":
        return 80
    if profile == "https":
        return 443
    if profile == "dns":
        return 53
    # from-target
    if explicit_port and 1 <= explicit_port <= 65535:
        return explicit_port
    if scheme_hint == "https":
        return 443
    if scheme_hint == "http":
        return 80
    return 53


def _parse_target_token(token: str) -> Optional[Tuple[str, Optional[int], str]]:
    part = str(token or "").strip()
    if not part:
        return None
    scheme_hint = ""
    explicit_port: Optional[int] = None
    host = ""
    try:
        if "://" in part:
            parsed = urlparse(part)
            host = str(parsed.hostname or "").strip().lower().rstrip(".")
            scheme_hint = str(parsed.scheme or "").strip().lower()
            explicit_port = parsed.port
        else:
            cleaned = part.split("/", 1)[0].strip()
            if cleaned.startswith("["):
                m = re.match(r"^\[([0-9a-fA-F:]+)\](?::(\d+))?$", cleaned)
                if m:
                    host = str(m.group(1) or "").strip().lower()
                    if m.group(2):
                        explicit_port = int(m.group(2))
                else:
                    host = cleaned.strip("[]").strip().lower()
            elif cleaned.count(":") == 1:
                left, right = cleaned.rsplit(":", 1)
                if right.isdigit():
                    host = left.strip().lower().rstrip(".")
                    explicit_port = int(right)
                else:
                    host = cleaned.strip().lower().rstrip(".")
            else:
                host = cleaned.strip().lower().rstrip(".")
    except Exception:
        return None
    if not host:
        return None
    return host, explicit_port, scheme_hint


def _parse_internet_check_targets(
    raw: Any,
    port_profile: str = "dns",
    custom_port: int = 53,
) -> List[Tuple[str, int]]:
    parsed_items: List[Tuple[str, Optional[int], str]] = []
    if isinstance(raw, list):
        for x in raw:
            if isinstance(x, (tuple, list)) and len(x) >= 1:
                host = str(x[0] or "").strip().lower().rstrip(".")
                explicit_port: Optional[int] = None
                if len(x) >= 2:
                    try:
                        explicit_port = int(x[1])
                    except Exception:
                        explicit_port = None
                if host:
                    parsed_items.append((host, explicit_port, ""))
                continue
            parsed = _parse_target_token(str(x or "").strip())
            if parsed:
                parsed_items.append(parsed)
    else:
        tokens = [p.strip() for p in re.split(r"[\s,;]+", str(raw or ""))]
        for part in tokens:
            parsed = _parse_target_token(part)
            if parsed:
                parsed_items.append(parsed)
    pairs: List[Tuple[str, int]] = []
    seen: set[Tuple[str, int]] = set()
    profile = _normalize_internet_check_port_profile(port_profile)
    cport = _normalize_internet_check_custom_port(custom_port)
    for parsed in parsed_items:
        host, explicit_port, scheme_hint = parsed
        resolved_port = _resolve_port_from_profile(profile, cport, explicit_port, scheme_hint)
        pair = (host, resolved_port)
        if pair in seen:
            continue
        seen.add(pair)
        pairs.append(pair)
    if not pairs:
        return list(DEFAULT_INTERNET_CHECK_TARGETS)
    return pairs


def _internet_check_targets_display(targets: List[Tuple[str, int]]) -> str:
    if not targets:
        targets = list(DEFAULT_INTERNET_CHECK_TARGETS)
    return ", ".join(f"{host}:{port}" for host, port in targets)


def _internet_check_settings_from_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    mode = _normalize_internet_check_mode(cfg.get("internet_check_mode", "tcp-connect"))
    timeout_ms = _normalize_internet_check_timeout_ms(cfg.get("internet_check_timeout_ms", 1500))
    port_profile = _normalize_internet_check_port_profile(cfg.get("internet_check_port_profile", "dns"))
    custom_port = _normalize_internet_check_custom_port(cfg.get("internet_check_custom_port", 53))
    targets = _parse_internet_check_targets(cfg.get("internet_check_targets", ""), port_profile=port_profile, custom_port=custom_port)
    dns_servers = _parse_internet_check_targets(cfg.get("internet_check_dns_servers", DEFAULT_INTERNET_CHECK_DNS_SERVERS), port_profile="dns", custom_port=53)
    if port_profile == "custom":
        target_port = custom_port
        target_port_text = f"custom:{custom_port}"
    elif port_profile == "from-target":
        target_port = int(targets[0][1]) if targets else 53
        target_port_text = "from target/url"
    else:
        target_port = {"dns": 53, "http": 80, "https": 443}.get(port_profile, 53)
        target_port_text = f"{port_profile}:{target_port}"
    return {
        "mode": mode,
        "port_profile": port_profile,
        "custom_port": custom_port,
        "target_port": target_port,
        "target_port_text": target_port_text,
        "timeout_ms": timeout_ms,
        "targets": targets,
        "targets_text": _internet_check_targets_display(targets),
        "dns_servers": dns_servers,
        "dns_servers_text": _internet_check_targets_display(dns_servers),
    }


def _probe_internet_connectivity(settings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = settings or {}
    timeout_ms = _normalize_internet_check_timeout_ms(cfg.get("timeout_ms", 1500))
    timeout_sec = max(0.25, float(timeout_ms) / 1000.0)
    port_profile = _normalize_internet_check_port_profile(cfg.get("port_profile", "dns"))
    custom_port = _normalize_internet_check_custom_port(cfg.get("custom_port", 53))
    targets = _parse_internet_check_targets(
        cfg.get("targets", DEFAULT_INTERNET_CHECK_TARGETS),
        port_profile=port_profile,
        custom_port=custom_port,
    )
    dns_servers = _parse_internet_check_targets(
        cfg.get("dns_servers", DEFAULT_INTERNET_CHECK_DNS_SERVERS),
        port_profile="dns",
        custom_port=53,
    )
    probe_targets_primary: List[Tuple[str, int]] = list(targets)
    for server in dns_servers:
        if server not in probe_targets_primary:
            probe_targets_primary.append(server)

    probe_targets: List[Tuple[str, int]] = list(probe_targets_primary)
    if port_profile == "dns":
        # DNS mode: add web ports as fallback to avoid false offline on networks
        # that block outbound DNS while general internet connectivity still works.
        for host, _ in probe_targets_primary:
            for fallback_port in (443, 80):
                pair = (host, fallback_port)
                if pair not in probe_targets:
                    probe_targets.append(pair)
    errors: List[str] = []
    checked_at = int(time.time())
    for host, port in probe_targets:
        try:
            with socket.create_connection((host, port), timeout=timeout_sec):
                return {
                    "reachable": True,
                    "detail": f"Outbound network reachable via {host}:{port}.",
                    "checked_at": checked_at,
                }
        except Exception as exc:
            errors.append(f"{host}:{port} {type(exc).__name__}")
    detail = (
        "All internet probes failed (" + ", ".join(errors) + ")."
        if errors
        else "All internet probes failed."
    )
    return {"reachable": False, "detail": detail, "checked_at": checked_at}


def _render_auth_shell(title: str, body_html: str, info: str = "", error: str = "", ssl_warning: str = "") -> str:
    info_html = f'<div class="ok">{html.escape(info)}</div>' if info else ""
    err_html = f'<div class="err">{html.escape(error)}</div>' if error else ""
    try:
        cfg = load_config()
        browser_instance_name = str(cfg.get("instance_name", "") or "").strip()
    except Exception:
        browser_instance_name = ""
    warn_html = (
        "<details class='warn-wrap'>"
        "<summary class='warn-btn'>Connection security warning (more info)</summary>"
        f"<div class='warn-body'>{html.escape(ssl_warning)}</div>"
        "</details>"
        if ssl_warning
        else ""
    )
    page_title = (
        f'{(html.escape(browser_instance_name) + " - ") if browser_instance_name else ""}'
        f"{html.escape(PRODUCT_NAME)} - Security"
    )
    return web_render.render_auth_shell(
        favicon_url=html.escape(BRAND_FAVICON_URL),
        page_title=page_title,
        styles=web_render.render_auth_shell_styles(),
        hero=web_render.render_auth_hero(
            html.escape(BRAND_URL), html.escape(BRAND_LOGO_URL), html.escape(BRAND_NAME)
        ),
        title=html.escape(title),
        warn_html=warn_html,
        info_html=info_html,
        err_html=err_html,
        body_html=body_html,
    )


def _render_auth_setup_page(
    info: str = "",
    error: str = "",
    verify: Optional[Dict[str, Any]] = None,
    recovery: Optional[Dict[str, Any]] = None,
    ssl_warning: str = "",
) -> str:
    copy_script = """
        <script>
        function copyText(text) {
          if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
          }
          return new Promise(function(resolve, reject) {
            try {
              var ta = document.createElement('textarea');
              ta.value = text;
              ta.setAttribute('readonly', '');
              ta.style.position = 'fixed';
              ta.style.opacity = '0';
              ta.style.left = '-9999px';
              document.body.appendChild(ta);
              ta.focus();
              ta.select();
              var ok = document.execCommand('copy');
              document.body.removeChild(ta);
              if (ok) resolve();
              else reject(new Error('copy command failed'));
            } catch (e) {
              reject(e);
            }
          });
        }
        function copyTotpSecret(btn) {
          var el = document.getElementById('totp-secret');
          if (!el) return;
          copyText(el.textContent || '').then(function() {
            var t = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(function() { btn.textContent = t; }, 1500);
          }).catch(function() {
            alert('Failed to copy. Please copy manually from the field.');
          });
        }
        function copyRecoveryCodes(btn) {
          var el = document.getElementById('recovery-codes');
          if (!el) return;
          copyText((el.textContent || '').trim()).then(function() {
            var t = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(function() { btn.textContent = t; }, 1500);
          }).catch(function() {
            alert('Failed to copy. Please copy manually from the field.');
          });
        }
        </script>
        """
    if recovery:
        recovery_codes_text = "\n".join([str(x) for x in recovery.get("recovery_codes", [])])
        body = f"""
        <div class="ok">Setup complete. Your authenticator is already linked — store these recovery codes in a safe place (shown once).</div>
        <div style="margin-top:10px;"><b>Recovery Codes (shown once)</b></div>
        <pre id="recovery-codes">{html.escape(recovery_codes_text)}</pre>
        <div class="button-row">
          <button type="button" class="btn secondary" onclick="copyRecoveryCodes(this)">Copy Recovery Codes</button>
        </div>
        <div class="button-row">
          <a class="btn" href="/auth/login">Continue to Login</a>
        </div>
        {copy_script}
        """
    elif verify:
        qr_html = ""
        if verify.get("qr_data_uri"):
            qr_html = f'<img class="qr" alt="TOTP QR" src="{html.escape(str(verify.get("qr_data_uri", "")))}">'
        setup_id = html.escape(str(verify.get("setup_id", "")))
        totp_secret = html.escape(str(verify.get("totp_secret", "")))
        body = f"""
        <div class="ok">Scan the QR code with your authenticator app, then enter the 6-digit code to verify before the account is saved.</div>
        {qr_html}
        <div style="margin-top:10px;"><b>TOTP Secret</b><br><code id="totp-secret">{totp_secret}</code></div>
        <div class="muted">If QR is unavailable, add this secret manually in your authenticator app.</div>
        <div class="button-row">
          <button type="button" class="btn secondary" onclick="copyTotpSecret(this)">Copy TOTP Secret</button>
        </div>
        <form method="post" action="/auth/setup/verify" style="margin-top:14px;">
          <input type="hidden" name="setup_id" value="{setup_id}">
          <label>6-digit code from authenticator</label>
          <input id="auth-verify-totp" name="token" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="123456" required autofocus>
          <div class="button-row">
            <button type="submit">Verify and save</button>
          </div>
        </form>
        {copy_script}
        """
    else:
        body = web_render.render_auth_setup_body()
    return _render_auth_shell("Initial Security Setup", body, info=info, error=error, ssl_warning=ssl_warning)


def _render_auth_login_page(info: str = "", error: str = "", ssl_warning: str = "") -> str:
    body = web_render.render_auth_login_body()
    return _render_auth_shell("Login", body, info=info, error=error, ssl_warning="")


def _render_auth_verify_page(info: str = "", error: str = "", ssl_warning: str = "") -> str:
    body = web_render.render_auth_verify_body()
    return _render_auth_shell("Two-Factor Verification", body, info=info, error=error, ssl_warning=ssl_warning)


def _render_auth_recovery_page(info: str = "", error: str = "", ssl_warning: str = "") -> str:
    body = web_render.render_auth_recovery_body()
    return _render_auth_shell("Recovery Access", body, info=info, error=error, ssl_warning=ssl_warning)


def _find_monitor_by_name(monitors: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    for m in monitors:
        if str(m.get("name", "")) == name:
            return m
    return None


def _ui_run_check_now(target_monitor: Optional[str] = None, initiated_by: str = "local") -> str:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    dbg = bool(cfg.get("debug", False))
    if not monitors:
        append_ui_log("run-check | no monitors configured")
        return "No monitors configured."
    if target_monitor:
        target = _find_monitor_by_name(monitors, target_monitor)
        if not target:
            append_ui_log(f"run-check | monitor not found: {target_monitor}")
            return f"Monitor not found: {target_monitor}"
        monitors = [target]
    lines: List[str] = []
    triggered_by_master = str(initiated_by or "").strip().lower() == "master"
    trigger_suffix = " (triggered by master)" if triggered_by_master else ""
    for m in monitors:
        name = m.get("name", "?")
        mode = str(m.get("check_mode", "smart")).lower()
        if mode not in CHECK_MODES:
            mode = "smart"
        devices = [str(x) for x in m.get("devices", [])]
        url = m.get("kuma_url", "")
        if not url:
            line = f"x {name}: no Kuma URL"
            lines.append(line)
            _set_monitor_state(str(name), "Monitor check failed" + trigger_suffix, line, level="err")
            append_ui_log(f"run-check | {name} | no Kuma URL | triggered_by={'master' if triggered_by_master else 'local'}")
            continue
        status, msg, lat = check_host_with_monitor(mode, devices, monitor=m, debug=dbg)
        if triggered_by_master:
            msg = f"{msg}\nTriggered by master."
        ok = push_to_kuma(url, status, msg, lat, debug=dbg)
        recorded_status = status if ok else "warning"
        _record_history(str(name), mode, recorded_status, lat)
        line = f"{'ok' if ok else 'x'} {name}: {status} (ping={lat:.2f}ms) push {'OK' if ok else 'FAILED'}"
        lines.append(line)
        _set_monitor_state(
            str(name),
            ("Monitor check completed" if ok else "Monitor check completed with errors") + trigger_suffix,
            line,
            level="ok" if ok else "err",
        )
        append_ui_log(
            f"run-check | {name} | mode={mode} | status={status} | ping_ms={lat:.2f} | push={'OK' if ok else 'FAILED'} | triggered_by={'master' if triggered_by_master else 'local'}"
        )
        compact_msg = " ".join(msg.replace("\n", " | ").split())
        append_ui_log(f"run-check-detail | {name} | {compact_msg}")
    if not target_monitor:
        role = str(cfg.get("peer_role", "")).lower()
        if role == "agent":
            try:
                sync_msg = _peer_push_to_master(cfg)
                lines.append(f"[peer-sync] {sync_msg}")
                append_ui_log(f"peer-sync | {sync_msg}")
            except Exception as e:
                lines.append(f"[peer-sync] error: {e}")
                append_ui_log(f"peer-sync | error: {type(e).__name__}: {e}")
        elif role == "master":
            try:
                sync_msg = _peer_sync_from_master(load_config())
                lines.append(f"[peer-sync] {sync_msg}")
                append_ui_log(f"peer-sync | master auto-sync: {sync_msg}")
            except Exception as e:
                lines.append(f"[peer-sync] error: {e}")
                append_ui_log(f"peer-sync | error: {type(e).__name__}: {e}")
    return "\n".join(lines)


def _ui_test_push(target_monitor: Optional[str] = None, initiated_by: str = "local") -> str:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    if not monitors:
        append_ui_log("test-push | no monitors configured")
        return "No monitors configured."
    if target_monitor:
        target = _find_monitor_by_name(monitors, target_monitor)
        if not target:
            append_ui_log(f"test-push | monitor not found: {target_monitor}")
            return f"Monitor not found: {target_monitor}"
        monitors = [target]
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    lines: List[str] = []
    triggered_by_master = str(initiated_by or "").strip().lower() == "master"
    trigger_suffix = " (triggered by master)" if triggered_by_master else ""
    for m in monitors:
        source_platform = _monitor_source_platform(m)
        flavor = "synology-monitor" if source_platform == "synology" else "unix-monitor"
        msg = f"Test push @ {now} - {BRAND_NAME} {flavor} connectivity check"
        if triggered_by_master:
            msg += " (triggered by master)"
        ok = push_to_kuma(m.get("kuma_url", ""), "up", msg, 0, debug=bool(cfg.get("debug", False)))
        line = f"{'ok' if ok else 'x'} {m.get('name', '?')}: push {'OK' if ok else 'FAILED'}"
        lines.append(line)
        _set_monitor_state(
            str(m.get("name", "?")),
            ("Monitor test push completed" if ok else "Monitor test push failed") + trigger_suffix,
            line,
            level="ok" if ok else "err",
        )
        parsed = urlparse(m.get("kuma_url", ""))
        append_ui_log(
            f"test-push | {m.get('name', '?')} | host={parsed.hostname or '?'} | push={'OK' if ok else 'FAILED'} | triggered_by={'master' if triggered_by_master else 'local'}"
        )
    return "\n".join(lines)


def _ui_check_elevated_access() -> str:
    ok, msg = get_smart_helper_status()
    append_ui_log(f"elevated-check | {'active' if ok else 'inactive'} | {msg}")
    return f"{'ACTIVE' if ok else 'INACTIVE'}: {msg}"


def _ui_delete_monitor(name: str) -> str:
    cfg = load_config()
    monitors = cfg.get("monitors", [])
    kept = [m for m in monitors if str(m.get("name", "")) != name]
    if len(kept) == len(monitors):
        append_ui_log(f"delete-monitor | not found: {name}")
        return f"Monitor not found: {name}"
    cfg["monitors"] = kept
    save_config(cfg)
    _delete_monitor_runtime_data(name)
    append_ui_log(f"delete-monitor | removed: {name}")
    _trigger_peer_sync_bg(cfg)
    return f"Removed monitor: {name}"


def _ui_run_scheduled_now() -> str:
    cfg = load_config()
    if not cfg.get("cron_enabled", False):
        append_ui_log("automation | run-scheduled-now | skipped | automatic checks disabled")
        return "Automatic checks are disabled in monitor settings."
    output = _ui_run_check_now()
    # Match run_scheduled() schedule state: global + per-monitor, so "due" and Kuma heartbeats stay aligned.
    for m in cfg.get("monitors", []):
        if isinstance(m, dict):
            n = str(m.get("name", "") or "").strip()
            if n:
                _touch_scheduled_run(monitor_name=n)
    _touch_scheduled_run()
    append_ui_log("automation | run-scheduled-now | completed")
    return output


def _ui_repair_automation() -> str:
    cfg = load_config()
    details: List[str] = []
    backend = str(cfg.get("scheduler_backend", "cron")).strip().lower()
    if backend not in ("systemd", "cron"):
        backend = "cron"
    service_script = _scheduler_service_path()
    if service_script.exists():
        rc, out = _run_cmd([str(service_script), "start"], timeout_sec=12)
        details.append(f"service start rc={rc}")
        if out.strip():
            details.append(out.strip().replace("\n", " ")[:240])
    else:
        details.append(f"service script missing: {service_script}")

    if backend == "systemd":
        if not Path("/run/systemd/system").exists():
            details.append("systemd backend selected but systemd runtime not detected.")
        else:
            # Legacy timers used OnUnitActiveSec with Type=oneshot; systemd can stop scheduling (elapsed / no next).
            timer_path = Path("/etc/systemd/system/unix-monitor-scheduler.timer")
            if timer_path.is_file():
                try:
                    cur_timer = timer_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    cur_timer = ""
                if "OnUnitActiveSec=" in cur_timer and "OnUnitInactiveSec=" not in cur_timer:
                    sched_min = max(1, min(int(cfg.get("cron_interval_minutes", 60) or 60), 1440))
                    new_timer = (
                        "[Unit]\n"
                        f"Description=Run {PRODUCT_NAME} checks every {sched_min} minute(s)\n\n"
                        "[Timer]\n"
                        "OnBootSec=2min\n"
                        f"OnUnitInactiveSec={sched_min}min\n"
                        "AccuracySec=30s\n"
                        "Persistent=true\n\n"
                        "[Install]\n"
                        "WantedBy=timers.target\n"
                    )
                    try:
                        timer_path.write_text(new_timer, encoding="utf-8")
                        timer_path.chmod(0o644)
                        rc_dr, _ = _run_cmd(["systemctl", "daemon-reload"], timeout_sec=20)
                        details.append(
                            "unix-monitor-scheduler.timer: migrated OnUnitActiveSec -> OnUnitInactiveSec "
                            f"(interval={sched_min}m, daemon-reload={'ok' if rc_dr == 0 else f'rc={rc_dr}'})"
                        )
                    except OSError as e:
                        details.append(f"scheduler.timer migrate failed: {type(e).__name__}: {e}")
            for unit in (
                "unix-monitor-scheduler.timer",
                "unix-monitor-smart-helper.timer",
                "unix-monitor-backup-helper.timer",
                "unix-monitor-system-log-helper.timer",
            ):
                rc, out = _run_cmd(["systemctl", "enable", "--now", unit], timeout_sec=15)
                details.append(f"{unit}: {'ok' if rc == 0 else f'failed rc={rc}'}")
                if rc != 0 and out.strip():
                    details.append(out.strip().replace("\n", " ")[:240])
            rc, out = _run_cmd(["systemctl", "start", "unix-monitor-scheduler.service"], timeout_sec=20)
            details.append(f"unix-monitor-scheduler.service start: {'ok' if rc == 0 else f'failed rc={rc}'}")
            if rc != 0 and out.strip():
                details.append(out.strip().replace("\n", " ")[:240])
    else:
        # Cron backend: install deterministic entries based on the active script path.
        helper = str(get_smart_helper_script_path())
        interval = int(cfg.get("cron_interval_minutes", 60) or 60)
        sched_line = build_cron_line(get_script_path(), interval)
        helper_line = f"*/5 * * * * {helper} # unix-monitor smart helper auto"
        for line in (helper_line, sched_line):
            rc, out = _run_cmd(["crontab", "-l"], timeout_sec=8)
            current = out if rc == 0 else ""
            if line not in current:
                new_cron = (current.rstrip() + "\n" + line + "\n").lstrip("\n")
                try:
                    p = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
                    p.communicate(new_cron)
                    details.append(f"crontab install {'ok' if p.returncode == 0 else 'failed'} for: {line}")
                except OSError as e:
                    details.append(f"crontab error for {line}: {type(e).__name__}: {e}")
            else:
                details.append(f"crontab already has: {line}")

    append_ui_log("automation | repair | " + " | ".join(details))
    return "\n".join(details)


class _DualProtocolSocket:
    """Wraps a server socket to auto-detect TLS vs plain HTTP on the same port.

    On each accepted connection, peeks at the first byte:
      - 0x16 (TLS ClientHello) -> wrap with the provided SSL context
      - Anything else (plain HTTP) -> leave unwrapped, handler will redirect to HTTPS
    """

    def __init__(self, raw_socket: socket.socket, ssl_ctx: ssl.SSLContext):
        self._raw = raw_socket
        self._ctx = ssl_ctx

    def accept(self) -> Tuple[socket.socket, Any]:
        conn, addr = self._raw.accept()
        try:
            conn.settimeout(5.0)
            first = conn.recv(1, socket.MSG_PEEK)
            if first and first[0] == 0x16:
                conn = self._ctx.wrap_socket(conn, server_side=True)
        except Exception:
            pass
        return conn, addr

    def fileno(self) -> int:
        return self._raw.fileno()

    def close(self) -> None:
        return self._raw.close()

    def getsockname(self) -> Any:
        return self._raw.getsockname()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


def run_setup_ui(host: str = "0.0.0.0", port: int = 8787) -> int:
    cfg = load_config()
    if not _agent_effective_web_enabled(cfg):
        print(
            "Local web UI is disabled (web_enabled=false or lock_local_ui_when_connected while master is connected).",
            file=sys.stderr,
        )
        return 2
    class Handler(BaseHTTPRequestHandler):
        _tls_available = False

        def _client_source_ip(self) -> str:
            xff = str(self.headers.get("X-Forwarded-For", "") or "").strip()
            if xff:
                first = xff.split(",")[0].strip()
                if first:
                    return first
            xrip = str(self.headers.get("X-Real-IP", "") or "").strip()
            if xrip:
                return xrip
            try:
                return str(self.client_address[0] or "").strip() or "unknown"
            except Exception:
                return "unknown"

        def _connected_interface_host(self) -> str:
            """Host/interface used to access this UI request."""
            xfh = str(self.headers.get("X-Forwarded-Host", "") or "").strip()
            if xfh:
                return xfh.split(",")[0].strip()
            host = str(self.headers.get("Host", "") or "").strip()
            if host:
                return host
            try:
                return str(self.server.server_address[0] or "").strip()
            except Exception:
                return ""

        def _redirect_http_to_https(self) -> bool:
            """If TLS is active but this request arrived over plain HTTP, redirect to HTTPS.
            Returns True if redirect was sent (caller should return), False otherwise.
            Peer API paths are exempt -- they use application-layer security.
            Requests arriving through a reverse proxy are exempt -- the proxy handles TLS.
            Raw IP access is exempt -- redirecting http://IP:port to https://IP:port can cause
            ERR_SSL_PROTOCOL_ERROR when TLS later becomes unavailable (certs removed, reinstall)."""
            if not self._tls_available:
                return False
            if isinstance(self.connection, ssl.SSLSocket):
                return False
            if self.path.startswith("/api/peer/"):
                return False
            fwd_proto = (self.headers.get("X-Forwarded-Proto", "") or
                         self.headers.get("X-Forwarded-Protocol", "")).lower()
            if fwd_proto:
                return False
            if self.headers.get("X-Forwarded-For") or self.headers.get("X-Real-IP"):
                return False
            host = self.headers.get("Host", "")
            if not host:
                host = f"localhost:{self.server.server_address[1]}"
            hostname = (host.split("]:")[0].lstrip("[") if "]" in host else host).split(":")[0]
            if not hostname:
                return False
            if (hostname in ("localhost", "127.0.0.1") or
                    re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) or
                    ":" in hostname):
                return False
            location = f"https://{host}{self.path}"
            self.send_response(301)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return True

        def _reply_png(self, data: bytes, code: int = 200) -> None:
            self.send_response(code)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _reply_html(self, content: str, code: int = 200, extra_headers: Optional[List[Tuple[str, str]]] = None) -> None:
            payload = content.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            if extra_headers:
                for k, v in extra_headers:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _reply_json(self, data: Dict[str, Any], code: int = 200, extra_headers: Optional[List[Tuple[str, str]]] = None) -> None:
            payload = json.dumps(data).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            if extra_headers:
                for k, v in extra_headers:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _redirect(self, location: str, extra_headers: Optional[List[Tuple[str, str]]] = None) -> None:
            self.send_response(302)
            if extra_headers:
                for k, v in extra_headers:
                    self.send_header(k, v)
            self.send_header("Location", location)
            self.end_headers()

        def _cookie_header(self, name: str, value: str, max_age: int) -> str:
            return build_cookie_header(
                name, value, max_age, secure=isinstance(self.connection, ssl.SSLSocket)
            )

        def _clear_cookie_header(self, name: str) -> str:
            return clear_cookie_header(
                name, secure=isinstance(self.connection, ssl.SSLSocket)
            )

        def _parse_cookies(self) -> Dict[str, str]:
            return parse_cookie_header(self.headers.get("Cookie", ""))

        def _ssl_warning_text(self) -> str:
            if isinstance(self.connection, ssl.SSLSocket):
                return ""
            forwarded = (self.headers.get("X-Forwarded-Proto", "") or self.headers.get("X-Forwarded-Protocol", "")).lower()
            if "https" in forwarded:
                return ""
            host = self.headers.get("Host", "")
            return (
                f"Connection appears to be plain HTTP ({host or 'direct access'}). "
                "Use reverse proxy with HTTPS to protect login credentials and 2FA codes."
            )

        def _view_from_referer(self) -> str:
            ref = self.headers.get("Referer", "")
            if not ref:
                return "overview"
            try:
                q = parse_qs(urlparse(ref).query)
                v = (q.get("view", ["overview"])[0] or "overview").strip().lower()
            except Exception:
                return "overview"
            return v if v in ("overview", "setup", "settings") else "overview"

        def _ui_context_from_referer(self) -> Tuple[str, str, str, str, str, str, str, str]:
            ref = self.headers.get("Referer", "")
            if not ref:
                return ("overview", "logs", "all", "local", "all", "all", "", "")
            try:
                q = parse_qs(urlparse(ref).query)
            except Exception:
                return ("overview", "logs", "all", "local", "all", "all", "", "")
            ui_view = (q.get("ui_view", [q.get("view", ["overview"])[0]])[0] or "overview").strip().lower()
            if ui_view not in ("overview", "setup", "settings"):
                ui_view = "overview"
            diag_view = (q.get("diag_view", ["logs"])[0] or "logs").strip().lower()
            if diag_view not in ("logs", "task", "cache", "config", "history", "paths", "system"):
                diag_view = "logs"
            log_filter = (q.get("log_filter", ["all"])[0] or "all").strip().lower()
            if log_filter not in ("all", "smart", "storage", "ping", "port", "dns", "backup", "service"):
                log_filter = "all"
            log_source = (q.get("source", [q.get("log_source", ["local"])[0]])[0] or "local").strip() or "local"
            log_date = _normalize_log_date((q.get("log_date", ["all"])[0] or "all").strip().lower())
            log_time_scope = _normalize_log_time_scope((q.get("log_time_scope", ["all"])[0] or "all").strip().lower())
            log_time_from = _normalize_log_time_hhmm((q.get("log_time_from", [""])[0] or "").strip())
            log_time_to = _normalize_log_time_hhmm((q.get("log_time_to", [""])[0] or "").strip())
            return (ui_view, diag_view, log_filter, log_source, log_date, log_time_scope, log_time_from, log_time_to)

        def _resolve_ui_context(self, form: Optional[Dict[str, List[str]]] = None) -> Tuple[str, str, str, str, str, str, str, str]:
            ui_view, diag_view, log_filter, log_source, log_date, log_time_scope, log_time_from, log_time_to = self._ui_context_from_referer()
            if not isinstance(form, dict):
                return (ui_view, diag_view, log_filter, log_source, log_date, log_time_scope, log_time_from, log_time_to)
            form_view = (form.get("ui_view", [form.get("view", [ui_view])[0]])[0] or ui_view).strip().lower()
            if form_view in ("overview", "setup", "settings"):
                ui_view = form_view
            form_diag = (form.get("diag_view", [diag_view])[0] or diag_view).strip().lower()
            if form_diag in ("logs", "task", "cache", "config", "history", "paths", "system"):
                diag_view = form_diag
            form_filter = (form.get("log_filter", [log_filter])[0] or log_filter).strip().lower()
            if form_filter in ("all", "smart", "storage", "ping", "port", "dns", "backup", "service"):
                log_filter = form_filter
            form_source = (form.get("source", [form.get("log_source", [log_source])[0]])[0] or log_source).strip()
            if form_source:
                log_source = form_source
            fd_ld = (form.get("log_date", [log_date])[0] or log_date).strip().lower()
            if fd_ld:
                log_date = _normalize_log_date(fd_ld)
            fd_lt = (form.get("log_time_scope", [log_time_scope])[0] or log_time_scope).strip().lower()
            if fd_lt:
                log_time_scope = _normalize_log_time_scope(fd_lt)
            fd_ltf = (form.get("log_time_from", [log_time_from])[0] or log_time_from).strip()
            log_time_from = _normalize_log_time_hhmm(fd_ltf)
            fd_ltt = (form.get("log_time_to", [log_time_to])[0] or log_time_to).strip()
            log_time_to = _normalize_log_time_hhmm(fd_ltt)
            return (ui_view, diag_view, log_filter, log_source, log_date, log_time_scope, log_time_from, log_time_to)

        def _is_authenticated(self) -> bool:
            auth = _load_auth_state()
            token = self._parse_cookies().get(AUTH_COOKIE_NAME, "")
            return session_token_valid(token, str(auth.get("session_secret", "")))

        def _has_valid_challenge(self) -> bool:
            auth = _load_auth_state()
            token = self._parse_cookies().get(AUTH_CHALLENGE_COOKIE_NAME, "")
            return challenge_token_valid(token, str(auth.get("session_secret", "")))

        def _verify_peer_token(self) -> bool:
            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return False
            token = auth_header[7:].strip()
            if not token:
                return False
            cfg = load_config()
            expected = str(cfg.get("peering_token", "") or "").strip()
            if not expected:
                return False
            return hmac.compare_digest(token, expected)

        def _peer_mtls_enforced(self) -> bool:
            cfg = load_config()
            cert, key, ca = _get_mtls_cert_paths(cfg)
            return bool(cert and key and ca)

        def _peer_client_cert_present(self) -> bool:
            if not isinstance(self.connection, ssl.SSLSocket):
                return False
            try:
                cert = self.connection.getpeercert()
                return bool(cert)
            except Exception:
                return False

        def _require_peer_mtls(self, allow_token_only: bool = False) -> bool:
            if allow_token_only or not self._peer_mtls_enforced():
                return True
            # Client certificates are only available on TLS connections. Plain HTTP
            # peering uses Bearer token + encrypted payloads (same bootstrap model as register).
            if not isinstance(self.connection, ssl.SSLSocket):
                return True
            if self._peer_client_cert_present():
                return True
            self._reply_json({"error": "mTLS client certificate required"}, 401)
            return False

        def _read_peer_body(self) -> Tuple[str, bool]:
            raw_len = int(self.headers.get("Content-Length", "0"))
            body_raw = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
            if isinstance(self.connection, ssl.SSLSocket):
                return body_raw, True
            if not body_raw:
                return body_raw, True
            try:
                wrapped = json.loads(body_raw)
            except (json.JSONDecodeError, ValueError):
                return body_raw, True
            if not isinstance(wrapped, dict) or not isinstance(wrapped.get("enc"), str):
                return body_raw, True
            cfg = load_config()
            token = str(cfg.get("peering_token", "") or "").strip()
            if not token:
                return "", False
            dec = _decrypt_payload(str(wrapped.get("enc", "")), token)
            if dec is None:
                return "", False
            return dec, True

        def _reply_peer_json(self, data: Dict[str, Any], code: int = 200) -> None:
            if isinstance(self.connection, ssl.SSLSocket):
                self._reply_json(data, code)
                return
            cfg = load_config()
            token = str(cfg.get("peering_token", "") or "").strip()
            if not token:
                self._reply_json(data, code)
                return
            payload = json.dumps({"enc": _encrypt_payload(json.dumps(data), token)}).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Peer-Encrypted", "1")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _check_get_signature(self) -> None:
            """Best-effort signature verification for GET peer requests (empty body)."""
            sig = self.headers.get("X-Peer-Sig", "")
            if sig:
                sig_headers = {
                    "X-Peer-Sig": sig,
                    "X-Peer-Ts": self.headers.get("X-Peer-Ts", ""),
                    "X-Peer-Nonce": self.headers.get("X-Peer-Nonce", ""),
                    "X-Peer-Id": self.headers.get("X-Peer-Id", ""),
                }
                vfy_cfg = load_config()
                valid, vmsg = _verify_peer_signature(sig_headers, b"", vfy_cfg)
                if valid:
                    append_ui_log(f"peer-sig | GET verified: {vmsg}")
                else:
                    append_ui_log(f"peer-sig | GET signature failed: {vmsg}")

        def do_GET(self) -> None:  # noqa: N802
            _set_request_display_host(self._connected_interface_host())
            if self._redirect_http_to_https():
                return
            parsed = urlparse(self.path)
            if parsed.path == "/connection-info":
                port = self.server.server_address[1]
                host = self.headers.get("Host", "").split(":")[0] or "localhost"
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Access-Control-Allow-Origin", "*")
                info = {
                    "tls_available": bool(Handler._tls_available),
                    "port": port,
                    "over_tls": isinstance(self.connection, ssl.SSLSocket),
                    "suggestion": (
                        "Use https:// when TLS is available."
                        if Handler._tls_available
                        else "Server is HTTP-only. Use http:// explicitly. If your browser forces HTTPS (HSTS), try another browser or clear site data."
                    ),
                }
                self.end_headers()
                self.wfile.write(json.dumps(info).encode("utf-8"))
                return
            if parsed.path == "/api/peer/health":
                if not self._require_peer_mtls(allow_token_only=True):
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                self._check_get_signature()
                cfg = load_config()
                mtls_status = _get_mtls_security_status(cfg)
                self._reply_peer_json({
                    "status": "ok",
                    "instance_id": _get_instance_id(cfg),
                    "instance_name": str(cfg.get("instance_name", "") or ""),
                    "version": VERSION,
                    "role": str(cfg.get("peer_role", "standalone") or "standalone"),
                    "monitor_count": len(cfg.get("monitors", [])),
                    "ts": int(time.time()),
                    "signing_active": mtls_status.get("signing_active", False),
                }, 200)
                return
            if parsed.path == "/api/peer/snapshot":
                if not self._require_peer_mtls():
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                self._check_get_signature()
                cfg = load_config()
                history = _load_history()
                state = _load_monitor_state()
                auth = load_auth()
                self._reply_peer_json({
                    "instance_id": _get_instance_id(cfg),
                    "instance_name": str(cfg.get("instance_name", "") or ""),
                    "version": VERSION,
                    "last_login_ip": str(auth.get("last_login_ip", "") or "").strip(),
                    "last_login_at": int(auth.get("last_login_at", 0) or 0),
                    "monitors": cfg.get("monitors", []),
                    "history": history[-200:],
                    "state": state,
                    "pushed_at": int(time.time()),
                }, 200)
                return
            if parsed.path == "/api/peer/config":
                if not self._require_peer_mtls():
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                self._check_get_signature()
                cfg = load_config()
                safe_cfg = {
                    "cron_enabled": bool(cfg.get("cron_enabled", False)),
                    "cron_interval_minutes": int(cfg.get("cron_interval_minutes", 60) or 60),
                    "instance_id": _get_instance_id(cfg),
                    "instance_name": str(cfg.get("instance_name", "") or ""),
                    "peer_role": str(cfg.get("peer_role", "standalone") or "standalone"),
                }
                self._reply_peer_json(safe_cfg, 200)
                return
            if parsed.path == "/api/peer/diag":
                if not self._require_peer_mtls(allow_token_only=True):
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                self._check_get_signature()
                qs = parse_qs(parsed.query)
                view = str(qs.get("view", ["logs"])[0] or "logs").strip().lower()
                lf = str(qs.get("log_filter", ["all"])[0] or "all").strip().lower()
                ld = _normalize_log_date(str(qs.get("log_date", ["all"])[0] or "all").strip().lower())
                lt = _normalize_log_time_scope(str(qs.get("log_time_scope", ["all"])[0] or "all").strip().lower())
                ltf = _normalize_log_time_hhmm(str(qs.get("log_time_from", [""])[0] or "").strip())
                ltt = _normalize_log_time_hhmm(str(qs.get("log_time_to", [""])[0] or "").strip())
                cfg = load_config()
                history = _load_history()
                text = _build_diag_text(cfg, history, diag_view=view, log_filter=lf, log_date=ld, log_time_scope=lt, log_time_from=ltf, log_time_to=ltt)
                self._reply_peer_json({"text": text}, 200)
                return
            if parsed.path == "/api/peer/update-status":
                if not self._require_peer_mtls(allow_token_only=True):
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                self._check_get_signature()
                qs = parse_qs(parsed.query)
                session_id = str(qs.get("session_id", [""])[0] or "").strip()
                sess = _load_agent_update_session()
                if not session_id or sess.get("session_id") != session_id:
                    self._reply_peer_json({"error": "session not found", "stage": "unknown"}, 404)
                    return
                self._reply_peer_json({
                    "session_id": sess.get("session_id"),
                    "stage": sess.get("stage", "unknown"),
                    "log": sess.get("log", []),
                    "error": sess.get("error"),
                    "started_at": sess.get("started_at"),
                    "updated_at": sess.get("updated_at"),
                }, 200)
                return
            if parsed.path == "/api/public/internet":
                cfg = load_config()
                role = str(cfg.get("peer_role", "standalone") or "standalone").strip().lower()
                internet_settings = _internet_check_settings_from_cfg(cfg)
                probe = _probe_internet_connectivity(internet_settings)
                self._reply_json({
                    "reachable": bool(probe.get("reachable")),
                    "detail": str(probe.get("detail", "") or ""),
                    "checked_at": int(probe.get("checked_at", int(time.time()))),
                    "peer_role": role,
                    "internet_required": role != "standalone",
                    "settings_used": {
                        "mode": str(internet_settings.get("mode", "tcp-connect")),
                        "port_profile": str(internet_settings.get("port_profile", "dns")),
                        "target_port": int(internet_settings.get("target_port", 53)),
                        "target_port_text": str(internet_settings.get("target_port_text", "dns:53")),
                        "custom_port": int(internet_settings.get("custom_port", 53)),
                        "timeout_ms": int(internet_settings.get("timeout_ms", 1500)),
                        "targets": str(internet_settings.get("targets_text", "")),
                        "dns_servers": str(internet_settings.get("dns_servers_text", "")),
                    },
                }, 200)
                return
            auth = _load_auth_state()
            ssl_warning = self._ssl_warning_text()
            if parsed.path == "/auth/logout":
                self._redirect(
                    "/auth/login",
                    extra_headers=[
                        ("Set-Cookie", self._clear_cookie_header(AUTH_COOKIE_NAME)),
                        ("Set-Cookie", self._clear_cookie_header(AUTH_CHALLENGE_COOKIE_NAME)),
                    ],
                )
                return
            if parsed.path == "/auth/setup":
                if _auth_initialized(auth):
                    self._redirect("/auth/login")
                    return
                self._reply_html(_render_auth_setup_page(ssl_warning=ssl_warning))
                return
            if parsed.path == "/auth/login":
                if not _auth_initialized(auth):
                    self._redirect("/auth/setup")
                    return
                if self._is_authenticated():
                    self._redirect("/")
                    return
                locked, wait_sec = _is_locked(auth)
                msg = _lockout_message(wait_sec) if locked else ""
                self._reply_html(_render_auth_login_page(info=msg, ssl_warning=ssl_warning))
                return
            if parsed.path == "/auth/verify-2fa":
                if not _auth_initialized(auth):
                    self._redirect("/auth/setup")
                    return
                if self._is_authenticated():
                    self._redirect("/")
                    return
                if not self._has_valid_challenge():
                    self._redirect("/auth/login")
                    return
                self._reply_html(_render_auth_verify_page(ssl_warning=ssl_warning))
                return
            if parsed.path == "/auth/recovery":
                if not _auth_initialized(auth):
                    self._redirect("/auth/setup")
                    return
                if self._is_authenticated():
                    self._redirect("/")
                    return
                if not self._has_valid_challenge():
                    self._redirect("/auth/login")
                    return
                self._reply_html(_render_auth_recovery_page(ssl_warning=ssl_warning))
                return
            if parsed.path == "/auth/export":
                if not _auth_initialized(auth):
                    self._redirect("/auth/setup")
                    return
                if not self._is_authenticated():
                    self._redirect("/auth/login")
                    return
                cfg = load_config()
                monitors = cfg.get("monitors", []) if isinstance(cfg.get("monitors", []), list) else []
                public_monitors = []
                for m in monitors:
                    if not isinstance(m, dict):
                        continue
                    public_monitors.append(
                        {
                            "name": str(m.get("name", "")),
                            "check_mode": str(m.get("check_mode", "smart")),
                            "device_count": len([x for x in m.get("devices", []) if str(x).strip()]),
                            "kuma_token_hint": kuma_token_label(str(m.get("kuma_url", ""))),
                        }
                    )
                payload = {
                    "export_type": "safe-public",
                    "exported_at": int(time.time()),
                    "config_public": {
                        "cron_enabled": bool(cfg.get("cron_enabled", False)),
                        "cron_interval_minutes": int(cfg.get("cron_interval_minutes", 60) or 60),
                        "debug": bool(cfg.get("debug", False)),
                        "monitor_count": len(public_monitors),
                        "monitors": public_monitors,
                    },
                    "auth_public": {
                        "auth_initialized": bool(auth.get("auth_initialized", False)),
                        "recovery_codes_remaining": _count_unused_recovery(auth),
                    },
                    "notes": [
                        "Sensitive secrets are intentionally excluded.",
                        "No password hash, TOTP secret, session secret, recovery hashes, or full Kuma URLs are exported.",
                    ],
                }
                self._reply_json(
                    payload,
                    200,
                    extra_headers=[("Content-Disposition", 'attachment; filename="unix-monitor-settings-export.json"')],
                )
                return
            if not _auth_initialized(auth):
                self._redirect("/auth/setup")
                return
            if not self._is_authenticated():
                self._redirect("/auth/login")
                return
            if parsed.path == "/status-json":
                qs = parse_qs(parsed.query)
                source_ctx = (qs.get("source", ["local"])[0] or "local").strip()
                self._reply_json(_build_live_snapshot_for_source(source_ctx), 200)
                return
            if parsed.path == "/api/agent-update-status":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                qs = parse_qs(parsed.query)
                peer_id = (qs.get("peer_id", [""])[0] or "").strip()
                session_id = (qs.get("session_id", [""])[0] or "").strip()
                if not peer_id or not session_id:
                    self._reply_json({"error": "Missing peer_id or session_id"}, 400)
                    return
                cfg = load_config()
                if str(cfg.get("peer_role", "")) != "master":
                    self._reply_json({"error": "Master role required"}, 403)
                    return
                data = _fetch_agent_update_status(cfg, peer_id, session_id)
                self._reply_json(data, 200)
                return
            if parsed.path == "/api/agent-diag":
                qs = parse_qs(parsed.query)
                peer_id = (qs.get("peer_id", [""])[0] or "").strip()
                view = (qs.get("view", ["logs"])[0] or "logs").strip().lower()
                log_filter = (qs.get("log_filter", ["all"])[0] or "all").strip().lower()
                log_date = _normalize_log_date((qs.get("log_date", ["all"])[0] or "all").strip().lower())
                log_time_scope = _normalize_log_time_scope((qs.get("log_time_scope", ["all"])[0] or "all").strip().lower())
                log_time_from = _normalize_log_time_hhmm((qs.get("log_time_from", [""])[0] or "").strip())
                log_time_to = _normalize_log_time_hhmm((qs.get("log_time_to", [""])[0] or "").strip())
                if not peer_id:
                    self._reply_json({"error": "Missing peer_id"}, 400)
                    return
                cfg = load_config()
                text = _fetch_agent_diag(
                    cfg,
                    peer_id,
                    view,
                    log_filter,
                    log_date=log_date,
                    log_time_scope=log_time_scope,
                    log_time_from=log_time_from,
                    log_time_to=log_time_to,
                    resolve_timeout=5,
                    fetch_timeout=10,
                )
                self._reply_json({"text": text}, 200)
                return
            if parsed.path == "/guide-image":
                name = (parse_qs(parsed.query).get("name", [""])[0] or "").strip()
                p = get_task_guide_images().get(name)
                if p is None:
                    self._reply_html(_render_setup_html(error=f"Unknown guide image: {name}"), 404)
                    return
                try:
                    self._reply_png(p.read_bytes(), 200)
                except OSError:
                    self._reply_html(_render_setup_html(error=f"Guide image missing in package: {name}"), 500)
                return
            if parsed.path == "/peer/sync-now":
                self._reply_html(_render_setup_html(
                    peering_message=(
                        "Sync uses POST only. Use the Sync now or Sync all agents button on this page "
                        "— do not open this address directly in the browser."
                    ),
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            qs = parse_qs(parsed.query)
            log_filter = (qs.get("log_filter", ["all"])[0] or "all").strip().lower()
            diag_view = (qs.get("diag_view", ["logs"])[0] or "logs").strip().lower()
            ui_view = (qs.get("view", ["overview"])[0] or "overview").strip().lower()
            highlight = (qs.get("highlight", [""])[0] or "").strip().lower()
            source_ctx = (qs.get("source", [qs.get("log_source", ["local"])[0]])[0] or "local").strip()
            diagnose = (qs.get("diagnose", ["0"])[0] or "0").strip().lower() in ("1", "true", "yes")
            log_date = _normalize_log_date((qs.get("log_date", ["all"])[0] or "all").strip().lower())
            log_time_scope = _normalize_log_time_scope((qs.get("log_time_scope", ["all"])[0] or "all").strip().lower())
            log_time_from = _normalize_log_time_hhmm((qs.get("log_time_from", [""])[0] or "").strip())
            log_time_to = _normalize_log_time_hhmm((qs.get("log_time_to", [""])[0] or "").strip())
            if highlight not in ("smart", "storage", "ping", "port", "dns", "backup", "service"):
                highlight = ""
            profile_render = (qs.get("render_profile", ["0"])[0] or "0").strip().lower() in ("1", "true", "yes")
            threading.Thread(target=_maybe_run_autoupdate, daemon=True).start()
            render_started = time.perf_counter()
            if profile_render:
                profiler = cProfile.Profile()
                profiler.enable()
            rendered_html = _render_setup_html(
                    log_filter=log_filter,
                    log_date=log_date,
                    log_time_scope=log_time_scope,
                    log_time_from=log_time_from,
                    log_time_to=log_time_to,
                    diag_view=diag_view,
                    ui_view=ui_view,
                    highlight_channel=highlight,
                    log_source=source_ctx,
                    diagnose_agent=diagnose,
                    ssl_warning=ssl_warning,
                )
            if profile_render:
                profiler.disable()
            render_ms = (time.perf_counter() - render_started) * 1000.0
            extra_headers: List[Tuple[str, str]] = [("X-Render-Ms", f"{render_ms:.1f}")]
            if profile_render:
                extra_headers.append(("X-Render-Profile", "1"))
                try:
                    stats_out = StringIO()
                    pstats.Stats(profiler, stream=stats_out).sort_stats("cumulative").print_stats(25)
                    lines = [ln.strip() for ln in stats_out.getvalue().splitlines() if ln.strip()]
                    append_ui_log(
                        "render-prof | "
                        f"view={ui_view} source={source_ctx or 'local'} diag={diag_view} "
                        f"total_ms={render_ms:.1f}"
                    )
                    for ln in lines[:20]:
                        append_ui_log(f"render-prof | {ln[:220]}")
                except Exception as exc:
                    append_ui_log(f"render-prof | failed to summarize: {type(exc).__name__}: {exc}")
            self._reply_html(rendered_html, extra_headers=extra_headers)

        def do_POST(self) -> None:  # noqa: N802
            _set_request_display_host(self._connected_interface_host())
            if self._redirect_http_to_https():
                return
            if self.path == "/api/peer/push":
                if not self._require_peer_mtls(allow_token_only=True):
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                body, ok_body = self._read_peer_body()
                if not ok_body:
                    self._reply_json({"error": "invalid encrypted payload"}, 400)
                    return
                try:
                    data = json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    self._reply_json({"error": "invalid json"}, 400)
                    return
                peer_id = str(data.get("instance_id", "") or "").strip()
                if not peer_id:
                    self._reply_json({"error": "missing instance_id"}, 400)
                    return
                cfg = load_config()
                peers = cfg.get("peers", [])
                if not isinstance(peers, list):
                    peers = []
                agent_url = str(data.get("callback_url", "") or "").strip()
                found = False
                for p in peers:
                    if str(p.get("instance_id", "")) == peer_id:
                        p["instance_name"] = str(data.get("instance_name", "") or "")
                        p["last_seen"] = int(time.time())
                        p["monitor_count"] = len(data.get("monitors", []))
                        p["version"] = str(data.get("version", "") or "")
                        p["platform"] = str(data.get("platform", "") or "")
                        p["status"] = "online"
                        existing_url = str(p.get("url", "") or "").strip()
                        # Preserve a manually set URL; only auto-fill from callback when unlocked.
                        if agent_url and (not existing_url or not bool(p.get("url_locked", False))):
                            p["url"] = agent_url
                        found = True
                        break
                if not found:
                    append_ui_log(f"peer-push | rejected unregistered agent {peer_id}")
                    self._reply_peer_json(
                        {"error": "peer not registered on master", "rejected": True},
                        403,
                    )
                    return
                data["received_at"] = int(time.time())
                _save_peer_snapshot(peer_id, data)
                cfg["peers"] = peers
                save_config(cfg, reapply_cron=False)
                append_ui_log(f"peer-push | received from {data.get('instance_name', peer_id)} | monitors={len(data.get('monitors', []))}")
                self._reply_peer_json({"status": "ok", "received": True}, 200)
                return
            if self.path == "/api/peer/register":
                if not self._require_peer_mtls(allow_token_only=True):
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                body, ok_body = self._read_peer_body()
                if not ok_body:
                    self._reply_json({"error": "invalid encrypted payload"}, 400)
                    return
                try:
                    data = json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    self._reply_json({"error": "invalid json"}, 400)
                    return
                peer_id = str(data.get("instance_id", "") or "").strip()
                if not peer_id:
                    self._reply_json({"error": "missing instance_id"}, 400)
                    return
                cfg = load_config()
                peers = cfg.get("peers", [])
                if not isinstance(peers, list):
                    peers = []
                found = False
                for p in peers:
                    if str(p.get("instance_id", "")) == peer_id:
                        p["instance_name"] = str(data.get("instance_name", "") or "")
                        p["last_seen"] = int(time.time())
                        p["monitor_count"] = int(data.get("monitor_count", 0) or 0)
                        p["version"] = str(data.get("version", "") or "")
                        p["status"] = "online"
                        if not str(p.get("enrollment", "") or "").strip():
                            p["enrollment"] = "legacy-peer"
                        found = True
                        break
                if not found:
                    peers.append({
                        "instance_id": peer_id,
                        "instance_name": str(data.get("instance_name", "") or ""),
                        "last_seen": int(time.time()),
                        "monitor_count": int(data.get("monitor_count", 0) or 0),
                        "version": str(data.get("version", "") or ""),
                        "status": "online",
                        "role": "agent",
                        "enrollment": "legacy-peer",
                    })
                csr_pem = str(data.get("csr_pem", "") or "").strip()
                signed_cert = ""
                ca_cert = ""
                master_cert = ""
                if csr_pem:
                    ca_key = get_certs_dir() / "ca.key"
                    ca_crt = get_certs_dir() / "ca.crt"
                    if not ca_key.exists() or not ca_crt.exists():
                        ok_ca, msg_ca = _generate_ca(force=False)
                        if not ok_ca:
                            self._reply_json({"error": f"master CA unavailable: {msg_ca}"}, 500)
                            return
                        cfg2 = load_config()
                        inst_id = _get_instance_id(cfg2)
                        _generate_instance_cert(inst_id, cn_prefix="master")
                    signed_pem, sign_msg = _sign_agent_csr(csr_pem, peer_id)
                    if not signed_pem:
                        self._reply_json({"error": f"CSR signing failed: {sign_msg}"}, 500)
                        return
                    signed_cert = signed_pem
                    try:
                        ca_cert = (get_certs_dir() / "ca.crt").read_text(encoding="utf-8")
                    except OSError:
                        ca_cert = ""
                    cfg3 = load_config()
                    m_cert, _, _ = _get_mtls_cert_paths(cfg3)
                    if m_cert:
                        try:
                            master_cert = Path(m_cert).read_text(encoding="utf-8")
                        except OSError:
                            master_cert = ""
                cfg["peers"] = peers
                save_config(cfg, reapply_cron=False)
                append_ui_log(f"peer-register | {data.get('instance_name', peer_id)} registered")
                reply_data: Dict[str, Any] = {"status": "ok", "registered": True}
                if signed_cert and ca_cert:
                    reply_data["signed_cert"] = signed_cert
                    reply_data["ca_cert"] = ca_cert
                    if master_cert:
                        reply_data["master_cert"] = master_cert
                self._reply_peer_json(reply_data, 200)
                return
            if self.path == "/api/peer/create-monitor":
                if not self._require_peer_mtls():
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                body, ok_body = self._read_peer_body()
                if not ok_body:
                    self._reply_json({"error": "invalid encrypted payload"}, 400)
                    return
                try:
                    data = json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    self._reply_json({"error": "invalid json"}, 400)
                    return
                m_name = str(data.get("name", "") or "").strip()
                m_mode = str(data.get("check_mode", "smart") or "smart").strip().lower()
                m_url = str(data.get("kuma_url", "") or "").strip()
                if not m_name:
                    self._reply_json({"error": "missing monitor name"}, 400)
                    return
                cfg = load_config()
                monitors = cfg.get("monitors", [])
                if not isinstance(monitors, list):
                    monitors = []
                if any(str(em.get("name", "")) == m_name for em in monitors):
                    self._reply_json({"error": f"monitor '{m_name}' already exists"}, 409)
                    return
                new_mon: Dict[str, Any] = {"name": m_name, "check_mode": m_mode, "kuma_url": m_url}
                for extra_key in ("probe_host", "probe_port", "dns_name", "dns_server", "service_names", "service_description_filter", "source_platform"):
                    val = str(data.get(extra_key, "") or "").strip()
                    if val:
                        new_mon[extra_key] = val
                monitors.append(new_mon)
                cfg["monitors"] = monitors
                save_config(cfg)
                append_ui_log(f"peer-create-monitor | remote created '{m_name}' mode={m_mode}")
                _trigger_peer_sync_bg(cfg)
                self._reply_peer_json({"status": "ok", "created": m_name}, 201)
                return
            if self.path == "/api/peer/update":
                append_ui_log("peer-update | request received from master")
                try:
                    append_ui_log("peer-update | checking mTLS")
                    if not self._require_peer_mtls(allow_token_only=True):
                        append_ui_log("peer-update | mTLS check failed")
                        return
                    append_ui_log("peer-update | checking token")
                    if not self._verify_peer_token():
                        append_ui_log("peer-update | token verification failed")
                        self._reply_json({"error": "unauthorized"}, 401)
                        return
                    helper = get_update_helper_path()
                    append_ui_log(f"peer-update | helper path: {helper} exists={helper.exists()}")
                    if not helper.exists():
                        append_ui_log("peer-update | update helper not found")
                        self._reply_peer_json({"error": "Update helper not found"}, 400)
                        return
                    append_ui_log("peer-update | starting background update")
                    session_id = _run_agent_update_background()
                    append_ui_log(f"peer-update | started session {session_id}")
                    self._reply_peer_json({"status": "started", "session_id": session_id}, 202)
                except Exception as e:
                    tb = traceback.format_exc()
                    err_msg = f"{type(e).__name__}: {e}"
                    append_ui_log(f"peer-update | error: {err_msg}")
                    append_ui_log(f"peer-update | traceback: {tb}")
                    self._reply_peer_json({"error": err_msg, "traceback": tb[:2000]}, 500)
                return
            if self.path == "/api/peer/clear-logs":
                if not self._require_peer_mtls(allow_token_only=True):
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                clear_ui_log()
                append_ui_log("peer-clear-logs | cleared by master request")
                self._reply_peer_json({"status": "ok", "message": "Remote logs cleared"}, 200)
                return
            if self.path == "/api/peer/monitor-action":
                if not self._require_peer_mtls(allow_token_only=True):
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                body, ok_body = self._read_peer_body()
                if not ok_body:
                    self._reply_json({"error": "invalid encrypted payload"}, 400)
                    return
                try:
                    data = json.loads(body) if body else {}
                except (json.JSONDecodeError, ValueError):
                    self._reply_json({"error": "invalid json"}, 400)
                    return
                action = str(data.get("action", "") or "").strip().lower()
                monitor_name = str(data.get("monitor_name", "") or "").strip()
                triggered_by = str(data.get("triggered_by", "master") or "master").strip().lower()
                if action not in ("run-check", "test-push"):
                    self._reply_peer_json({"error": "unsupported action"}, 400)
                    return
                append_ui_log(
                    f"peer-monitor-action | action={action} | monitor={monitor_name or '(all)'} | triggered_by={triggered_by}"
                )
                if action == "run-check":
                    output = _ui_run_check_now(target_monitor=monitor_name or None, initiated_by="master")
                    message = "Run check executed on agent (triggered by master)."
                else:
                    output = _ui_test_push(target_monitor=monitor_name or None, initiated_by="master")
                    message = "Test push executed on agent (triggered by master)."
                self._reply_peer_json({"status": "ok", "message": message, "output": output}, 200)
                return
            if self.path == "/api/peer/trigger-monitor-action":
                if not self._require_peer_mtls(allow_token_only=True):
                    return
                if not self._verify_peer_token():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                body, ok_body = self._read_peer_body()
                if not ok_body:
                    self._reply_json({"error": "invalid encrypted payload"}, 400)
                    return
                try:
                    data = json.loads(body) if body else {}
                except (json.JSONDecodeError, ValueError):
                    self._reply_json({"error": "invalid json"}, 400)
                    return
                cfg = load_config()
                if str(cfg.get("peer_role", "standalone") or "standalone").lower() != "master":
                    self._reply_peer_json({"error": "master role required"}, 403)
                    return
                peer_id = str(data.get("instance_id", "") or "").strip()
                action = str(data.get("action", "") or "").strip().lower()
                monitor_name = str(data.get("monitor_name", "") or "").strip()
                if not peer_id:
                    self._reply_peer_json({"error": "missing instance_id"}, 400)
                    return
                if action not in ("run-check", "test-push"):
                    self._reply_peer_json({"error": "unsupported action"}, 400)
                    return
                ok_action, summary, output = _trigger_agent_monitor_action(cfg, peer_id, action, monitor_name=monitor_name)
                if ok_action:
                    self._reply_peer_json({"status": "ok", "message": summary, "output": output}, 200)
                else:
                    self._reply_peer_json({"error": summary}, 502)
                return
            if self.path == "/peer/test-connection":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                cfg = load_config()
                test_url_raw, test_token = _peer_agent_test_inputs(form, cfg)
                resolved_url = ""
                if not test_url_raw or not test_token:
                    result = "Missing master host/port or peering token. Enter master host, master port, and token."
                    test_url = ""
                else:
                    resolved_url = _resolve_peer_url_from_stored(test_url_raw, test_token, timeout=4, cfg=cfg)
                    _, target_port = _parse_peer_host_port(test_url_raw, _peer_master_port(cfg))
                    test_url = resolved_url or _peer_direct_base_url(test_url_raw, target_port)
                    result = _peer_test_connection(test_url, test_token) if test_url else "Missing master host/port."
                ok = str(result).strip().lower().startswith("ok")
                if ok and test_url:
                    cfg["peer_master_base_url"] = test_url
                    save_config(cfg, reapply_cron=False)
                diag_lines = [
                    "Action: Test connection to master",
                    f"Result: {'OK' if ok else 'FAILED'}",
                    f"Role: agent (form action)",
                    f"Master target (input): {test_url_raw or '(empty)'}",
                    f"Resolved target URL: {resolved_url or '(probe failed — used direct URL)'}",
                    f"Direct/final URL: {test_url or '(none)'}",
                    f"Token provided: {'yes' if bool(test_token) else 'no'}",
                    f"Result detail: {result}",
                    ("Next action: Run 'Sync now' to push an agent snapshot."
                     if ok else "Next action: Save settings, verify master is reachable from this host (port/firewall), then retry.")
                ]
                ssl_warning = self._ssl_warning_text()
                ui_view = self._view_from_referer()
                self._reply_html(_render_setup_html(
                    peering_message=f"Peer test: {result}",
                    peering_diagnostics="\n".join(diag_lines),
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/save-settings":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                cfg = load_config()
                prev_role = _cfg_peer_role(cfg)
                prev_master_host = str(cfg.get("peer_master_url", "") or "").strip()
                prev_master_port = int(cfg.get("peer_master_port", cfg.get("peer_port", PEER_DEFAULT_PORT)) or PEER_DEFAULT_PORT)
                if _rollout_agent_mode():
                    role = "agent"
                else:
                    role = (form.get("peer_role", [prev_role])[0] or prev_role).strip().lower()
                    if role not in _peer_roles():
                        role = prev_role
                if role != prev_role:
                    if prev_role == "agent" and role != "standalone" and _peer_agent_bound_to_master(cfg):
                        ssl_warning = self._ssl_warning_text()
                        self._reply_html(_render_setup_html(
                            peering_message=(
                                "Cannot change role while this agent is connected to a master. "
                                "Use Disconnect from master first, or switch to Standalone to clear master settings."
                            ),
                            ui_view="settings",
                            ssl_warning=ssl_warning,
                        ))
                        return
                    if prev_role == "master" and _peer_master_has_registered_agents(cfg):
                        ssl_warning = self._ssl_warning_text()
                        self._reply_html(_render_setup_html(
                            peering_message=(
                                "Cannot change role while configured peers exist. "
                                "Remove all agents in Peering cleanup first."
                            ),
                            ui_view="settings",
                            ssl_warning=ssl_warning,
                        ))
                        return
                cfg["peer_role"] = role
                _legacy_port_val = (form.get("peer_port", [""])[0] or "").strip()
                if "peer_master_port" in form or "peer_port" in form:
                    _master_port_val = (form.get("peer_master_port", [_legacy_port_val])[0] or _legacy_port_val or "").strip()
                    _master_port = int(_master_port_val) if _master_port_val and _master_port_val.isdigit() else PEER_DEFAULT_PORT
                    cfg["peer_master_port"] = _master_port if 1 <= _master_port <= 65535 else PEER_DEFAULT_PORT
                if "peer_agent_port" in form or "peer_port" in form:
                    _agent_port_val = (form.get("peer_agent_port", [_legacy_port_val])[0] or _legacy_port_val or "").strip()
                    _agent_port = int(_agent_port_val) if _agent_port_val and _agent_port_val.isdigit() else PEER_DEFAULT_PORT
                    cfg["peer_agent_port"] = _agent_port if 1 <= _agent_port <= 65535 else PEER_DEFAULT_PORT
                    cfg["peer_port"] = cfg["peer_agent_port"]
                if "peer_master_url" in form:
                    _m_raw = (form.get("peer_master_url", [""])[0] or "").strip()
                    cfg["peer_master_url"] = _parse_peer_host_port(_m_raw, _peer_master_port(cfg))[0]
                if "agent_callback_url" in form:
                    _cb_raw = (form.get("agent_callback_url", [""])[0] or "").strip()
                    cfg["agent_callback_url"] = _parse_peer_host_port(_cb_raw, _peer_agent_port(cfg))[0]
                new_master_host = str(cfg.get("peer_master_url", "") or "").strip()
                new_master_port = int(cfg.get("peer_master_port", PEER_DEFAULT_PORT) or PEER_DEFAULT_PORT)
                if new_master_host != prev_master_host or new_master_port != prev_master_port:
                    cfg.pop("peer_master_base_url", None)
                token_val = (form.get("peering_token", [""])[0] or "").strip()
                token_auto_generated = False
                if "peering_token" in form:
                    if token_val:
                        cfg["peering_token"] = token_val
                    elif role == "master":
                        # Auto-generate token when switching to master so it's ready to share
                        existing = str(cfg.get("peering_token", "") or "").strip()
                        switching_to_master = prev_role != "master"
                        if switching_to_master or not existing:
                            cfg["peering_token"] = secrets.token_hex(32)
                            token_auto_generated = True
                inst_id = _get_instance_id(cfg)
                if role == "standalone":
                    _peer_clear_standalone_peering(cfg, prev_role=prev_role)
                save_config(cfg, reapply_cron=False)
                _extra_msg = " Peering token auto-generated." if token_auto_generated else ""
                if role == "standalone" and prev_role != "standalone":
                    _extra_msg += " Master connection settings and stored trust cleared."
                if role == "master" and _openssl_available():
                    ca_path = get_certs_dir() / "ca.crt"
                    if not ca_path.exists():
                        ok_ca, msg_ca = _generate_ca(force=False)
                        if ok_ca:
                            ok_sc, msg_sc = _generate_instance_cert(inst_id, cn_prefix="master")
                            _extra_msg += f" CA auto-generated. {msg_sc}"
                        else:
                            _extra_msg += f" CA generation failed: {msg_ca}"
                elif role == "agent" and cfg.get("peer_master_url") and cfg.get("peering_token"):
                    sec_st = _get_mtls_security_status(cfg)
                    if not sec_st["instance_cert_ok"] and _openssl_available():
                        _extra_msg += " Agent certificate will be requested automatically after master approval."
                append_ui_log(f"peer-settings | saved | role={role} | name={cfg.get('instance_name', '')}")
                diag_lines = [
                    "Action: Save peering settings",
                    "Result: OK",
                    f"Role: {role}",
                    f"Master host: {str(cfg.get('peer_master_url', '') or '(empty)')}",
                    f"Master port: {int(cfg.get('peer_master_port', cfg.get('peer_port', PEER_DEFAULT_PORT)) or PEER_DEFAULT_PORT)}",
                    f"Agent callback port: {int(cfg.get('peer_agent_port', cfg.get('peer_port', PEER_DEFAULT_PORT)) or PEER_DEFAULT_PORT)}",
                    f"Token configured: {'yes' if bool(str(cfg.get('peering_token', '') or '').strip()) else 'no'}",
                    f"Agent callback host: {str(cfg.get('agent_callback_url', '') or '(empty)')}",
                ]
                token_for_probe = str(cfg.get("peering_token", "") or "").strip()
                if role == "agent" and cfg.get("peer_master_url") and token_for_probe:
                    master_probe = _peer_test_connection(
                        _resolve_peer_url_from_stored(
                            str(cfg.get("peer_master_url", "") or ""),
                            token_for_probe,
                            timeout=8,
                        )
                        or str(cfg.get("peer_master_url", "") or ""),
                        token_for_probe,
                    )
                    diag_lines.append(f"Master connectivity: {master_probe.splitlines()[0]}")
                callback_host = str(cfg.get("agent_callback_url", "") or "").strip()
                if callback_host and token_for_probe:
                    callback_probe = _probe_agent_callback_health(
                        callback_host,
                        token_for_probe,
                        default_port=int(cfg.get("peer_agent_port", cfg.get("peer_port", PEER_DEFAULT_PORT)) or PEER_DEFAULT_PORT),
                    )
                    diag_lines.append(f"Agent callback connectivity: {callback_probe}")
                if role == "agent":
                    diag_lines.append("Next action: Run 'Test connection to master' and then 'Sync now'.")
                elif role == "master":
                    diag_lines.append("Next action: Sync agents after callback URLs are configured.")
                else:
                    diag_lines.append("Next action: No peering configured.")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=f"Peering settings saved.{_extra_msg}",
                    peering_diagnostics="\n".join(diag_lines),
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/agent-disconnect-master":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                cfg = load_config()
                ssl_warning = self._ssl_warning_text()
                if str(cfg.get("peer_role", "") or "").lower() != "agent":
                    self._reply_html(_render_setup_html(
                        peering_message="Disconnect is only available when role is Agent.",
                        ui_view="settings",
                        ssl_warning=ssl_warning,
                    ))
                    return
                _peer_agent_release_master_binding(cfg)
                save_config(cfg, reapply_cron=False)
                append_ui_log("peer-settings | agent disconnected from master | trust/sync cleared")
                self._reply_html(_render_setup_html(
                    peering_message="Disconnected from master. You can change role when ready.",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/generate-token":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                cfg = load_config()
                cfg["peering_token"] = secrets.token_hex(32)
                save_config(cfg, reapply_cron=False)
                append_ui_log("peer-settings | new peering token generated")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message="New peering token generated.",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/remove":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                rm_id = (form.get("peer_id", [""])[0] or "").strip()
                ssl_warning = self._ssl_warning_text()
                if not rm_id:
                    self._reply_html(_render_setup_html(
                        peering_message="No instance ID provided.",
                        ui_view="settings",
                        ssl_warning=ssl_warning,
                    ))
                    return
                rm_key = _normalize_peer_instance_id_key(rm_id)
                cfg = load_config()
                peers = [
                    p for p in cfg.get("peers", [])
                    if _normalize_peer_instance_id_key(str(p.get("instance_id", ""))) != rm_key
                ]
                cfg["peers"] = peers
                raw_allow = cfg.get("allow_unknown_update_peers", [])
                if isinstance(raw_allow, list):
                    cfg["allow_unknown_update_peers"] = sorted(
                        str(x or "").strip()
                        for x in raw_allow
                        if str(x or "").strip() and _normalize_peer_instance_id_key(str(x or "").strip()) != rm_key
                    )
                save_config(cfg, reapply_cron=False)
                snapshot_candidates = {rm_id}
                if rm_key and rm_key != rm_id:
                    snapshot_candidates.add(rm_key)
                for snap_id in snapshot_candidates:
                    _clear_file(get_peer_data_dir() / f"{snap_id}.json")
                append_ui_log(f"peer-remove | removed peer {rm_id}")
                self._reply_html(_render_setup_html(
                    peering_message="Peer removed.",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/prune-orphan-snapshots":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                ssl_warning = self._ssl_warning_text()
                cfg = load_config()
                if str(cfg.get("peer_role", "") or "").lower() != "master":
                    self._reply_html(_render_setup_html(
                        peering_message="Orphan snapshot cleanup is only available in master role.",
                        ui_view="settings",
                        ssl_warning=ssl_warning,
                    ))
                    return
                reg = _registered_peer_instance_ids(cfg)
                d = get_peer_data_dir()
                removed = 0
                names: List[str] = []
                if d.exists():
                    for p in sorted(d.glob("*.json")):
                        stem = p.stem
                        if stem not in reg:
                            _clear_file(p)
                            removed += 1
                            names.append(stem)
                raw_allow = cfg.get("allow_unknown_update_peers", [])
                allow_changed = False
                if isinstance(raw_allow, list):
                    allow_norm = sorted({str(x or "").strip() for x in raw_allow if str(x or "").strip()})
                    new_allow = sorted(x for x in allow_norm if x in reg)
                    if new_allow != allow_norm:
                        cfg["allow_unknown_update_peers"] = new_allow
                        allow_changed = True
                if allow_changed:
                    save_config(cfg, reapply_cron=False)
                msg = f"Removed {removed} orphan snapshot file(s)."
                if names:
                    show = names[:5]
                    msg += " (" + ", ".join(show) + ("…" if len(names) > 5 else "") + ")"
                append_ui_log(f"peer-cleanup | prune orphan snapshots | removed_files={removed}")
                self._reply_html(_render_setup_html(
                    peering_message=msg,
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/dedupe-peers":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                ssl_warning = self._ssl_warning_text()
                cfg = load_config()
                if str(cfg.get("peer_role", "") or "").lower() != "master":
                    self._reply_html(_render_setup_html(
                        peering_message="Peer deduplication is only available in master role.",
                        ui_view="settings",
                        ssl_warning=ssl_warning,
                    ))
                    return
                old_peers = cfg.get("peers", [])
                if not isinstance(old_peers, list):
                    old_peers = []
                new_peers = _dedupe_peers_by_instance_id(old_peers)
                if new_peers == old_peers:
                    msg = "No duplicate peer rows found."
                else:
                    cfg["peers"] = new_peers
                    save_config(cfg, reapply_cron=False)
                    msg = f"Deduplicated peer list ({len(old_peers)} → {len(new_peers)} entries)."
                append_ui_log(f"peer-cleanup | dedupe peers | {msg}")
                self._reply_html(_render_setup_html(
                    peering_message=msg,
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/sync-now":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                ssl_warning = self._ssl_warning_text()
                try:
                    cfg = load_config()
                    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
                    master_url = ""
                    if role == "agent":
                        result = _peer_push_to_master(cfg)
                        master_url, _ = _peer_master_base_url(cfg, timeout=4)
                        cfg["last_peer_sync"] = int(time.time())
                        cfg["last_peer_sync_result"] = result
                        save_config(cfg, reapply_cron=False)
                        append_ui_log(f"peer-sync | manual agent push: {result}")
                    elif role == "master":
                        result = _peer_sync_from_master(cfg)
                        cfg = load_config()
                        cfg["last_peer_sync_result"] = result
                        save_config(cfg, reapply_cron=False)
                        append_ui_log(f"peer-sync | manual master sync: {result}")
                    else:
                        result = "Standalone mode - no sync needed."
                    diag_lines = [
                        "Action: Sync now",
                        f"Result: {'OK' if 'failed' not in str(result).lower() and 'error' not in str(result).lower() else 'FAILED'}",
                        f"Role: {role}",
                        f"Master host: {str(cfg.get('peer_master_url', '') or '(empty)')}",
                        f"Master port: {int(cfg.get('peer_master_port', cfg.get('peer_port', PEER_DEFAULT_PORT)) or PEER_DEFAULT_PORT)}",
                        f"Master base URL: {master_url or '(not resolved)'}",
                    f"Agent callback port: {int(cfg.get('peer_agent_port', cfg.get('peer_port', PEER_DEFAULT_PORT)) or PEER_DEFAULT_PORT)}",
                        f"Token configured: {'yes' if bool(str(cfg.get('peering_token', '') or '').strip()) else 'no'}",
                        f"Agent callback host: {str(cfg.get('agent_callback_url', '') or '(empty)')}",
                        f"Result detail: {result}",
                        ("Next action: Open master overview and verify this agent snapshot appears."
                         if role == "agent" else "Next action: Verify role and use the matching peering action.")
                    ]
                except Exception as e:
                    append_ui_log(f"peer-sync | manual error: {type(e).__name__}: {e}")
                    self._reply_html(_render_setup_html(
                        peering_message=f"Sync failed: {type(e).__name__}: {e}",
                        peering_diagnostics=(
                            "Action: Sync now\n"
                            "Result: FAILED\n"
                            f"Role: {str(load_config().get('peer_role', 'standalone') or 'standalone').lower()}\n"
                            f"Result detail: {type(e).__name__}: {e}\n"
                            "Next action: Run 'Test connection to master' and verify token/host/port."
                        ),
                        ui_view="settings",
                        ssl_warning=ssl_warning,
                    ))
                    return
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=f"Sync result: {result}",
                    peering_diagnostics="\n".join(diag_lines),
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/sync-one":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                sync_pid = (form.get("peer_id", [""])[0] or "").strip()
                cfg = load_config()
                token = str(cfg.get("peering_token", "") or "").strip()
                peers = cfg.get("peers", [])
                target_p = None
                for p in peers:
                    if str(p.get("instance_id", "")) == sync_pid:
                        target_p = p
                        break
                if not target_p or not token:
                    result = "Peer not found or no token."
                else:
                    pname = str(target_p.get("instance_name", "") or sync_pid[:8])
                    p_url_raw = str(target_p.get("url", "") or "").strip().rstrip("/")
                    if not p_url_raw:
                        result = f"{pname}: no URL configured."
                    else:
                        p_url = _resolve_peer_url_from_stored(p_url_raw, token, timeout=10)
                        if not p_url:
                            result = f"{pname}: cannot reach {p_url_raw}."
                        else:
                            try:
                                t0 = time.time()
                                status, resp_body = _peer_http_request(p_url, token, "GET", "/api/peer/snapshot", timeout=10)
                                latency_ms = round((time.time() - t0) * 1000)
                                if status < 300:
                                    target_p["last_seen"] = int(time.time())
                                    target_p["status"] = "online"
                                    target_p["latency_ms"] = latency_ms
                                    try:
                                        snap = json.loads(resp_body)
                                        target_p["monitor_count"] = len(snap.get("monitors", []))
                                        target_p["instance_name"] = str(snap.get("instance_name", "") or pname)
                                        target_p["version"] = str(snap.get("version", "") or "")
                                        snap["received_at"] = int(time.time())
                                        _save_peer_snapshot(sync_pid, snap)
                                    except (json.JSONDecodeError, ValueError):
                                        pass
                                    result = f"{pname}: online ({latency_ms} ms)"
                                else:
                                    target_p["status"] = "offline"
                                    target_p["latency_ms"] = None
                                    result = f"{pname}: HTTP {status}"
                            except Exception as e:
                                target_p["status"] = "offline"
                                target_p["latency_ms"] = None
                                result = f"{pname}: {type(e).__name__}: {e}"
                    cfg["peers"] = peers
                    cfg["last_peer_sync"] = int(time.time())
                    save_config(cfg, reapply_cron=False)
                append_ui_log(f"peer-sync-one | {sync_pid} | {result}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=f"Sync: {result}",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/create-remote-monitor":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                target_peer = (form.get("target_peer", [""])[0] or "").strip()
                m_name = (form.get("monitor_name", [""])[0] or "").strip()
                m_mode = (form.get("check_mode", ["smart"])[0] or "smart").strip().lower()
                m_url = (form.get("kuma_url", [""])[0] or "").strip()
                mon_cfg: Dict[str, Any] = {"name": m_name, "check_mode": m_mode, "kuma_url": m_url}
                for extra in ("probe_host", "probe_port", "dns_name", "dns_server", "service_names", "service_description_filter"):
                    v = (form.get(extra, [""])[0] or "").strip()
                    if v:
                        mon_cfg[extra] = v
                cfg = load_config()
                if target_peer and len(target_peer) < 4:
                    ssl_warning = self._ssl_warning_text()
                    self._reply_html(_render_setup_html(
                        peering_message=f"Invalid target peer '{target_peer}'.",
                        ui_view="settings",
                        ssl_warning=ssl_warning,
                    ))
                    return
                result = _peer_create_remote_monitor(cfg, target_peer, mon_cfg)
                append_ui_log(f"peer-create-remote | peer={target_peer} monitor={m_name} result={result}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=result,
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/update-unknown-policy":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                upd_id = (form.get("peer_id", [""])[0] or "").strip()
                allow_unknown_update = (form.get("allow_unknown_update", ["0"])[0] or "0").strip() in ("1", "true", "yes", "on")
                if not upd_id:
                    ssl_warning = self._ssl_warning_text()
                    self._reply_html(_render_setup_html(error="Missing peer_id.", ui_view="settings", ssl_warning=ssl_warning))
                    return
                cfg = load_config()
                _set_unknown_update_override(cfg, upd_id, allow_unknown_update)
                save_config(cfg, reapply_cron=False)
                msg = "Unknown-platform updates enabled for this agent." if allow_unknown_update else "Unknown-platform updates blocked for this agent."
                append_ui_log(f"peer-update-unknown-policy | {upd_id} allow={allow_unknown_update}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=msg,
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/update-peer-url":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                upd_id = (form.get("peer_id", [""])[0] or "").strip()
                upd_url_raw = (form.get("peer_url", [""])[0] or "").strip()
                upd_url = f"{_parse_peer_host_port(upd_url_raw)[0]}:{_parse_peer_host_port(upd_url_raw)[1]}" if upd_url_raw else ""
                cfg = load_config()
                peers = cfg.get("peers", [])
                if not isinstance(peers, list):
                    peers = []
                updated = False
                for p in peers:
                    if str(p.get("instance_id", "")) == upd_id:
                        p["url"] = upd_url
                        p["url_locked"] = bool(upd_url)
                        updated = True
                        break
                cfg["peers"] = peers
                save_config(cfg, reapply_cron=False)
                token = str(cfg.get("peering_token", "") or "").strip()
                probe_msg = ""
                if updated and upd_url and token:
                    probe_msg = _probe_agent_callback_health(upd_url, token)
                msg = "Peer URL updated." if updated else "Peer not found."
                if probe_msg:
                    msg = f"{msg} {probe_msg}"
                append_ui_log(f"peer-update-url | {upd_id} -> {upd_url}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=msg,
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/add-agent":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                a_name = (form.get("agent_name", [""])[0] or "").strip()
                a_id = (form.get("agent_id", [""])[0] or "").strip()
                a_url = (form.get("agent_url", [""])[0] or "").strip()
                if not a_id:
                    ssl_warning = self._ssl_warning_text()
                    self._reply_html(_render_setup_html(error="Agent Instance ID is required.", ui_view="settings", ssl_warning=ssl_warning))
                    return
                cfg = load_config()
                peers = cfg.get("peers", [])
                if not isinstance(peers, list):
                    peers = []
                if any(str(p.get("instance_id", "")) == a_id for p in peers):
                    ssl_warning = self._ssl_warning_text()
                    self._reply_html(_render_setup_html(error=f"Agent '{a_id}' already exists.", ui_view="settings", ssl_warning=ssl_warning))
                    return
                new_peer: Dict[str, Any] = {
                    "instance_id": a_id,
                    "instance_name": a_name or a_id[:8],
                    "last_seen": 0,
                    "monitor_count": 0,
                    "status": "offline",
                    "role": "agent",
                    "enrollment": "legacy-peer",
                }
                if a_url:
                    _ah, _ap = _parse_peer_host_port(a_url)
                    new_peer["url"] = f"{_ah}:{_ap}" if _ah else a_url
                    new_peer["url_locked"] = True
                peers.append(new_peer)
                cfg["peers"] = peers
                save_config(cfg, reapply_cron=False)
                append_ui_log(f"peer-add | manually added agent {a_name or a_id[:8]} ({a_id})")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=f"Agent '{a_name or a_id[:8]}' added. It will sync when it pushes data or you click Sync.",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/generate-ca":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                ok, msg = _generate_ca(force=False)
                cfg = load_config()
                inst_id = _get_instance_id(cfg)
                if ok:
                    ok2, msg2 = _generate_instance_cert(inst_id, cn_prefix="master")
                    if ok2:
                        msg += f" Server cert: {msg2}"
                    else:
                        msg += f" Server cert failed: {msg2}"
                append_ui_log(f"mtls | CA generate: {msg}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=msg,
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/generate-server-cert":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                cfg = load_config()
                inst_id = _get_instance_id(cfg)
                ok, msg = _generate_instance_cert(inst_id, cn_prefix="master")
                append_ui_log(f"mtls | server cert generate: {msg}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=msg + " Restart the addon for TLS to take effect.",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/request-cert":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                cfg = load_config()
                master_url, _ = _peer_master_base_url(cfg, timeout=4)
                result = _agent_request_cert(cfg)
                append_ui_log(f"mtls | agent cert request: {result}")
                ssl_warning = self._ssl_warning_text()
                cert_ok = str(result).strip().lower().startswith("certificate signed")
                token_only_ok = "token-only peering still works" in str(result).lower()
                diag_lines = [
                    "Action: Request certificate from master",
                    f"Result: {'OK' if cert_ok else ('OPTIONAL' if token_only_ok else 'FAILED')}",
                    f"Master base URL: {str(cfg.get('peer_master_base_url', '') or master_url or '(not resolved)')}",
                    f"Detail: {result}",
                    ("Next action: Run 'Sync now' to push telemetry with mTLS."
                     if cert_ok else (
                         "Next action: Hosted master — skip cert; run Test connection then Sync now."
                         if token_only_ok else
                         "Next action: Run Test connection. If timeout, set HOSTED_BIND_IP=0.0.0.0 on master and redeploy."
                     ))
                ]
                self._reply_html(_render_setup_html(
                    peering_message=result,
                    peering_diagnostics="\n".join(diag_lines),
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            if self.path == "/peer/revoke-agent-cert":
                if not self._is_authenticated():
                    self._reply_json({"error": "unauthorized"}, 401)
                    return
                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                revoke_id = (form.get("agent_id", [""])[0] or "").strip()
                if revoke_id:
                    _revoke_agent_cert(revoke_id)
                    append_ui_log(f"mtls | revoked cert for {revoke_id}")
                ssl_warning = self._ssl_warning_text()
                self._reply_html(_render_setup_html(
                    peering_message=f"Certificate revoked for agent {revoke_id}." if revoke_id else "No agent ID provided.",
                    ui_view="settings",
                    ssl_warning=ssl_warning,
                ))
                return
            auth_routes = (
                "/auth/setup",
                "/auth/setup/verify",
                "/auth/login",
                "/auth/verify-2fa",
                "/auth/recovery",
                "/auth/logout",
                "/auth/regenerate-recovery",
                "/auth/rotate-totp",
                "/auth/change-password",
                "/auth/import",
                "/auth/export-backup",
            )
            auth = _load_auth_state()
            ssl_warning = self._ssl_warning_text()
            ui_view, diag_view, log_filter, log_source, log_date, log_time_scope, log_time_from, log_time_to = self._resolve_ui_context()
            if self.path in auth_routes:
                content_type = (self.headers.get("Content-Type", "") or "").lower()
                import_file_json = ""
                if self.path == "/auth/import" and "multipart/form-data" in content_type and cgi is not None:
                    fs = cgi.FieldStorage(
                        fp=self.rfile,
                        headers=self.headers,
                        environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": self.headers.get("Content-Type", "")},
                        keep_blank_values=True,
                    )
                    raw_payload = fs.getvalue("import_payload")
                    if isinstance(raw_payload, bytes):
                        raw_payload = raw_payload.decode("utf-8", errors="ignore")
                    bk = fs.getvalue("backup_key")
                    if isinstance(bk, bytes):
                        bk = bk.decode("utf-8", errors="ignore")
                    form = {"import_payload": [str(raw_payload or "")], "backup_key": [str(bk or "")]}
                    for _ctx in ("ui_view", "diag_view", "log_filter", "log_date", "log_time_scope", "log_time_from", "log_time_to", "source", "log_source"):
                        if _ctx in fs:
                            try:
                                _v = fs.getvalue(_ctx)
                                if isinstance(_v, bytes):
                                    _v = _v.decode("utf-8", errors="ignore")
                                form[_ctx] = [str(_v or "")]
                            except Exception:
                                pass
                    if "import_file" in fs:
                        up = fs["import_file"]
                        if getattr(up, "file", None):
                            try:
                                data = up.file.read(2 * 1024 * 1024)  # 2MB safety limit
                            except Exception:
                                data = b""
                            if isinstance(data, bytes):
                                import_file_json = data.decode("utf-8", errors="ignore").strip()
                else:
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                ui_view, diag_view, log_filter, log_source, log_date, log_time_scope, log_time_from, log_time_to = self._resolve_ui_context(form)
                if self.path == "/auth/logout":
                    flag_path = _get_autoupdate_on_logout_flag_path()
                    if flag_path.exists():
                        try:
                            flag_path.unlink(missing_ok=True)
                        except OSError:
                            pass
                        threading.Thread(
                            target=lambda: _maybe_run_autoupdate(defer_if_user_logged_in=False),
                            daemon=True,
                        ).start()
                    self._redirect(
                        "/auth/login",
                        extra_headers=[
                            ("Set-Cookie", self._clear_cookie_header(AUTH_COOKIE_NAME)),
                            ("Set-Cookie", self._clear_cookie_header(AUTH_CHALLENGE_COOKIE_NAME)),
                        ],
                    )
                    return
                if self.path == "/auth/setup":
                    if _auth_initialized(auth):
                        self._redirect("/auth/login")
                        return
                    ok, dep_msg = _totp_available()
                    if not ok:
                        self._reply_html(_render_auth_setup_page(error=dep_msg, ssl_warning=ssl_warning))
                        return
                    pwd = (form.get("password", [""])[0] or "").strip()
                    pwd2 = (form.get("password_confirm", [""])[0] or "").strip()
                    if len(pwd) < 10:
                        self._reply_html(_render_auth_setup_page(error="Password must be at least 10 characters.", ssl_warning=ssl_warning))
                        return
                    if pwd != pwd2:
                        self._reply_html(_render_auth_setup_page(error="Password confirmation does not match.", ssl_warning=ssl_warning))
                        return
                    pending = _create_pending_setup(pwd)
                    self._reply_html(
                        _render_auth_setup_page(
                            verify={
                                "setup_id": pending["setup_id"],
                                "totp_secret": pending["totp_secret"],
                                "qr_data_uri": pending["qr_data_uri"],
                            },
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/auth/setup/verify":
                    if _auth_initialized(auth):
                        self._redirect("/auth/login")
                        return
                    setup_id = (form.get("setup_id", [""])[0] or "").strip()
                    token = (form.get("token", [""])[0] or "").strip()
                    pending_row = _get_pending_setup(setup_id)
                    if not pending_row:
                        self._reply_html(
                            _render_auth_setup_page(
                                error="Setup session expired. Enter your password again.",
                                ssl_warning=ssl_warning,
                            )
                        )
                        return
                    if not _verify_totp_token(str(pending_row.get("totp_secret", "")), token):
                        self._reply_html(
                            _render_auth_setup_page(
                                verify={
                                    "setup_id": setup_id,
                                    "totp_secret": pending_row.get("totp_secret", ""),
                                    "qr_data_uri": pending_row.get("qr_data_uri", ""),
                                },
                                error="Invalid authenticator code.",
                                ssl_warning=ssl_warning,
                            )
                        )
                        return
                    pending_row = _pop_pending_setup(setup_id)
                    if not pending_row:
                        self._reply_html(
                            _render_auth_setup_page(
                                error="Setup session expired. Enter your password again.",
                                ssl_warning=ssl_warning,
                            )
                        )
                        return
                    recovery_codes = list(pending_row.get("recovery_codes", []) or [])
                    auth["auth_initialized"] = True
                    auth["password_hash"] = generate_password_hash(str(pending_row.get("password", "")))
                    auth["totp_secret"] = str(pending_row.get("totp_secret", ""))
                    auth["recovery_hashes"] = _issue_recovery_hashes(recovery_codes)
                    auth["failed_attempts"] = 0
                    auth["lockout_until"] = 0
                    _save_auth_state(auth)
                    self._reply_html(
                        _render_auth_setup_page(
                            recovery={"recovery_codes": recovery_codes},
                            ssl_warning=ssl_warning,
                        )
                    )
                    append_ui_log("auth-setup | initialized admin auth + 2fa")
                    return
                if self.path == "/auth/login":
                    if not _auth_initialized(auth):
                        self._redirect("/auth/setup")
                        return
                    locked, wait_sec = _is_locked(auth)
                    if locked:
                        self._reply_html(_render_auth_login_page(error=_lockout_message(wait_sec), ssl_warning=ssl_warning))
                        return
                    pwd = (form.get("password", [""])[0] or "").strip()
                    if not check_password_hash(str(auth.get("password_hash", "")), pwd):
                        _register_auth_failure(auth)
                        _append_login_event(auth, self._client_source_ip(), "failed-password")
                        _save_auth_state(auth)
                        self._reply_html(_render_auth_login_page(error=_invalid_password_message(auth), ssl_warning=ssl_warning))
                        return
                    _register_auth_success(auth)
                    challenge = issue_challenge_token(str(auth.get("session_secret", "")))
                    self._redirect(
                        "/auth/verify-2fa",
                        extra_headers=[("Set-Cookie", self._cookie_header(AUTH_CHALLENGE_COOKIE_NAME, challenge, AUTH_CHALLENGE_TTL_SEC))],
                    )
                    return
                if self.path == "/auth/verify-2fa":
                    if not self._has_valid_challenge():
                        self._redirect("/auth/login")
                        return
                    token = (form.get("token", [""])[0] or "").strip()
                    if not _verify_totp_token(str(auth.get("totp_secret", "")), token):
                        _register_auth_failure(auth)
                        _append_login_event(auth, self._client_source_ip(), "failed-2fa")
                        _save_auth_state(auth)
                        self._reply_html(_render_auth_verify_page(error="Invalid authenticator code.", ssl_warning=ssl_warning))
                        return
                    _register_auth_success(auth)
                    auth["last_login_ip"] = self._client_source_ip()
                    auth["last_login_at"] = int(time.time())
                    _append_login_event(auth, auth["last_login_ip"], "success-2fa")
                    _save_auth_state(auth)
                    sess = issue_session_token(str(auth.get("session_secret", "")))
                    self._redirect(
                        "/",
                        extra_headers=[
                            ("Set-Cookie", self._cookie_header(AUTH_COOKIE_NAME, sess, AUTH_SESSION_TTL_SEC)),
                            ("Set-Cookie", self._clear_cookie_header(AUTH_CHALLENGE_COOKIE_NAME)),
                        ],
                    )
                    return
                if self.path == "/auth/recovery":
                    if not self._has_valid_challenge():
                        self._redirect("/auth/login")
                        return
                    code = (form.get("recovery_code", [""])[0] or "").strip()
                    if not _consume_recovery_code(auth, code):
                        _register_auth_failure(auth)
                        _append_login_event(auth, self._client_source_ip(), "failed-recovery")
                        _save_auth_state(auth)
                        self._reply_html(_render_auth_recovery_page(error="Invalid or already used recovery code.", ssl_warning=ssl_warning))
                        return
                    _register_auth_success(auth)
                    auth["last_login_ip"] = self._client_source_ip()
                    auth["last_login_at"] = int(time.time())
                    _append_login_event(auth, auth["last_login_ip"], "success-recovery")
                    _save_auth_state(auth)
                    sess = issue_session_token(str(auth.get("session_secret", "")))
                    self._redirect(
                        "/",
                        extra_headers=[
                            ("Set-Cookie", self._cookie_header(AUTH_COOKIE_NAME, sess, AUTH_SESSION_TTL_SEC)),
                            ("Set-Cookie", self._clear_cookie_header(AUTH_CHALLENGE_COOKIE_NAME)),
                        ],
                    )
                    append_ui_log("auth-login | recovery code consumed")
                    return
                if self.path == "/auth/regenerate-recovery":
                    if not self._is_authenticated():
                        self._redirect("/auth/login")
                        return
                    new_codes = _generate_recovery_codes()
                    auth["recovery_hashes"] = _issue_recovery_hashes(new_codes)
                    _save_auth_state(auth)
                    output = "New one-time recovery codes (shown once):\n" + "\n".join(new_codes)
                    self._reply_html(
                        _render_setup_html(
                            security_message="Recovery codes regenerated",
                            security_output=output,
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        )
                    )
                    append_ui_log("auth-security | recovery codes regenerated")
                    return
                if self.path == "/auth/rotate-totp":
                    if not self._is_authenticated():
                        self._redirect("/auth/login")
                        return
                    token = (form.get("token", [""])[0] or "").strip()
                    if not _verify_totp_token(str(auth.get("totp_secret", "")), token):
                        self._reply_html(_render_setup_html(error="Invalid current TOTP code for rotation.", ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    ok, dep_msg = _totp_available()
                    if not ok:
                        self._reply_html(_render_setup_html(error=dep_msg, ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    totp_secret = _generate_totp_secret()
                    new_codes = _generate_recovery_codes()
                    auth["totp_secret"] = totp_secret
                    auth["recovery_hashes"] = _issue_recovery_hashes(new_codes)
                    _save_auth_state(auth)
                    uri = _build_totp_uri(totp_secret, issuer_name=PRODUCT_NAME)
                    qr = _build_qr_data_uri(uri)
                    out = "TOTP secret rotated.\nNew recovery codes (shown once):\n" + "\n".join(new_codes)
                    if qr:
                        out += "\n\nQR data URI generated (displayed on auth setup pages)."
                    self._reply_html(
                        _render_setup_html(
                            security_message="Security credentials rotated",
                            security_output=out,
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        )
                    )
                    append_ui_log("auth-security | totp secret rotated")
                    return
                if self.path == "/auth/change-password":
                    if not self._is_authenticated():
                        self._redirect("/auth/login")
                        return
                    cur = (form.get("current_password", [""])[0] or "").strip()
                    newp = (form.get("new_password", [""])[0] or "").strip()
                    conf = (form.get("new_password_confirm", [""])[0] or "").strip()
                    if not check_password_hash(str(auth.get("password_hash", "")), cur):
                        self._reply_html(_render_setup_html(error="Current password is incorrect.", ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    if len(newp) < 10:
                        self._reply_html(_render_setup_html(error="New password must be at least 10 characters.", ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    if newp != conf:
                        self._reply_html(_render_setup_html(error="New password confirmation does not match.", ui_view=ui_view, ssl_warning=ssl_warning))
                        return
                    auth["password_hash"] = generate_password_hash(newp)
                    _save_auth_state(auth)
                    append_ui_log("auth-security | password updated")
                    self._reply_html(_render_setup_html(security_message="Password updated successfully.", ui_view=ui_view, ssl_warning=ssl_warning))
                    return
                if self.path == "/auth/export-backup":
                    if not self._is_authenticated():
                        self._redirect("/auth/login")
                        return
                    backup_key = (form.get("backup_key", [""])[0] or "").strip()
                    if len(backup_key) < 12:
                        self._reply_html(_render_setup_html(
                            export_backup_error="Encryption key must be at least 12 characters. Save this key securely; you need it to restore.",
                            ui_view="settings",
                            ssl_warning=ssl_warning,
                        ))
                        return
                    cfg = load_config()
                    auth_state = _load_auth_state()
                    payload = {
                        "config": cfg,
                        "auth": auth_state,
                        "exported_at": int(time.time()),
                        "v": 1,
                    }
                    plaintext = json.dumps(payload)
                    try:
                        enc = _encrypt_backup(plaintext, backup_key)
                    except Exception as e:
                        self._reply_html(_render_setup_html(
                            export_backup_error=f"Encryption failed: {type(e).__name__}: {e}",
                            ui_view="settings",
                            ssl_warning=ssl_warning,
                        ))
                        return
                    result = json.dumps({"v": 1, "enc": enc, "exported_at": payload["exported_at"]})
                    append_ui_log("auth-security | full encrypted backup exported")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Disposition", 'attachment; filename="unix-monitor-backup.enc.json"')
                    self.send_header("Content-Length", str(len(result.encode("utf-8"))))
                    self.end_headers()
                    self.wfile.write(result.encode("utf-8"))
                    return
                if self.path == "/auth/import":
                    if not self._is_authenticated():
                        self._redirect("/auth/login")
                        return
                    raw = (form.get("import_payload", [""])[0] or "").strip()
                    if not raw and import_file_json:
                        raw = import_file_json
                    if not raw:
                        self._reply_html(_render_setup_html(import_backup_error="Import payload is empty. Paste JSON or choose a JSON file.", ui_view="settings", ssl_warning=ssl_warning))
                        return
                    try:
                        parsed = json.loads(raw)
                    except json.JSONDecodeError:
                        self._reply_html(_render_setup_html(import_backup_error="Import payload is not valid JSON.", ui_view="settings", ssl_warning=ssl_warning))
                        return
                    if not isinstance(parsed, dict):
                        self._reply_html(_render_setup_html(import_backup_error="Import payload must be a JSON object.", ui_view="settings", ssl_warning=ssl_warning))
                        return
                    enc_blob = str(parsed.get("enc", "") or "").strip()
                    if enc_blob:
                        backup_key = (form.get("backup_key", [""])[0] or "").strip()
                        if not backup_key:
                            self._reply_html(_render_setup_html(
                                import_backup_error="Encrypted backup requires the decryption key.",
                                ui_view="settings",
                                ssl_warning=ssl_warning,
                            ))
                            return
                        dec = _decrypt_backup(enc_blob, backup_key)
                        if dec is None:
                            self._reply_html(_render_setup_html(
                                import_backup_error="Decryption failed. Wrong key or corrupted backup.",
                                ui_view="settings",
                                ssl_warning=ssl_warning,
                            ))
                            return
                        try:
                            payload = json.loads(dec)
                        except json.JSONDecodeError:
                            self._reply_html(_render_setup_html(import_backup_error="Decrypted backup is not valid JSON.", ui_view="settings", ssl_warning=ssl_warning))
                            return
                    else:
                        payload = parsed
                    cfg_in = payload.get("config")
                    auth_in = payload.get("auth")
                    if isinstance(cfg_in, dict):
                        save_config(cfg_in, reapply_cron=False)
                    if isinstance(auth_in, dict):
                        if not str(auth_in.get("session_secret", "")).strip():
                            auth_in["session_secret"] = secrets.token_hex(32)
                        _save_auth_state(auth_in)
                    append_ui_log("auth-security | settings import applied")
                    self._redirect(
                        "/auth/login",
                        extra_headers=[
                            ("Set-Cookie", self._clear_cookie_header(AUTH_COOKIE_NAME)),
                            ("Set-Cookie", self._clear_cookie_header(AUTH_CHALLENGE_COOKIE_NAME)),
                        ],
                    )
                    return

            if not _auth_initialized(auth):
                self._redirect("/auth/setup")
                return
            if not self._is_authenticated():
                self._redirect("/auth/login")
                return
            if self.path not in (
                "/settings/save-instance-name",
                "/settings/save-ui-bind",
                "/settings/save-internet-check",
                "/settings/save-autoupdate",
                "/settings/save-update-from-main",
                "/settings/request-autoupdate-on-logout",
                "/settings/recheck-updates",
                "/save",
                "/run-check",
                "/run-check-monitor",
                "/test-push",
                "/test-push-monitor",
                "/run-scheduled-now",
                "/repair-automation",
                "/automation-status",
                "/open-create",
                "/open-setup-popup",
                "/edit-monitor",
                "/delete-monitor",
                "/clear-logs",
                "/clear-logs-remote",
                "/clear-task-status",
                "/clear-cache",
                "/clear-history",
                "/clear-system-cache",
                "/check-elevated",
                "/auto-create-task",
                "/danger-restart",
                "/danger-reset",
                "/self-update",
                "/self-rollback",
                "/agent-update",
            ):
                self._reply_html(_render_setup_html(error="Unsupported endpoint"), 404)
                return
            try:
                if self.path == "/settings/save-instance-name":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    instance_name = (form.get("instance_name", [""])[0] or "").strip()
                    cfg = load_config()
                    cfg["instance_name"] = instance_name
                    save_config(cfg, reapply_cron=False)
                    append_ui_log(f"settings | instance name saved: {instance_name or '-'}")
                    self._reply_html(_render_setup_html(
                        security_message="Instance name saved.",
                        ui_view="settings",
                        ssl_warning=ssl_warning,
                    ))
                    return
                if self.path == "/settings/save-ui-bind":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    cfg = load_config()
                    selected_host = _normalize_ui_bind_host(form.get("ui_bind_host", [cfg.get("ui_bind_host", "0.0.0.0")])[0], _list_system_ips())
                    selected_port = _normalize_ui_bind_port(form.get("ui_bind_port", [cfg.get("ui_bind_port", 8787)])[0])
                    cfg["ui_bind_host"] = selected_host
                    cfg["ui_bind_port"] = selected_port
                    save_config(cfg, reapply_cron=False)
                    bind_desc = (
                        "all interfaces (0.0.0.0)"
                        if selected_host == "0.0.0.0"
                        else ("localhost only (127.0.0.1)" if selected_host == "127.0.0.1" else selected_host)
                    )
                    append_ui_log(f"settings | web ui bind saved host={selected_host} port={selected_port}")
                    self._reply_html(_render_setup_html(
                        security_message=f"Web UI binding saved: {bind_desc}:{selected_port}. Restart UI/service to apply.",
                        ui_view="settings",
                        ssl_warning=ssl_warning,
                    ))
                    return
                if self.path == "/settings/save-internet-check":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    cfg = load_config()
                    mode = _normalize_internet_check_mode(form.get("internet_check_mode", [cfg.get("internet_check_mode", "tcp-connect")])[0])
                    port_profile = _normalize_internet_check_port_profile(form.get("internet_check_port_profile", [cfg.get("internet_check_port_profile", "dns")])[0])
                    custom_port = _normalize_internet_check_custom_port(form.get("internet_check_custom_port", [cfg.get("internet_check_custom_port", 53)])[0])
                    timeout_ms = _normalize_internet_check_timeout_ms(form.get("internet_check_timeout_ms", [cfg.get("internet_check_timeout_ms", 1500)])[0])
                    targets = _internet_check_targets_display(
                        _parse_internet_check_targets(
                            form.get("internet_check_targets", [cfg.get("internet_check_targets", "")])[0],
                            port_profile=port_profile,
                            custom_port=custom_port,
                        )
                    )
                    dns_servers = _internet_check_targets_display(
                        _parse_internet_check_targets(
                            form.get("internet_check_dns_servers", [cfg.get("internet_check_dns_servers", "")])[0],
                            port_profile="dns",
                            custom_port=53,
                        )
                    )
                    cfg["internet_check_mode"] = mode
                    cfg["internet_check_port_profile"] = port_profile
                    cfg["internet_check_custom_port"] = custom_port
                    cfg["internet_check_timeout_ms"] = timeout_ms
                    cfg["internet_check_targets"] = targets
                    cfg["internet_check_dns_servers"] = dns_servers
                    save_config(cfg, reapply_cron=False)
                    append_ui_log(
                        f"settings | internet check saved mode={mode} port_profile={port_profile} "
                        f"custom_port={custom_port} timeout_ms={timeout_ms} targets={targets} dns_servers={dns_servers}"
                    )
                    self._reply_html(_render_setup_html(
                        security_message=(
                            f"Internet check settings saved: mode={mode}, port_profile={port_profile}, "
                            f"custom_port={custom_port}, timeout={timeout_ms}ms, targets={targets}, dns_servers={dns_servers}."
                        ),
                        ui_view="settings",
                        ssl_warning=ssl_warning,
                    ))
                    return
                if self.path == "/settings/save-autoupdate":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    ui_view, diag_view, log_filter, log_source, log_date, log_time_scope, log_time_from, log_time_to = self._resolve_ui_context(form)
                    vals = form.get("autoupdate_enabled", []) or []
                    enabled = "1" in vals
                    cfg = load_config()
                    cfg["autoupdate_enabled"] = enabled
                    save_config(cfg, reapply_cron=False)
                    append_ui_log(f"settings | autoupdate {'enabled' if enabled else 'disabled'}")
                    self._reply_html(_render_setup_html(
                        security_message="Autoupdate " + ("enabled" if enabled else "disabled") + ".",
                        ui_view=ui_view,
                        diag_view=diag_view,
                        log_filter=log_filter,
                        log_date=log_date,
                        log_time_scope=log_time_scope,
                        log_source=log_source,
                        ssl_warning=ssl_warning,
                        open_server_panel="package",
                    ))
                    return
                if self.path == "/settings/save-update-from-main":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    ui_view, diag_view, log_filter, log_source, log_date, log_time_scope, log_time_from, log_time_to = self._resolve_ui_context(form)
                    vals = form.get("update_from_main", []) or []
                    enabled = "1" in vals
                    cfg = load_config()
                    cfg["update_from_main"] = enabled
                    save_config(cfg, reapply_cron=False)
                    check_result = _run_update_check(cfg)
                    _save_update_check_result(check_result)
                    selected = "main" if enabled else "latest release"
                    public_version = str(check_result.get("public_version", "") or check_result.get("latest_version", "") or "")
                    append_ui_log(f"settings | update source set to {selected}")
                    self._reply_html(_render_setup_html(
                        security_message="Update source set to " + selected + (f". Public version: {public_version}." if public_version else "."),
                        ui_view=ui_view,
                        diag_view=diag_view,
                        log_filter=log_filter,
                        log_date=log_date,
                        log_time_scope=log_time_scope,
                        log_source=log_source,
                        ssl_warning=ssl_warning,
                        open_server_panel="package",
                    ))
                    return
                if self.path == "/agent-update":
                    if not self._is_authenticated():
                        self._reply_json({"error": "unauthorized"}, 401)
                        return
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    peer_id = (form.get("peer_id", [""])[0] or "").strip()
                    if not peer_id:
                        self._reply_json({"error": "Missing peer_id"}, 400)
                        return
                    cfg = load_config()
                    if str(cfg.get("peer_role", "")) != "master":
                        self._reply_json({"error": "Master role required"}, 403)
                        return
                    update_supported, _source_platform, update_block_reason = _peer_update_capability(cfg, peer_id)
                    if not update_supported:
                        self._reply_json({"error": update_block_reason}, 403)
                        return
                    session_id, err = _trigger_agent_update(cfg, peer_id)
                    if err:
                        peers = cfg.get("peers", []) or []
                        target = next((p for p in peers if str(p.get("instance_id", "")) == peer_id), None)
                        pname = str(target.get("instance_name", "") or peer_id[:8]) if target else peer_id[:8]
                        p_url = str(target.get("url", "") or "").strip() if target else ""
                        diag_lines = [
                            f"Agent: {pname} ({peer_id[:16]}...)",
                            f"URL: {p_url or '(not set)'}",
                            f"Error: {err}",
                        ]
                        self._reply_json({
                            "error": err,
                            "diagnostic": "\n".join(diag_lines),
                        }, 400)
                        return
                    append_ui_log(f"agent-update | triggered for {peer_id}, session {session_id}")
                    self._reply_json({"status": "started", "session_id": session_id, "peer_id": peer_id}, 202)
                    return
                if self.path == "/settings/recheck-updates":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    ui_view, diag_view, log_filter, log_source, log_date, log_time_scope, log_time_from, log_time_to = self._resolve_ui_context(form)
                    cfg = load_config()
                    report = _build_unix_update_sync_report(cfg=cfg, force=True)
                    selected_channel = str(report.get("selected_channel", "") or "latest")
                    public_version = str(report.get("public_version", "") or "")
                    installed_version = str(report.get("installed_version", "") or VERSION)
                    if report.get("error"):
                        append_ui_log(f"settings | recheck updates failed ({selected_channel}): {report.get('error')}")
                        self._reply_html(_render_setup_html(
                            error=f"Recheck failed ({selected_channel}): {report.get('error')}",
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                            open_server_panel="package",
                        ))
                        return
                    status_note = "Update available." if str(report.get("status", "")) == "update_available" else "Local is up to date."
                    append_ui_log(
                        f"settings | recheck updates ok ({selected_channel}) "
                        f"public={public_version or '?'} local_installed={installed_version} runtime={VERSION}"
                    )
                    self._reply_html(_render_setup_html(
                        security_message=(
                            f"Rechecked updates ({selected_channel}). Installed: {installed_version}. "
                            f"Runtime: {VERSION}. Public: {public_version or 'unknown'}. {status_note}"
                        ),
                        ui_view=ui_view,
                        diag_view=diag_view,
                        log_filter=log_filter,
                        log_date=log_date,
                        log_time_scope=log_time_scope,
                        log_source=log_source,
                        ssl_warning=ssl_warning,
                        open_server_panel="package",
                    ))
                    return
                if self.path == "/settings/request-autoupdate-on-logout":
                    flag_path = _get_autoupdate_on_logout_flag_path()
                    try:
                        flag_path.parent.mkdir(parents=True, exist_ok=True)
                        flag_path.write_text("1", encoding="utf-8")
                    except OSError:
                        pass
                    append_ui_log("settings | autoupdate will run on next logout")
                    self._reply_html(_render_setup_html(
                        security_message="Update will run when you log out. You can keep working until then.",
                        ui_view=ui_view,
                        diag_view=diag_view,
                        log_filter=log_filter,
                        log_date=log_date,
                        log_time_scope=log_time_scope,
                        log_source=log_source,
                        ssl_warning=ssl_warning,
                        open_server_panel="package",
                    ))
                    return
                if self.path == "/danger-restart":
                    service_script = "/usr/local/bin/unix-monitor-service"
                    cmd = f'(sleep 1; "{service_script}" stop; sleep 1; "{service_script}" start) >/dev/null 2>&1'
                    try:
                        subprocess.Popen(["sh", "-c", cmd])
                        append_ui_log("danger-zone | package restart requested from UI")
                        self._reply_html(
                            _render_setup_html(
                                security_message="Restart requested. UI may disconnect briefly (~10s).",
                                ui_view=ui_view,
                                diag_view=diag_view,
                                log_filter=log_filter,
                                log_date=log_date,
                                log_time_scope=log_time_scope,
                                log_source=log_source,
                                ssl_warning=ssl_warning,
                            )
                        )
                    except OSError as e:
                        self._reply_html(
                            _render_setup_html(
                                error=f"Restart failed: {type(e).__name__}: {e}",
                                ui_view=ui_view,
                                diag_view=diag_view,
                                log_filter=log_filter,
                                log_date=log_date,
                                log_time_scope=log_time_scope,
                                log_source=log_source,
                                ssl_warning=ssl_warning,
                            )
                        )
                    return
                if self.path == "/danger-reset":
                    cfg = load_config()
                    reset_cfg: Dict[str, Any] = {"monitors": []}
                    if cfg.get("instance_id"):
                        reset_cfg["instance_id"] = cfg["instance_id"]
                    save_config(reset_cfg, reapply_cron=True)
                    append_ui_log("danger-zone | configuration reset from UI")
                    self._reply_html(
                        _render_setup_html(
                            security_message="Configuration reset. All monitors and peering cleared.",
                            ui_view="settings",
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/self-update":
                    helper = get_update_helper_path()
                    script_dir = str(get_script_path().parent)
                    if not helper.exists():
                        self._reply_html(_render_setup_html(
                            error="Update helper not found. Reinstall to add self-update.",
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                        return
                    try:
                        cfg = load_config()
                        pre = _build_unix_update_sync_report(cfg=cfg, force=True)
                        if pre.get("error"):
                            msg = f"Update pre-check failed ({pre.get('selected_channel', 'latest')}): {pre.get('error')}"
                            append_ui_log(f"self-update | blocked | {msg}")
                            self._reply_html(_render_setup_html(
                                error=msg,
                                ui_view=ui_view,
                                ssl_warning=ssl_warning,
                            ))
                            return
                        rc, out = _run_cmd([str(helper), script_dir, "update", "no-restart"], timeout_sec=30, env=_update_helper_env(cfg))
                        if rc != 0:
                            self._reply_html(_render_setup_html(
                                error=f"Update failed: {out.strip() or 'exit ' + str(rc)}",
                                action_output=out,
                                ui_view=ui_view,
                                ssl_warning=ssl_warning,
                            ))
                            return
                        _cleanup_update_runtime_cache()
                        append_ui_log("self-update | completed successfully")
                        post = _build_unix_update_sync_report(cfg=load_config(), force=True)
                        post_status = str(post.get("status", "") or "unknown")
                        post_note = (
                            "Sync check: update available still detected."
                            if post_status == "update_available"
                            else ("Sync check: local is up to date." if post_status == "up_to_date" else "Sync check: status unknown.")
                        )
                        self._reply_html(_render_setup_html(
                            security_message=(
                                "Update complete. Config and data preserved. Restarting services… "
                                + post_note
                            ),
                            action_output=out,
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                        def _delayed_restart() -> None:
                            time.sleep(2)
                            for u in ("unix-monitor-ui.service", "unix-monitor-scheduler.timer", "unix-monitor-smart-helper.timer", "unix-monitor-backup-helper.timer", "unix-monitor-system-log-helper.timer"):
                                _run_cmd(["systemctl", "restart", u], timeout_sec=10)
                        threading.Thread(target=_delayed_restart, daemon=True).start()
                    except Exception as e:
                        self._reply_html(_render_setup_html(
                            error=f"Update failed: {type(e).__name__}: {e}",
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                    return
                if self.path == "/self-rollback":
                    helper = get_update_helper_path()
                    script_dir = str(get_script_path().parent)
                    backup_path = Path(script_dir) / "unix-monitor.py.prev"
                    if not helper.exists():
                        self._reply_html(_render_setup_html(
                            error="Update helper not found.",
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                        return
                    if not backup_path.exists():
                        self._reply_html(_render_setup_html(
                            error="No backup found. Run an update first to create one.",
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                        return
                    try:
                        rc, out = _run_cmd([str(helper), script_dir, "rollback"], timeout_sec=30)
                        if rc != 0:
                            self._reply_html(_render_setup_html(
                                error=f"Rollback failed: {out.strip() or 'exit ' + str(rc)}",
                                action_output=out,
                                ui_view=ui_view,
                                ssl_warning=ssl_warning,
                            ))
                            return
                        append_ui_log("self-rollback | restored from backup")
                        self._reply_html(_render_setup_html(
                            security_message="Rollback complete. Restored previous version. Restarting services…",
                            action_output=out,
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                    except Exception as e:
                        self._reply_html(_render_setup_html(
                            error=f"Rollback failed: {type(e).__name__}: {e}",
                            ui_view=ui_view,
                            ssl_warning=ssl_warning,
                        ))
                    return
                if self.path == "/run-check":
                    cfg = load_config()
                    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
                    if role == "agent":
                        ok_action, summary, remote_output = _agent_request_master_monitor_action(cfg, "run-check")
                        output = remote_output or summary
                        message_text = "Run check completed (triggered by master)" if ok_action else "Run check failed (master trigger)"
                    else:
                        output = _ui_run_check_now()
                        message_text = "Run check completed"
                    self._reply_html(
                        _render_setup_html(
                            message=message_text,
                            action_output=output,
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/run-check-monitor":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    ui_view, diag_view, log_filter, log_source, log_date, log_time_scope, log_time_from, log_time_to = self._resolve_ui_context(form)
                    monitor_name = (form.get("monitor_name", [""])[0] or "").strip()
                    cfg = load_config()
                    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
                    if role == "master" and log_source != "local":
                        ok_action, summary, remote_output = _trigger_agent_monitor_action(cfg, log_source, "run-check", monitor_name=monitor_name)
                        output = remote_output or summary
                        action_msg = "Monitor check completed (triggered by master)" if ok_action else "Monitor check failed (triggered by master)"
                    elif role == "agent":
                        ok_action, summary, remote_output = _agent_request_master_monitor_action(cfg, "run-check", monitor_name=monitor_name)
                        output = remote_output or summary
                        action_msg = "Monitor check completed (triggered by master)" if ok_action else "Monitor check failed (master trigger)"
                    else:
                        output = _ui_run_check_now(target_monitor=monitor_name)
                        action_msg = "Monitor check completed"
                    self._reply_html(
                        _render_setup_html(
                            monitor_action_name=monitor_name,
                            monitor_action_message=action_msg,
                            monitor_action_output=output,
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/test-push":
                    cfg = load_config()
                    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
                    if role == "agent":
                        ok_action, summary, remote_output = _agent_request_master_monitor_action(cfg, "test-push")
                        output = remote_output or summary
                        message_text = "Connection test completed (triggered by master)" if ok_action else "Connection test failed (master trigger)"
                    else:
                        output = _ui_test_push()
                        message_text = "Connection test completed"
                    self._reply_html(
                        _render_setup_html(
                            message=message_text,
                            action_output=output,
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/test-push-monitor":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    ui_view, diag_view, log_filter, log_source, log_date, log_time_scope, log_time_from, log_time_to = self._resolve_ui_context(form)
                    monitor_name = (form.get("monitor_name", [""])[0] or "").strip()
                    cfg = load_config()
                    role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
                    if role == "master" and log_source != "local":
                        ok_action, summary, remote_output = _trigger_agent_monitor_action(cfg, log_source, "test-push", monitor_name=monitor_name)
                        output = remote_output or summary
                        action_msg = "Monitor test push completed (triggered by master)" if ok_action else "Monitor test push failed (triggered by master)"
                    elif role == "agent":
                        ok_action, summary, remote_output = _agent_request_master_monitor_action(cfg, "test-push", monitor_name=monitor_name)
                        output = remote_output or summary
                        action_msg = "Monitor test push completed (triggered by master)" if ok_action else "Monitor test push failed (master trigger)"
                    else:
                        output = _ui_test_push(target_monitor=monitor_name)
                        action_msg = "Monitor test push completed"
                    self._reply_html(
                        _render_setup_html(
                            monitor_action_name=monitor_name,
                            monitor_action_message=action_msg,
                            monitor_action_output=output,
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/run-scheduled-now":
                    output = _ui_run_scheduled_now()
                    self._reply_html(
                        _render_setup_html(
                            automation_message="Scheduled run executed",
                            automation_output=output,
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/repair-automation":
                    output = _ui_repair_automation()
                    self._reply_html(
                        _render_setup_html(
                            automation_message="Automation repair attempted",
                            automation_output=output,
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/automation-status":
                    self._reply_html(
                        _render_setup_html(
                            automation_message="Automation status refreshed",
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/open-create":
                    append_ui_log("open-create | requested")
                    self._reply_html(_render_setup_html(message="Create monitor", create_mode=True, ui_view="setup", ssl_warning=ssl_warning))
                    return
                if self.path == "/open-setup-popup":
                    append_ui_log("open-setup-popup | requested")
                    self._reply_html(_render_setup_html(message="Elevation setup guide", show_setup_popup=True, ui_view="setup", ssl_warning=ssl_warning))
                    return
                if self.path == "/edit-monitor":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    monitor_name = (form.get("monitor_name", [""])[0] or "").strip()
                    append_ui_log(f"edit-monitor | target={monitor_name}")
                    self._reply_html(_render_setup_html(message=f"Editing monitor: {monitor_name}", edit_target=monitor_name, ui_view="setup", ssl_warning=ssl_warning))
                    return
                if self.path == "/delete-monitor":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    ui_view, diag_view, log_filter, log_source, log_date, log_time_scope, log_time_from, log_time_to = self._resolve_ui_context(form)
                    monitor_name = (form.get("monitor_name", [""])[0] or "").strip()
                    output = _ui_delete_monitor(monitor_name)
                    self._reply_html(
                        _render_setup_html(
                            message=output,
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/clear-logs":
                    clear_ui_log()
                    append_ui_log("logs cleared")
                    self._reply_html(
                        _render_setup_html(
                            message="Logs cleared",
                            ui_view="overview",
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/clear-logs-remote":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    target_peer = (form.get("source", [log_source])[0] or log_source).strip()
                    if not target_peer or target_peer == "local":
                        msg = "Select a remote source first."
                    else:
                        msg = _clear_agent_logs(load_config(), target_peer)
                        append_ui_log(f"remote-clear-logs | source={target_peer} | {msg}")
                    self._reply_html(
                        _render_setup_html(
                            message=msg,
                            ui_view="overview",
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/clear-task-status":
                    clear_task_status()
                    append_ui_log("task status cleared")
                    self._reply_html(
                        _render_setup_html(
                            message="Task data cleared",
                            ui_view="overview",
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/clear-cache":
                    clear_smart_cache()
                    clear_backup_cache()
                    clear_system_log_cache()
                    append_ui_log("cache cleared (smart + backup + system-log)")
                    self._reply_html(
                        _render_setup_html(
                            message="Cache cleared",
                            ui_view="overview",
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/clear-history":
                    clear_history()
                    append_ui_log("monitor history cleared")
                    self._reply_html(
                        _render_setup_html(
                            message="History cleared",
                            ui_view="overview",
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/clear-system-cache":
                    clear_system_log_cache()
                    append_ui_log("system log cache cleared")
                    self._reply_html(
                        _render_setup_html(
                            message="System log cache cleared",
                            ui_view="overview",
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/check-elevated":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    stay_popup = "stay_popup" in form
                    output = _ui_check_elevated_access()
                    self._reply_html(
                        _render_setup_html(
                            elevated_check_message="Elevated access check completed",
                            elevated_check_output=output,
                            show_setup_popup=stay_popup,
                            ui_view="setup",
                            ssl_warning=ssl_warning,
                        )
                    )
                    return
                if self.path == "/auto-create-task":
                    raw_len = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                    form = parse_qs(body, keep_blank_values=True)
                    stay_popup = "stay_popup" in form
                    output = _ui_auto_create_task_beta()
                    self._reply_html(
                        _render_setup_html(
                            message="Auto-create task attempt finished",
                            action_output=output,
                            show_setup_popup=stay_popup,
                            ui_view="setup",
                            ssl_warning=ssl_warning,
                        )
                    )
                    return

                raw_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(raw_len).decode("utf-8", errors="ignore")
                form = parse_qs(body, keep_blank_values=True)
                ui_view, diag_view, log_filter, log_source, log_date, log_time_scope, log_time_from, log_time_to = self._resolve_ui_context(form)

                name = (form.get("name", [""])[0] or "").strip()
                mode = (form.get("check_mode", ["smart"])[0] or "smart").strip().lower()
                kuma_url = (form.get("kuma_url", [""])[0] or "").strip()
                interval_raw = (form.get("interval", ["60"])[0] or "60").strip()
                probe_host = (form.get("probe_host", [""])[0] or "").strip()
                probe_port_raw = (form.get("probe_port", [""])[0] or "").strip()
                dns_name = (form.get("dns_name", [""])[0] or "").strip()
                dns_server = (form.get("dns_server", [""])[0] or "").strip()
                service_names = (form.get("service_names", [""])[0] or "").strip()
                service_description_filter = (form.get("service_description_filter", [""])[0] or "").strip()
                cron_enabled = "cron_enabled" in form
                edit_original_name = (form.get("edit_original_name", [""])[0] or "").strip()

                if mode not in CHECK_MODES:
                    append_ui_log(f"save-config | invalid mode: {mode}")
                    self._reply_html(
                        _render_setup_html(
                            error="Invalid check mode",
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                            create_mode=not edit_original_name,
                            edit_original_name=edit_original_name or None,
                        )
                    )
                    return
                if not name:
                    name = f"{mode}-unix-check"
                if len(name) < 2:
                    self._reply_html(
                        _render_setup_html(
                            error="Monitor name must be at least 2 characters.",
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                            create_mode=not edit_original_name,
                            edit_original_name=edit_original_name or None,
                        )
                    )
                    return
                if not kuma_url.strip():
                    self._reply_html(
                        _render_setup_html(
                            error="Kuma Push URL is required.",
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                            create_mode=not edit_original_name,
                            edit_original_name=edit_original_name or None,
                        )
                    )
                    return
                if not kuma_url.startswith(("http://", "https://")):
                    kuma_url = "https://" + kuma_url
                kuma_url = normalize_kuma_url(kuma_url)
                err = validate_kuma_url(kuma_url)
                if err:
                    append_ui_log(f"save-config | invalid Kuma URL: {err}")
                    self._reply_html(
                        _render_setup_html(
                            error=f"Invalid Kuma URL: {err}",
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                            create_mode=not edit_original_name,
                            edit_original_name=edit_original_name or None,
                        )
                    )
                    return
                try:
                    interval = max(INTERVAL_MIN, min(INTERVAL_MAX, int(interval_raw)))
                except ValueError:
                    interval = 60
                try:
                    probe_port = int(probe_port_raw) if probe_port_raw else 0
                except ValueError:
                    probe_port = 0
                if mode == "ping" and not probe_host:
                    self._reply_html(
                        _render_setup_html(
                            error="Ping mode requires a probe host.",
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                            create_mode=not edit_original_name,
                            edit_original_name=edit_original_name or None,
                        )
                    )
                    return
                if mode == "port":
                    if not probe_host or probe_port < 1 or probe_port > 65535:
                        self._reply_html(
                            _render_setup_html(
                                error="Port mode requires valid probe host and TCP port (1-65535).",
                                ui_view=ui_view,
                                diag_view=diag_view,
                                log_filter=log_filter,
                                log_date=log_date,
                                log_time_scope=log_time_scope,
                                log_time_from=log_time_from,
                                log_time_to=log_time_to,
                                log_source=log_source,
                                ssl_warning=ssl_warning,
                                create_mode=not edit_original_name,
                                edit_original_name=edit_original_name or None,
                            )
                        )
                        return
                if mode == "dns" and not dns_name:
                    self._reply_html(
                        _render_setup_html(
                            error="DNS mode requires a DNS name/domain.",
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                            create_mode=not edit_original_name,
                            edit_original_name=edit_original_name or None,
                        )
                    )
                    return
                if mode == "service" and not service_names and not service_description_filter:
                    self._reply_html(
                        _render_setup_html(
                            error="Service mode requires service names and/or a description filter.",
                            ui_view=ui_view,
                            diag_view=diag_view,
                            log_filter=log_filter,
                            log_date=log_date,
                            log_time_scope=log_time_scope,
                            log_time_from=log_time_from,
                            log_time_to=log_time_to,
                            log_source=log_source,
                            ssl_warning=ssl_warning,
                            create_mode=not edit_original_name,
                            edit_original_name=edit_original_name or None,
                        )
                    )
                    return

                cfg = load_config()
                target_peer = (form.get("target_peer", ["local"])[0] or "local").strip()
                save_role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
                if save_role != "master" or edit_original_name:
                    target_peer = "local"
                elif target_peer != "local":
                    _allowed_tp = False
                    for _p in (cfg.get("peers", []) or []):
                        _pid = str(_p.get("instance_id", "") or "").strip()
                        if _pid == target_peer and _is_valid_peer_instance_id(_pid):
                            _allowed_tp = True
                            break
                    if not _allowed_tp:
                        target_peer = "local"
                if target_peer and target_peer != "local" and not edit_original_name:
                    peer_entry = _peer_entry_for_instance_id(cfg, target_peer) or {}
                    if _is_legacy_peer(peer_entry):
                        ack_val = (form.get("acknowledge_legacy", [""])[0] or "").strip().lower()
                        if ack_val not in ("1", "on", "yes", "true"):
                            self._reply_html(
                                _render_setup_html(
                                    error="Confirm the legacy agent warning before creating a monitor for this peer.",
                                    ui_view=ui_view,
                                    diag_view=diag_view,
                                    log_filter=log_filter,
                                    log_date=log_date,
                                    log_time_scope=log_time_scope,
                                    log_time_from=log_time_from,
                                    log_time_to=log_time_to,
                                    log_source=log_source,
                                    ssl_warning=ssl_warning,
                                    create_mode=True,
                                )
                            )
                            return
                    source_platform = _infer_peer_source_platform(cfg, target_peer)
                    agent_monitor_cfg: Dict[str, Any] = {
                        "name": name,
                        "check_mode": mode,
                        "kuma_url": kuma_url,
                        "source_platform": source_platform,
                    }
                    for ek, ev in (
                        ("probe_host", probe_host),
                        ("probe_port", probe_port),
                        ("dns_name", dns_name),
                        ("dns_server", dns_server),
                        ("service_names", service_names),
                        ("service_description_filter", service_description_filter),
                    ):
                        if ev:
                            agent_monitor_cfg[ek] = ev
                    result = _peer_create_remote_monitor(cfg, target_peer, agent_monitor_cfg)
                    master_monitor = {
                        "name": name,
                        "check_mode": mode,
                        "devices": [],
                        "kuma_url": kuma_url,
                        "probe_host": probe_host,
                        "probe_port": probe_port,
                        "dns_name": dns_name,
                        "dns_server": dns_server,
                        "service_names": service_names,
                        "service_description_filter": service_description_filter,
                        "interval": interval,
                        "cron_enabled": cron_enabled,
                        "_remote_peer": target_peer,
                        "source_platform": source_platform,
                    }
                    cfg.setdefault("monitors", []).append(master_monitor)
                    cfg["cron_enabled"] = any(m.get("cron_enabled", False) for m in cfg.get("monitors", []))
                    save_config(cfg, reapply_cron=False)
                    sync_result = _peer_sync_from_master(load_config())
                    append_ui_log(f"save-config | remote create on {target_peer} | name={name} | mode={mode} | result={result}")
                    append_ui_log(f"peer-sync | auto-sync after remote create: {sync_result}")
                    self._reply_html(_render_setup_html(
                        message=f"Monitor '{name}' created on agent and registered on master.\n{result}",
                        ui_view="setup", ssl_warning=ssl_warning,
                    ))
                    return

                new_monitor = {
                    "name": name,
                    "check_mode": mode,
                    "devices": [],
                    "kuma_url": kuma_url,
                    "probe_host": probe_host,
                    "probe_port": probe_port,
                    "dns_name": dns_name,
                    "dns_server": dns_server,
                    "service_names": service_names,
                    "service_description_filter": service_description_filter,
                    "interval": interval,
                    "cron_enabled": cron_enabled,
                }
                if edit_original_name:
                    updated = False
                    for i, m in enumerate(cfg.get("monitors", [])):
                        if str(m.get("name", "")) == edit_original_name:
                            keep_devices = [str(x) for x in m.get("devices", [])]
                            new_monitor["devices"] = keep_devices
                            if m.get("_remote_peer"):
                                new_monitor["_remote_peer"] = m["_remote_peer"]
                            if m.get("source_platform"):
                                new_monitor["source_platform"] = m["source_platform"]
                            cfg["monitors"][i] = new_monitor
                            updated = True
                            break
                    if not updated:
                        cfg.setdefault("monitors", []).append(new_monitor)
                else:
                    existing = _find_monitor_by_name(cfg.get("monitors", []), name)
                    if existing is not None:
                        existing["check_mode"] = mode
                        existing["kuma_url"] = kuma_url
                        existing["interval"] = interval
                        existing["cron_enabled"] = cron_enabled
                    else:
                        cfg.setdefault("monitors", []).append(new_monitor)
                any_cron = any(m.get("cron_enabled", False) for m in cfg.get("monitors", []))
                cfg["cron_enabled"] = any_cron
                # Package runtime uses headless scheduler helper; avoid per-user crontab dependencies.
                save_config(cfg, reapply_cron=False)
                append_ui_log(
                    f"save-config | name={name} | mode={mode} | cron={'on' if cron_enabled else 'off'} | interval={interval} | edit_target={edit_original_name or '-'}"
                )
                _trigger_peer_sync_bg(cfg)
                self._reply_html(_render_setup_html(message="Saved successfully", ui_view="setup", ssl_warning=ssl_warning))
            except Exception as e:
                append_ui_log(f"ui-error | {type(e).__name__}: {e}")
                self._reply_html(_render_setup_html(error=f"Failed to save: {type(e).__name__}: {e}", ui_view=ui_view, ssl_warning=ssl_warning), code=500)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    _srv_cfg = load_config()
    _srv_cert, _srv_key, _srv_ca = _get_mtls_cert_paths(_srv_cfg)
    _tls_available = False
    if _srv_cert and _srv_key and _srv_ca:
        try:
            _srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            _srv_ctx.load_cert_chain(_srv_cert, _srv_key)
            _srv_ctx.load_verify_locations(_srv_ca)
            _srv_ctx.verify_mode = ssl.CERT_OPTIONAL
            server.socket = _DualProtocolSocket(server.socket, _srv_ctx)
            _tls_available = True
            Handler._tls_available = True
            append_ui_log("tls | dual-protocol listener active (HTTPS + HTTP redirect on same port)")
        except Exception as _ssl_err:
            append_ui_log(f"tls | TLS setup failed, running plain HTTP only: {_ssl_err}")
    if _tls_available:
        print(f"Setup UI running on https://{host}:{port} (HTTP auto-redirects)")
    else:
        print(f"Setup UI running on http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    threading.Thread(target=_agent_peer_heartbeat_loop, daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping setup UI.")
    finally:
        server.server_close()
    return 0


def run_scheduled() -> int:
    cfg = load_config()
    monitors = [m for m in cfg.get("monitors", []) if isinstance(m, dict)]
    cfg_path = str(get_config_path())
    runtime_dir = str(get_runtime_data_dir())
    if not monitors:
        if _agent_peer_push_if_due(cfg, force=True):
            append_ui_log(
                f"scheduled-run | no monitors | agent peer push | cfg={cfg_path} | data_dir={runtime_dir}"
            )
        else:
            append_ui_log(f"scheduled-run | skipped | no monitors | cfg={cfg_path} | data_dir={runtime_dir}")
        return 0
    global_cron = bool(cfg.get("cron_enabled", False))
    global_interval = int(cfg.get("cron_interval_minutes", 60) or 60)
    dbg = bool(cfg.get("debug", False))
    due_count = 0
    attempted_count = 0
    ran_any = False
    append_ui_log(
        "scheduled-run | start | "
        f"monitors={len(monitors)} | global_cron={'on' if global_cron else 'off'} | "
        f"global_interval={global_interval} | cfg={cfg_path} | data_dir={runtime_dir}"
    )
    for m in monitors:
        name = str(m.get("name", "")).strip()
        if not name:
            continue
        mon_cron = bool(m.get("cron_enabled", global_cron))
        if not mon_cron:
            continue
        try:
            mon_interval = int(m.get("interval", global_interval) or global_interval)
        except (TypeError, ValueError):
            mon_interval = global_interval
        mon_interval = max(1, mon_interval)
        due = _is_scheduled_due(mon_interval, monitor_name=name)
        if not due:
            continue
        due_count += 1
        mode = str(m.get("check_mode", "smart")).lower()
        if mode not in CHECK_MODES:
            mode = "smart"
        attempted_count += 1
        ran_any = True
        try:
            url = m.get("kuma_url", "")
            if not url:
                line = f"x {name}: no Kuma URL"
                _set_monitor_state(name, "Automatic monitor check skipped", line, level="err")
                append_ui_log(f"scheduled-check | {name} | mode={mode} | skipped | no Kuma URL")
                continue
            devices = [str(x) for x in m.get("devices", [])]
            status, msg, lat = check_host_with_monitor(mode, devices, monitor=m, debug=dbg)
            ok = push_to_kuma(url, status, msg, lat, debug=dbg)
            recorded_status = status if ok else "warning"
            _record_history(name, mode, recorded_status, lat)
            line = f"{'ok' if ok else 'x'} {name}: {status} (ping={lat:.2f}ms) push {'OK' if ok else 'FAILED'}"
            _set_monitor_state(
                name,
                "Automatic monitor check completed" if ok else "Automatic monitor check completed with errors",
                line,
                level="ok" if ok else "err",
            )
            append_ui_log(
                f"scheduled-check | {name} | mode={mode} | status={status} | ping_ms={lat:.2f} | push={'OK' if ok else 'FAILED'}"
            )
        except Exception as e:
            err_line = f"x {name}: scheduler error {type(e).__name__}: {e}"
            _set_monitor_state(name, "Automatic monitor check failed", err_line, level="err")
            append_ui_log(f"scheduled-check | {name} | mode={mode} | error={type(e).__name__}: {e}")
        finally:
            _touch_scheduled_run(monitor_name=name)
    if ran_any:
        _touch_scheduled_run()
    if _agent_peer_push_if_due(cfg):
        append_ui_log("scheduled-run | agent peer push triggered")
    append_ui_log(
        "scheduled-run | done | "
        f"due={due_count} | attempted={attempted_count} | ran_any={'yes' if ran_any else 'no'}"
    )
    return 0


def run_scheduled_loop() -> int:
    append_ui_log("scheduled-loop | started")
    try:
        while True:
            try:
                run_scheduled()
            except Exception as e:
                append_ui_log(f"scheduled-loop | error | {type(e).__name__}: {e}")
            time.sleep(60)
    except KeyboardInterrupt:
        pass
    append_ui_log("scheduled-loop | stopped")
    return 0


def _systemd_unit_status(unit: str) -> str:
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return (proc.stdout or proc.stderr or "unknown").strip()
    except Exception:
        return "unknown"


def _manage_show_status() -> None:
    cfg = load_config()
    install_dir = str(Path(__file__).resolve().parent)
    print("\n--- Installation ---")
    print(f"  Product:     {PRODUCT_NAME}")
    print(f"  Version:     {VERSION}")
    print(f"  Script:      {Path(__file__).resolve()}")
    print(f"  Install dir: {install_dir}")
    print(f"  Config:      {CONFIG_PATH}")
    print(f"  Webserver:   {'enabled' if bool(cfg.get('web_enabled', True)) else 'disabled (agent-only)'}")
    print(f"  Peer role:   {_cfg_peer_role(cfg)}")
    master = str(cfg.get("peer_master_url", "") or "").strip()
    token_set = bool(str(cfg.get("peering_token", "") or "").strip())
    print(f"  Master URL:  {master or '(not set)'}")
    print(f"  Peering tok: {'set' if token_set else 'not set'}")
    print(f"  Monitors:    {len(cfg.get('monitors', []) or [])}")
    if shutil.which("systemctl"):
        print("\n--- Services ---")
        prefix = "unix-rollout-agent" if _rollout_agent_mode() else "unix-monitor"
        for suffix in (
            "ui.service",
            "scheduler.timer",
            "smart-helper.timer",
            "backup-helper.timer",
            "system-log-helper.timer",
        ):
            unit = f"{prefix}-{suffix}"
            print(f"  {unit}: {_systemd_unit_status(unit)}")
    if bool(cfg.get("web_enabled", True)):
        host = str(cfg.get("ui_host", "0.0.0.0") or "0.0.0.0")
        port = int(cfg.get("ui_port", 8787) or 8787)
        print(f"\n  Web UI: http://{host}:{port}/")
    print(f"\n  Uninstall: sudo bash {install_dir}/uninstall.sh")


def manage_menu() -> str:
    print("\n" + "=" * 50)
    print(f"  {PRODUCT_NAME} — Management")
    print("=" * 50)
    print("  1) Show installation status")
    print("  2) Monitor menu (add/run/list monitors)")
    print("  3) Run scheduled checks now")
    print("  4) Exit")
    print("=" * 50)
    return prompt("Choice", "1").strip() or "1"


def run_manage() -> int:
    while True:
        choice = manage_menu()
        if choice == "1":
            _manage_show_status()
        elif choice == "2":
            main()
        elif choice == "3":
            run_scheduled()
        elif choice == "4":
            print("Bye.")
            return 0
        else:
            print("Invalid choice.")


def main_menu() -> str:
    cfg = load_config()
    print("\n" + "=" * 50)
    print(f"  {PRODUCT_NAME}")
    print("=" * 50)
    print(CHANGES_NOTICE)
    print(f"  Debug: {'ON' if cfg.get('debug', False) else 'OFF'}")
    print()
    print("  1) Add monitor (Mount / SMART / Storage / Ping / Port / DNS / Backup)")
    print("  2) Run check (all configured monitors)")
    print("  3) List configured monitors")
    print("  4) Remove monitor")
    print("  5) Schedule automatic checks (cron)")
    print("  6) Test push (send test message to Kuma)")
    print("  7) Toggle debug mode")
    from_main = cfg.get("update_from_main", False)
    print(f"  8) Toggle update from main (testing) — {('ON' if from_main else 'OFF')}")
    print("  9) Exit")
    print("=" * 50)
    return prompt("Choice", "1").strip() or "1"


def main() -> int:
    while True:
        choice = main_menu()
        if choice == "1":
            add_monitor()
        elif choice == "2":
            run_check()
        elif choice == "3":
            list_configured()
        elif choice == "4":
            remove_monitor()
        elif choice == "5":
            manage_cron()
        elif choice == "6":
            test_push()
        elif choice == "7":
            toggle_debug()
        elif choice == "8":
            toggle_update_from_main()
        elif choice == "9":
            print("Bye.")
            return 0
        else:
            print("Invalid choice.")


def _agent_only_gate() -> Tuple[bool, str]:
    cfg = load_config()
    if bool(cfg.get("web_enabled", True)):
        return True, ""
    role = _cfg_peer_role(cfg)
    if role != "agent":
        return False, "Webserver is disabled. This installation is agent-only and requires peer_role=agent."
    if not str(cfg.get("peer_master_url", "") or "").strip() or not str(cfg.get("peering_token", "") or "").strip():
        return False, "Webserver is disabled. Agent mode requires peer_master_url and peering_token."
    return True, ""


def _print_usage() -> None:
    print("Usage:")
    print("  python3 unix-monitor.py")
    print("  python3 unix-monitor.py --run|-r [--debug|-d]")
    print("  python3 unix-monitor.py --run-scheduled")
    print("  python3 unix-monitor.py --run-scheduled-loop")
    print("  python3 unix-monitor.py --run-smart-helper")
    print("  python3 unix-monitor.py --run-backup-helper")
    print("  python3 unix-monitor.py --run-system-log-helper")
    print("  python3 unix-monitor.py --ui [--host 0.0.0.0] [--port 8787]")
    print("  python3 unix-monitor.py --manage")
    print("  python3 unix-monitor.py --agent-menu")
    print("  easymonitor   (after install — same as --manage)")


if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        _print_usage()
        sys.exit(0)
    if "--run-smart-helper" in sys.argv:
        sys.exit(run_smart_helper())
    if "--run-backup-helper" in sys.argv:
        sys.exit(run_backup_helper())
    if "--run-system-log-helper" in sys.argv:
        sys.exit(run_system_log_helper())
    if "--run-scheduled" in sys.argv:
        sys.exit(run_scheduled())
    if "--run-scheduled-loop" in sys.argv:
        sys.exit(run_scheduled_loop())
    if "--agent-menu" in sys.argv:
        ok, reason = _agent_only_gate()
        if not ok:
            print(reason)
            sys.exit(2)
        sys.exit(main())
    if "--manage" in sys.argv or "--easymonitor" in sys.argv:
        sys.exit(run_manage())
    if "--ui" in sys.argv:
        cfg = load_config()
        if not bool(cfg.get("web_enabled", True)):
            print("Webserver is disabled in config (agent-only installation).")
            sys.exit(2)
        ui_host = _normalize_ui_bind_host(cfg.get("ui_bind_host", "0.0.0.0"))
        ui_port = _normalize_ui_bind_port(cfg.get("ui_bind_port", 8787))
        if "--host" in sys.argv:
            try:
                ui_host = _normalize_ui_bind_host(sys.argv[sys.argv.index("--host") + 1])
            except (ValueError, IndexError):
                print("Invalid --host usage. Example: --host 0.0.0.0")
                sys.exit(1)
        if "--port" in sys.argv:
            try:
                ui_port = _normalize_ui_bind_port(int(sys.argv[sys.argv.index("--port") + 1]))
            except (ValueError, IndexError):
                print("Invalid --port usage. Example: --port 8787")
                sys.exit(1)
        sys.exit(run_setup_ui(host=ui_host, port=ui_port))
    if len(sys.argv) > 1 and sys.argv[1] in ("--run", "-r"):
        dbg = "--debug" in sys.argv or "-d" in sys.argv
        run_check(debug=dbg, interactive=False)
        sys.exit(0)
    ok, reason = _agent_only_gate()
    if not ok:
        print(reason)
        print("Use --agent-menu after configuring master URL and peering token.")
        sys.exit(2)
    sys.exit(main())
