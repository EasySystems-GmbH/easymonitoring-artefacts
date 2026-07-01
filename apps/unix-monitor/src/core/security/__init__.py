"""Security helpers extracted from the ``unix-monitor.py`` monolith.

Currently exposes the config-backup encryption family (``backup_crypto``),
which is distinct from the peer payload-crypto family in
``src/core/peering/crypto.py`` (different, backup-specific salt).
"""

from .backup_crypto import (
    configure as configure_backup_crypto,
    BACKUP_SALT,
    _derive_backup_key,
    _encrypt_backup,
    _decrypt_backup,
)

__all__ = [
    "configure_backup_crypto",
    "BACKUP_SALT",
    "_derive_backup_key",
    "_encrypt_backup",
    "_decrypt_backup",
]
