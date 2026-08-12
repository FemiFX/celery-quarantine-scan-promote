"""Quarantine → scan → promote pipeline for user uploads.

Uploads land in a quarantine space nothing user-facing can read. A background
worker scans them and only then moves them to live storage.
"""

from .errors import (
    InvalidStorageConfiguration,
    MissingObjectError,
    ScannerUnavailableError,
    StorageBackendError,
)
from .scanner import (
    ScanOutcome,
    ScanStatus,
    VirusScanner,
    clamav_scanner_factory,
    scan_and_promote,
)
from .storage import (
    BaseStorageBackend,
    LocalStorageBackend,
    S3StorageBackend,
    backend_from_config,
)

__version__ = "0.1.0"

__all__ = [
    "BaseStorageBackend",
    "InvalidStorageConfiguration",
    "LocalStorageBackend",
    "MissingObjectError",
    "S3StorageBackend",
    "ScanOutcome",
    "ScanStatus",
    "ScannerUnavailableError",
    "StorageBackendError",
    "VirusScanner",
    "backend_from_config",
    "clamav_scanner_factory",
    "scan_and_promote",
]
