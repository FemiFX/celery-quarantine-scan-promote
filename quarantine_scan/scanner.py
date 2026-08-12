"""The scan-and-promote state machine, independent of any web framework or ORM.

`scan_and_promote()` returns a verdict; persisting it is the caller's business.
That split is what makes this testable without a database and reusable outside
the app it came from.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Protocol

from .errors import ScannerUnavailableError
from .storage import BaseStorageBackend

logger = logging.getLogger(__name__)

DEFAULT_CLAMAV_HOST = "clamav"
DEFAULT_CLAMAV_PORT = 3310
DEFAULT_CLAMAV_TIMEOUT = 30


class ScanStatus(str, Enum):
    """Terminal states for a scanned object."""

    PENDING = "pending"
    CLEAN = "clean"
    INFECTED = "infected"
    FAILED = "failed"


@dataclass(frozen=True)
class ScanOutcome:
    """What happened. Persist this however your application stores state."""

    status: ScanStatus
    message: str
    signature: str | None = None
    promoted: bool = False
    #: True when the caller should retry — the scanner was unreachable or the
    #: object could not be read. A verdict (clean/infected) is never retriable.
    retriable: bool = False

    @property
    def is_clean(self) -> bool:
        return self.status is ScanStatus.CLEAN


class VirusScanner(Protocol):
    """Anything that can scan a binary stream and return a verdict.

    Matches `clamd`'s `instream()` shape: a mapping whose first value is a
    ``(status, signature)`` tuple with status in {"OK", "FOUND", "ERROR"}.
    """

    def instream(self, stream: Any) -> dict: ...


def clamav_scanner_factory(
    host: str = DEFAULT_CLAMAV_HOST,
    port: int = DEFAULT_CLAMAV_PORT,
    timeout: int = DEFAULT_CLAMAV_TIMEOUT,
) -> Callable[[], VirusScanner]:
    """Return a callable producing a ClamAV network client.

    A factory rather than an instance: the connection is made at scan time, so a
    scanner restart doesn't leave a worker holding a dead socket for its whole
    lifetime.
    """

    def _factory() -> VirusScanner:
        try:
            import clamd
        except ImportError as exc:  # pragma: no cover - import guard
            raise ScannerUnavailableError(
                "ClamAV support requires the 'clamav' extra: pip install "
                "quarantine-scan[clamav]"
            ) from exc
        return clamd.ClamdNetworkSocket(host=host, port=port, timeout=timeout)

    return _factory


def scan_and_promote(
    stored_filename: str,
    storage: BaseStorageBackend,
    scanner_factory: Callable[[], VirusScanner],
    *,
    already_clean: bool = False,
    delete_infected: bool = False,
) -> ScanOutcome:
    """Scan a quarantined object and promote it to live storage when clean.

    Idempotent by design, because a Celery task can be delivered more than once:

    * object already live **and** already recorded clean -> no-op success
    * object in neither space -> terminal failure, not a retry (retrying cannot
      conjure bytes that aren't there)
    * object still live but not yet recorded clean -> rescan in place, which
      covers a crash between the copy and the status write

    Args:
        stored_filename: key or filename, relative to each storage space.
        storage: backend implementing the quarantine/live interface.
        scanner_factory: callable returning a scanner; called once per scan.
        already_clean: whether the caller's record already says CLEAN.
        delete_infected: remove the object outright when a signature matches.
            Leave False to keep it for forensics.
    """
    has_live = storage.exists_live(stored_filename)
    has_quarantine = storage.exists_quarantine(stored_filename)

    if has_live and already_clean:
        logger.info("Object %s already clean and live; nothing to do", stored_filename)
        return ScanOutcome(
            status=ScanStatus.CLEAN, message="Already clean", promoted=False
        )

    if not has_quarantine and not has_live:
        logger.error("Source object missing entirely: %s", stored_filename)
        return ScanOutcome(status=ScanStatus.FAILED, message="File not found")

    source_is_quarantine = has_quarantine

    try:
        scanner = scanner_factory()
    except Exception as exc:
        logger.exception("Could not connect to the virus scanner: %s", exc)
        return ScanOutcome(
            status=ScanStatus.FAILED,
            message="Scanner unavailable",
            retriable=True,
        )

    opener = (
        storage.open_quarantine_stream
        if source_is_quarantine
        else storage.open_live_stream
    )
    try:
        with opener(stored_filename) as handle:
            result = scanner.instream(handle)
    except Exception as exc:
        logger.exception("Error scanning %s: %s", stored_filename, exc)
        return ScanOutcome(
            status=ScanStatus.FAILED, message="Scan failed", retriable=True
        )

    try:
        status, signature = next(iter(result.values()))
    except (StopIteration, ValueError, AttributeError):
        logger.error("Unparseable scanner response for %s: %r", stored_filename, result)
        return ScanOutcome(
            status=ScanStatus.FAILED, message="Unparseable scanner response"
        )

    logger.info("Scan result for %s: %s (%s)", stored_filename, status, signature)

    if status == "OK":
        if not source_is_quarantine:
            return ScanOutcome(status=ScanStatus.CLEAN, message="Clean", promoted=False)
        try:
            storage.promote_quarantine_to_live(stored_filename)
        except Exception as exc:
            logger.exception("Failed to promote clean object %s: %s", stored_filename, exc)
            # Deliberately NOT retriable-clean: the object is clean but still
            # quarantined. Surfacing FAILED keeps it out of the live space until
            # a human or a retry actually moves it.
            return ScanOutcome(
                status=ScanStatus.FAILED, message="Promotion failed", retriable=True
            )
        return ScanOutcome(status=ScanStatus.CLEAN, message="Clean", promoted=True)

    if status == "FOUND":
        if delete_infected:
            try:
                if source_is_quarantine:
                    storage.delete_quarantine(stored_filename)
                else:
                    storage.delete_live(stored_filename)
            except Exception:
                logger.warning("Failed to remove infected object %s", stored_filename)
        return ScanOutcome(
            status=ScanStatus.INFECTED,
            message=f"Infected: {signature}",
            signature=signature,
        )

    return ScanOutcome(status=ScanStatus.FAILED, message=f"Scan status: {status}")
