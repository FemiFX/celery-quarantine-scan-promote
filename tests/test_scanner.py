"""Tests for the scan/promote state machine.

No Celery, no database, no ClamAV — the point of keeping the core framework-free
is that its behaviour is testable with a fake scanner and a temp directory.
"""

from __future__ import annotations

import pytest

from quarantine_scan import (
    LocalStorageBackend,
    ScanStatus,
    scan_and_promote,
)


class FakeScanner:
    """Stands in for clamd's ClamdNetworkSocket."""

    def __init__(self, status="OK", signature=None, raises=None):
        self.status = status
        self.signature = signature
        self.raises = raises
        self.calls = 0

    def instream(self, stream):
        self.calls += 1
        if self.raises:
            raise self.raises
        stream.read()
        return {"stream": (self.status, self.signature)}


@pytest.fixture()
def storage(tmp_path):
    backend = LocalStorageBackend(
        upload_folder=str(tmp_path / "live"),
        quarantine_folder=str(tmp_path / "quarantine"),
    )
    backend.ensure_directories()
    return backend


def _quarantine(storage, name="doc.pdf", data=b"harmless bytes"):
    path = f"{storage.quarantine_folder}/{name}"
    with open(path, "wb") as handle:
        handle.write(data)
    return name


def test_clean_object_is_promoted(storage):
    name = _quarantine(storage)

    outcome = scan_and_promote(name, storage, lambda: FakeScanner("OK"))

    assert outcome.status is ScanStatus.CLEAN
    assert outcome.promoted is True
    assert storage.exists_live(name)
    assert not storage.exists_quarantine(name)


def test_infected_object_stays_quarantined(storage):
    name = _quarantine(storage, data=b"pretend-eicar")

    outcome = scan_and_promote(name, storage, lambda: FakeScanner("FOUND", "Test.Sig"))

    assert outcome.status is ScanStatus.INFECTED
    assert outcome.signature == "Test.Sig"
    assert outcome.promoted is False
    # The critical assertion: an infected object must never reach live storage.
    assert not storage.exists_live(name)
    assert storage.exists_quarantine(name)


def test_infected_object_deleted_when_requested(storage):
    name = _quarantine(storage)

    scan_and_promote(
        name, storage, lambda: FakeScanner("FOUND", "Test.Sig"), delete_infected=True
    )

    assert not storage.exists_quarantine(name)
    assert not storage.exists_live(name)


def test_missing_object_is_terminal_not_retriable(storage):
    outcome = scan_and_promote("nope.pdf", storage, lambda: FakeScanner("OK"))

    assert outcome.status is ScanStatus.FAILED
    assert outcome.retriable is False


def test_already_clean_and_live_is_a_noop(storage):
    name = "done.pdf"
    with open(f"{storage.upload_folder}/{name}", "wb") as handle:
        handle.write(b"x")
    scanner = FakeScanner("OK")

    outcome = scan_and_promote(name, storage, lambda: scanner, already_clean=True)

    assert outcome.status is ScanStatus.CLEAN
    assert outcome.promoted is False
    assert scanner.calls == 0, "must not re-scan an object already recorded clean"


def test_live_but_not_recorded_clean_is_rescanned_in_place(storage):
    """Covers a crash between promotion and the status write."""
    name = "half.pdf"
    with open(f"{storage.upload_folder}/{name}", "wb") as handle:
        handle.write(b"x")
    scanner = FakeScanner("OK")

    outcome = scan_and_promote(name, storage, lambda: scanner, already_clean=False)

    assert scanner.calls == 1
    assert outcome.status is ScanStatus.CLEAN
    assert outcome.promoted is False


def test_unreachable_scanner_is_retriable(storage):
    name = _quarantine(storage)

    def boom():
        raise ConnectionRefusedError("scanner down")

    outcome = scan_and_promote(name, storage, boom)

    assert outcome.status is ScanStatus.FAILED
    assert outcome.retriable is True
    assert storage.exists_quarantine(name), "object must stay quarantined"


def test_scan_error_is_retriable(storage):
    name = _quarantine(storage)

    outcome = scan_and_promote(
        name, storage, lambda: FakeScanner(raises=TimeoutError("slow"))
    )

    assert outcome.status is ScanStatus.FAILED
    assert outcome.retriable is True


def test_unparseable_response_is_terminal(storage):
    name = _quarantine(storage)

    class Weird:
        def instream(self, stream):
            return {}

    outcome = scan_and_promote(name, storage, Weird)

    assert outcome.status is ScanStatus.FAILED
    assert outcome.retriable is False


def test_promotion_failure_keeps_object_out_of_live(storage, monkeypatch):
    name = _quarantine(storage)

    def explode(_):
        raise OSError("disk full")

    monkeypatch.setattr(storage, "promote_quarantine_to_live", explode)

    outcome = scan_and_promote(name, storage, lambda: FakeScanner("OK"))

    assert outcome.status is ScanStatus.FAILED
    assert outcome.retriable is True
    assert not storage.exists_live(name)
