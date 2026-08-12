"""Exception hierarchy for the quarantine/scan/promote pipeline."""

from __future__ import annotations


class StorageBackendError(Exception):
    """Base class for storage failures."""


class MissingObjectError(StorageBackendError):
    """A referenced object does not exist in the expected location."""


class InvalidStorageConfiguration(StorageBackendError):
    """Backend settings are missing or contradictory."""


class ScannerUnavailableError(Exception):
    """The virus scanner could not be reached.

    Distinct from a scan that ran and returned a verdict: this one is
    retriable, a verdict is not.
    """
