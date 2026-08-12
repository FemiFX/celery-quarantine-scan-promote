"""Optional Celery wiring.

The scanner core has no Celery dependency. This module adds the parts that only
matter once scanning runs asynchronously: a dedicated queue, bounded retries,
and late acknowledgement.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from .scanner import ScanOutcome, scan_and_promote

logger = logging.getLogger(__name__)

DEFAULT_QUEUE = "virus_scan"
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_COUNTDOWN = 10


def apply_scan_routing(
    celery_app: Any,
    task_name: str = "quarantine_scan.scan_and_promote",
    queue: str = DEFAULT_QUEUE,
) -> None:
    """Route the scan task to its own queue.

    Why it needs one: scanning streams whole files through ClamAV and is slow and
    bursty. Left on the default queue it head-of-line blocks every other job. A
    dedicated queue lets you scale scan workers independently, and lets you stop
    them entirely without stopping the rest of the application.
    """
    routes = dict(getattr(celery_app.conf, "task_routes", None) or {})
    routes[task_name] = {"queue": queue}
    celery_app.conf.task_routes = routes


def register_scan_task(
    celery_app: Any,
    storage_factory: Callable[[], Any],
    scanner_factory: Callable[[], Any],
    *,
    task_name: str = "quarantine_scan.scan_and_promote",
    queue: str = DEFAULT_QUEUE,
    max_retries: int = DEFAULT_MAX_RETRIES,
    retry_countdown: int = DEFAULT_RETRY_COUNTDOWN,
    on_outcome: Callable[[str, ScanOutcome], None] | None = None,
    delete_infected: bool = False,
):
    """Register the scan task on an existing Celery app and return it.

    Args:
        celery_app: your configured Celery instance.
        storage_factory: callable returning a storage backend. A factory, not an
            instance, so each worker builds its own client rather than
            inheriting one across a fork.
        scanner_factory: callable returning a virus scanner.
        on_outcome: called with ``(stored_filename, outcome)`` after each scan.
            This is where you persist status to your database.
        delete_infected: remove infected objects instead of keeping them.

    The task is declared ``acks_late=True``: the message is acknowledged only
    after the task finishes, so a worker killed mid-scan leaves the job on the
    broker to be redelivered. Combined with the idempotency in
    ``scan_and_promote``, redelivery is safe.
    """
    apply_scan_routing(celery_app, task_name=task_name, queue=queue)

    @celery_app.task(
        bind=True,
        name=task_name,
        queue=queue,
        acks_late=True,
        max_retries=max_retries,
    )
    def scan_task(self, stored_filename: str, already_clean: bool = False):
        outcome = scan_and_promote(
            stored_filename,
            storage=storage_factory(),
            scanner_factory=scanner_factory,
            already_clean=already_clean,
            delete_infected=delete_infected,
        )

        # Retry only transient failures, and only while retries remain. On the
        # final attempt fall through and record the terminal failure — otherwise
        # the object sits in quarantine forever with no recorded state.
        retries_used = getattr(getattr(self, "request", None), "retries", 0) or 0
        if outcome.retriable and retries_used < max_retries:
            logger.warning(
                "Retrying scan of %s (attempt %s/%s): %s",
                stored_filename,
                retries_used + 1,
                max_retries,
                outcome.message,
            )
            raise self.retry(countdown=retry_countdown)

        if on_outcome is not None:
            on_outcome(stored_filename, outcome)
        return {
            "stored_filename": stored_filename,
            "status": outcome.status.value,
            "message": outcome.message,
            "signature": outcome.signature,
            "promoted": outcome.promoted,
        }

    return scan_task
