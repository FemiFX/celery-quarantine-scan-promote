"""Celery worker wiring for the demo stack.

Shows the whole integration in ~40 lines: build a storage backend and a scanner
factory from the environment, register the task, and persist outcomes.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from celery import Celery

from quarantine_scan import ScanOutcome, backend_from_config, clamav_scanner_factory
from quarantine_scan.celery_integration import register_scan_task

logging.basicConfig(level=logging.INFO)

celery_app = Celery(
    "demo",
    broker=os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0"),
    backend=os.environ.get("CELERY_RESULT_BACKEND", "redis://redis:6379/1"),
)
celery_app.conf.task_acks_late = True


def storage_factory():
    # A factory, not a module-level instance: each forked worker builds its own
    # client rather than inheriting a parent's socket.
    return backend_from_config(os.environ)


scanner_factory = clamav_scanner_factory(
    host=os.environ.get("CLAMAV_HOST", "clamav"),
    port=int(os.environ.get("CLAMAV_PORT", "3310")),
)

# Stand-in for "write the verdict to your database".
OUTCOMES = Path(os.environ.get("UPLOAD_FOLDER", "/data/live")).parent / "outcomes.jsonl"


def persist_outcome(stored_filename: str, outcome: ScanOutcome) -> None:
    OUTCOMES.parent.mkdir(parents=True, exist_ok=True)
    with OUTCOMES.open("a") as handle:
        handle.write(
            json.dumps(
                {
                    "file": stored_filename,
                    "status": outcome.status.value,
                    "message": outcome.message,
                    "signature": outcome.signature,
                    "promoted": outcome.promoted,
                }
            )
            + "\n"
        )
    logging.info("Recorded %s -> %s", stored_filename, outcome.status.value)


scan_task = register_scan_task(
    celery_app,
    storage_factory=storage_factory,
    scanner_factory=scanner_factory,
    on_outcome=persist_outcome,
)
