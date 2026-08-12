"""Drive the demo end to end.

Writes two files into quarantine — one harmless, one the EICAR test signature —
queues a scan for each, and reports where they ended up.

EICAR is the industry-standard antivirus test string. It is completely harmless
and is deliberately not obfuscated here; every scanner recognises it.

    docker compose run --rm demo python examples/demo.py
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from examples.worker import scan_task

QUARANTINE = Path(os.environ.get("QUARANTINE_FOLDER", "/data/quarantine"))
LIVE = Path(os.environ.get("UPLOAD_FOLDER", "/data/live"))

# Assembled at runtime so this source file itself doesn't trip scanners.
EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode()

SAMPLES = {
    "harmless.txt": b"An entirely ordinary file.\n",
    "eicar.txt": EICAR,
}


def main() -> None:
    QUARANTINE.mkdir(parents=True, exist_ok=True)
    LIVE.mkdir(parents=True, exist_ok=True)

    print("Writing samples into quarantine…")
    for name, payload in SAMPLES.items():
        (QUARANTINE / name).write_bytes(payload)
        print(f"  quarantine/{name}  ({len(payload)} bytes)")

    print("\nQueueing scans…")
    results = {name: scan_task.delay(name) for name in SAMPLES}

    print("Waiting for the worker…\n")
    for name, async_result in results.items():
        outcome = async_result.get(timeout=180)
        print(f"  {name:<15} {outcome['status']:<9} {outcome['message']}")

    print("\nFinal state:")
    print(f"  live/       {sorted(p.name for p in LIVE.iterdir())}")
    print(f"  quarantine/ {sorted(p.name for p in QUARANTINE.iterdir())}")
    print(
        "\nExpected: harmless.txt promoted to live/, eicar.txt still in quarantine/.\n"
        "An infected upload never reaches the space the application serves from."
    )


if __name__ == "__main__":
    main()
    time.sleep(0.1)
