# quarantine-scan

**Quarantine → antivirus scan → promote** for user uploads. Uploaded bytes land
in a space nothing user-facing can read; a background worker scans them; only a
clean verdict moves them to live storage.

The core has **no dependencies** and imports no web framework, ORM, or task
queue. Celery, ClamAV and S3 are optional extras.

```python
from quarantine_scan import LocalStorageBackend, clamav_scanner_factory, scan_and_promote

storage = LocalStorageBackend(upload_folder="live", quarantine_folder="quarantine")
outcome = scan_and_promote("invoice.pdf", storage, clamav_scanner_factory("clamav"))

if outcome.is_clean:
    ...   # the file is now in live/, safe to serve
```

## Why quarantine at all

The common shape is: save the upload where the app serves from, then scan it.
That leaves a window — often seconds, sometimes minutes if the queue is backed
up — where unscanned attacker-controlled bytes are reachable at a URL. Antivirus
becomes a report rather than a control.

Two spaces closes the window. Nothing reaches the live space without a clean
verdict, so the worst case of a slow or broken scanner is an upload that stays
pending — not one that gets served.

## Try it

```bash
docker compose up --build -d          # ClamAV + Redis + a scan worker
docker compose run --rm demo          # writes 2 files, scans them, reports
```

The demo writes a harmless file and the [EICAR test
signature](https://www.eicar.org/download-anti-malware-testfile/) into
quarantine and queues both. Expected output: the harmless file promoted to
`live/`, EICAR still sitting in `quarantine/`.

> First start is slow. The ClamAV image downloads a ~200 MB signature database
> before it reports healthy, and the worker is gated on that healthcheck — so it
> can't scan against an empty signature set. Two to five minutes on a cold pull.

## Install

```bash
pip install quarantine-scan[clamav,celery]     # add s3 for object storage
```

| Extra | Pulls in | For |
|---|---|---|
| `clamav` | `clamd` | The ClamAV scanner client |
| `celery` | `celery` | The async task wiring |
| `s3` | `boto3` | S3 / MinIO / R2 / Hetzner object storage |

Core install has zero dependencies — useful if you bring your own scanner or
storage.

## Design

### Idempotent, because a task can be delivered twice

`scan_and_promote()` is safe to run repeatedly on the same object:

| State | Behaviour |
|---|---|
| Live **and** already recorded clean | No-op. Does not re-scan |
| In neither space | Terminal failure, **not** a retry — retrying cannot conjure missing bytes |
| Live but not yet recorded clean | Re-scans in place. Covers a crash between the copy and the status write |
| In quarantine | Normal path: scan, then promote or hold |

### Retriable vs terminal

`ScanOutcome.retriable` distinguishes *the scan didn't happen* from *the scan
happened and here's the verdict*. Scanner unreachable, read error, promotion
failure — retriable. Clean, infected, unparseable response, file missing —
terminal. Retrying a verdict just burns worker time; retrying a connection
failure is the whole point.

The Celery wrapper retries only while attempts remain, then records the terminal
failure. Without that last step an object with a permanently unreachable scanner
sits in quarantine forever with no state written anywhere.

### Promotion failure keeps the object out of live storage

If a scan says clean but the move fails, the outcome is `FAILED`, not `CLEAN`.
Reporting clean would mark it available while the bytes are still quarantined —
a phantom file. Better to leave it visibly incomplete.

### A dedicated queue

Scanning streams whole files through ClamAV: slow, bursty, and memory-hungry
relative to ordinary jobs. On a shared queue it head-of-line blocks everything
else. `register_scan_task()` routes to `virus_scan` by default, so scan workers
scale — and can be stopped — independently.

Tasks are declared `acks_late=True`: a worker killed mid-scan leaves the job on
the broker for redelivery, which the idempotency above makes safe.

### Storage backends

`LocalStorageBackend` (two directories) and `S3StorageBackend` (one bucket, two
key prefixes) ship. S3 promotion is a server-side copy then delete — bytes never
transit the application.

Two details worth knowing if you implement your own backend:

- **`exists_*` must not swallow errors.** The S3 backend treats only a genuine
  404 as "absent" and re-raises everything else. Returning `False` on a
  permissions or throttling error reads as "object missing" and silently
  discards data.
- **Promotion is not atomic.** A crash between copy and delete leaves an object
  in both spaces. That's why "already live" is a success state.

Subclass `BaseStorageBackend` to add another.

## Integrating

```python
from celery import Celery
from quarantine_scan import backend_from_config, clamav_scanner_factory
from quarantine_scan.celery_integration import register_scan_task

celery_app = Celery("myapp", broker="redis://localhost:6379/0")

def persist(stored_filename, outcome):
    doc = Document.query.filter_by(stored_filename=stored_filename).one()
    doc.scan_status = outcome.status.value
    doc.scan_message = outcome.message
    db.session.commit()

scan_task = register_scan_task(
    celery_app,
    storage_factory=lambda: backend_from_config(os.environ),
    scanner_factory=clamav_scanner_factory(host="clamav"),
    on_outcome=persist,
)

# In your upload handler:
storage.save_to_quarantine(request.files["file"], stored_filename)
scan_task.delay(stored_filename)
```

`storage_factory` is a callable rather than an instance on purpose: each forked
worker builds its own client instead of inheriting the parent's socket.

`backend_from_config()` takes any mapping with `.get()` — `os.environ`, a Flask
`app.config`, a plain dict.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `STORAGE_BACKEND` | `local` | `local` or `s3` |
| `UPLOAD_FOLDER` | `uploads` | Live space (local backend) |
| `QUARANTINE_FOLDER` | `<uploads>/quarantine` | **Keep this outside anything your web server serves** |
| `S3_BUCKET` / `S3_ACCESS_KEY` / `S3_SECRET_KEY` | — | Required for `s3` |
| `S3_ENDPOINT_URL` | AWS | Set for MinIO / R2 / Hetzner / B2 |
| `S3_QUARANTINE_PREFIX` | `quarantine/` | |
| `S3_UPLOADS_PREFIX` | `uploads/` | |
| `S3_ADDRESSING_STYLE` | `path` | MinIO and several providers need path style |

## Tests

```bash
pip install -e ".[dev]"
pytest
```

10 tests, no ClamAV or broker required — the core is framework-free, so a fake
scanner and a temp directory cover the whole state machine including the crash
paths.

## Not included

- **Content-type and size validation.** Do that at the upload boundary, before
  anything is written.
- **Signature database updates.** The ClamAV image handles `freshclam` itself.
- **Deduplication.** `stored_filename` is whatever you pass; content-hash names
  are a good idea and out of scope here.

## Licence

MIT — see [LICENSE](LICENSE).
