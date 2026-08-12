FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first so the layer caches across source edits.
COPY pyproject.toml README.md LICENSE ./
COPY quarantine_scan ./quarantine_scan
RUN pip install --no-cache-dir ".[clamav,celery,s3]"

COPY examples ./examples
COPY tests ./tests

# Run as a non-root user. The demo writes to /data, so it has to own it.
RUN useradd --create-home --uid 1000 app \
    && mkdir -p /data/live /data/quarantine \
    && chown -R app:app /data /app
USER app

CMD ["celery", "-A", "examples.worker", "worker", "-Q", "virus_scan", "-l", "info"]
