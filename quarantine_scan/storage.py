"""Storage backends for the two-space (quarantine + live) object lifecycle.

Every upload lands in a quarantine space that nothing user-facing can read from.
Only once a scan returns clean does the object move to the live space. The two
spaces are separate directories on local disk, or separate key prefixes in one
S3 bucket.
"""

from __future__ import annotations

import os
import shutil
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Iterator, Mapping

from .errors import InvalidStorageConfiguration, MissingObjectError


class BaseStorageBackend:
    """Interface for backends handling the quarantine/live lifecycle.

    Implement this to add a backend (Azure Blob, GCS, …). The scanner depends on
    this interface only, never on a concrete backend.
    """

    def save_to_quarantine(
        self, file_obj: BinaryIO, stored_filename: str, content_type: str | None = None
    ) -> None:
        raise NotImplementedError

    def promote_quarantine_to_live(self, stored_filename: str) -> None:
        raise NotImplementedError

    def open_live_stream(self, stored_filename: str):
        raise NotImplementedError

    def open_quarantine_stream(self, stored_filename: str):
        raise NotImplementedError

    def exists_live(self, stored_filename: str) -> bool:
        raise NotImplementedError

    def exists_quarantine(self, stored_filename: str) -> bool:
        raise NotImplementedError

    def delete_live(self, stored_filename: str) -> None:
        raise NotImplementedError

    def delete_quarantine(self, stored_filename: str) -> None:
        raise NotImplementedError

    def save_path_to_live(
        self, file_path: str, stored_filename: str, content_type: str | None = None
    ) -> None:
        raise NotImplementedError

    def save_path_to_quarantine(
        self, file_path: str, stored_filename: str, content_type: str | None = None
    ) -> None:
        raise NotImplementedError


@dataclass
class LocalStorageBackend(BaseStorageBackend):
    """Two directories on local disk. Fine for development and single-node deploys.

    Keep `quarantine_folder` outside any directory your web server serves — the
    whole point is that unscanned bytes are unreachable.
    """

    upload_folder: str
    quarantine_folder: str

    def ensure_directories(self) -> None:
        os.makedirs(self.upload_folder, exist_ok=True)
        os.makedirs(self.quarantine_folder, exist_ok=True)

    def _live_path(self, stored_filename: str) -> str:
        return os.path.join(self.upload_folder, stored_filename)

    def _quarantine_path(self, stored_filename: str) -> str:
        return os.path.join(self.quarantine_folder, stored_filename)

    def save_to_quarantine(
        self, file_obj: BinaryIO, stored_filename: str, content_type: str | None = None
    ) -> None:
        del content_type
        self.ensure_directories()
        destination = self._quarantine_path(stored_filename)
        # Accept either a plain binary file object or a framework upload wrapper
        # that exposes .save() (Werkzeug's FileStorage, for instance).
        save = getattr(file_obj, "save", None)
        if callable(save):
            save(destination)
            return
        try:
            file_obj.seek(0)
        except Exception:
            pass
        with open(destination, "wb") as handle:
            shutil.copyfileobj(file_obj, handle)

    def promote_quarantine_to_live(self, stored_filename: str) -> None:
        self.ensure_directories()
        source = self._quarantine_path(stored_filename)
        if not os.path.exists(source):
            raise MissingObjectError(f"Quarantine object not found: {stored_filename}")
        shutil.move(source, self._live_path(stored_filename))

    @contextmanager
    def open_live_stream(self, stored_filename: str) -> Iterator[BinaryIO]:
        path = self._live_path(stored_filename)
        if not os.path.exists(path):
            raise MissingObjectError(f"Live object not found: {stored_filename}")
        with open(path, "rb") as handle:
            yield handle

    @contextmanager
    def open_quarantine_stream(self, stored_filename: str) -> Iterator[BinaryIO]:
        path = self._quarantine_path(stored_filename)
        if not os.path.exists(path):
            raise MissingObjectError(f"Quarantine object not found: {stored_filename}")
        with open(path, "rb") as handle:
            yield handle

    def exists_live(self, stored_filename: str) -> bool:
        return os.path.exists(self._live_path(stored_filename))

    def exists_quarantine(self, stored_filename: str) -> bool:
        return os.path.exists(self._quarantine_path(stored_filename))

    def delete_live(self, stored_filename: str) -> None:
        path = self._live_path(stored_filename)
        if os.path.exists(path):
            os.remove(path)

    def delete_quarantine(self, stored_filename: str) -> None:
        path = self._quarantine_path(stored_filename)
        if os.path.exists(path):
            os.remove(path)

    def save_path_to_live(
        self, file_path: str, stored_filename: str, content_type: str | None = None
    ) -> None:
        del content_type
        self.ensure_directories()
        shutil.copy2(file_path, self._live_path(stored_filename))

    def save_path_to_quarantine(
        self, file_path: str, stored_filename: str, content_type: str | None = None
    ) -> None:
        del content_type
        self.ensure_directories()
        shutil.copy2(file_path, self._quarantine_path(stored_filename))


@dataclass
class S3StorageBackend(BaseStorageBackend):
    """One bucket, two key prefixes. Works with AWS S3, MinIO, Hetzner, R2, B2.

    Promotion is a server-side copy followed by a delete — the bytes never
    transit the application. Note this is not atomic: a crash between the two
    leaves a copy in both spaces. The scanner treats "already live" as success,
    so a retry converges.
    """

    endpoint_url: str | None
    region: str
    access_key: str
    secret_key: str
    bucket: str
    quarantine_prefix: str = "quarantine/"
    uploads_prefix: str = "uploads/"
    use_ssl: bool = True
    addressing_style: str = "path"
    client: Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.client is not None:
            return
        try:
            import boto3
            from botocore.config import Config as BotoConfig
        except ImportError as exc:  # pragma: no cover - import guard
            raise InvalidStorageConfiguration(
                "S3StorageBackend requires the 's3' extra: pip install "
                "quarantine-scan[s3]"
            ) from exc

        session = boto3.session.Session()
        self.client = session.client(
            "s3",
            endpoint_url=self.endpoint_url,
            region_name=self.region,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            use_ssl=self.use_ssl,
            # Path addressing: MinIO and several S3-compatible providers do not
            # support virtual-host style buckets.
            config=BotoConfig(s3={"addressing_style": self.addressing_style}),
        )

    @staticmethod
    def _normalize_prefix(prefix: str) -> str:
        cleaned = (prefix or "").strip().strip("/")
        return f"{cleaned}/" if cleaned else ""

    def _live_key(self, stored_filename: str) -> str:
        return f"{self._normalize_prefix(self.uploads_prefix)}{stored_filename}"

    def _quarantine_key(self, stored_filename: str) -> str:
        return f"{self._normalize_prefix(self.quarantine_prefix)}{stored_filename}"

    def _exists_key(self, key: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            # Only a genuine "not found" is False. Anything else — permissions,
            # throttling, a broken endpoint — must propagate, or a transient
            # error silently reads as "object absent" and data goes missing.
            if code in {"404", "NoSuchKey", "NotFound"}:
                return False
            raise

    def _delete_key(self, key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=key)

    @contextmanager
    def _open_key_stream(self, key: str) -> Iterator[BinaryIO]:
        from botocore.exceptions import ClientError

        try:
            response = self.client.get_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in {"404", "NoSuchKey", "NotFound"}:
                raise MissingObjectError(f"Object not found: {key}") from exc
            raise

        body = response["Body"]
        try:
            yield body
        finally:
            body.close()

    def save_to_quarantine(
        self, file_obj: BinaryIO, stored_filename: str, content_type: str | None = None
    ) -> None:
        key = self._quarantine_key(stored_filename)
        try:
            file_obj.seek(0)
        except Exception:
            pass
        extra_args = {"ContentType": content_type} if content_type else None
        if extra_args:
            self.client.upload_fileobj(file_obj, self.bucket, key, ExtraArgs=extra_args)
        else:
            self.client.upload_fileobj(file_obj, self.bucket, key)

    def promote_quarantine_to_live(self, stored_filename: str) -> None:
        source_key = self._quarantine_key(stored_filename)
        destination_key = self._live_key(stored_filename)
        if not self._exists_key(source_key):
            raise MissingObjectError(f"Quarantine object not found: {stored_filename}")

        self.client.copy_object(
            Bucket=self.bucket,
            CopySource={"Bucket": self.bucket, "Key": source_key},
            Key=destination_key,
        )
        self._delete_key(source_key)

    def open_live_stream(self, stored_filename: str):
        return self._open_key_stream(self._live_key(stored_filename))

    def open_quarantine_stream(self, stored_filename: str):
        return self._open_key_stream(self._quarantine_key(stored_filename))

    def exists_live(self, stored_filename: str) -> bool:
        return self._exists_key(self._live_key(stored_filename))

    def exists_quarantine(self, stored_filename: str) -> bool:
        return self._exists_key(self._quarantine_key(stored_filename))

    def delete_live(self, stored_filename: str) -> None:
        self._delete_key(self._live_key(stored_filename))

    def delete_quarantine(self, stored_filename: str) -> None:
        self._delete_key(self._quarantine_key(stored_filename))

    def save_path_to_live(
        self, file_path: str, stored_filename: str, content_type: str | None = None
    ) -> None:
        extra_args = {"ContentType": content_type} if content_type else None
        if extra_args:
            self.client.upload_file(file_path, self.bucket, self._live_key(stored_filename), ExtraArgs=extra_args)
        else:
            self.client.upload_file(file_path, self.bucket, self._live_key(stored_filename))

    def save_path_to_quarantine(
        self, file_path: str, stored_filename: str, content_type: str | None = None
    ) -> None:
        extra_args = {"ContentType": content_type} if content_type else None
        if extra_args:
            self.client.upload_file(file_path, self.bucket, self._quarantine_key(stored_filename), ExtraArgs=extra_args)
        else:
            self.client.upload_file(file_path, self.bucket, self._quarantine_key(stored_filename))


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def backend_from_config(config: Mapping[str, Any]) -> BaseStorageBackend:
    """Build a backend from a plain mapping.

    Works with `os.environ`, a Flask `app.config`, a dict, or anything else
    supporting `.get()` — the library never imports a web framework.
    """
    backend_name = str(config.get("STORAGE_BACKEND", "local")).strip().lower()

    if backend_name == "local":
        upload_folder = config.get("UPLOAD_FOLDER", "uploads")
        quarantine_folder = config.get("QUARANTINE_FOLDER") or os.path.join(
            upload_folder, "quarantine"
        )
        return LocalStorageBackend(
            upload_folder=upload_folder, quarantine_folder=quarantine_folder
        )

    if backend_name == "s3":
        bucket = config.get("S3_BUCKET")
        access_key = config.get("S3_ACCESS_KEY")
        secret_key = config.get("S3_SECRET_KEY")
        if not bucket or not access_key or not secret_key:
            raise InvalidStorageConfiguration(
                "S3_BUCKET, S3_ACCESS_KEY and S3_SECRET_KEY are required for the S3 backend."
            )
        return S3StorageBackend(
            endpoint_url=config.get("S3_ENDPOINT_URL"),
            region=config.get("S3_REGION", "us-east-1"),
            access_key=access_key,
            secret_key=secret_key,
            bucket=bucket,
            quarantine_prefix=config.get("S3_QUARANTINE_PREFIX", "quarantine/"),
            uploads_prefix=config.get("S3_UPLOADS_PREFIX", "uploads/"),
            use_ssl=_as_bool(config.get("S3_USE_SSL"), default=True),
            addressing_style=config.get("S3_ADDRESSING_STYLE", "path"),
        )

    raise InvalidStorageConfiguration(f"Unsupported STORAGE_BACKEND: {backend_name}")
