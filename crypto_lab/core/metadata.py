"""Helpers for nonce/salt/tag/algorithm info encoding and decoding."""

import base64
from datetime import datetime, timezone
from typing import Optional

from crypto_lab.config import SCHEMA_VERSION
from crypto_lab.models.payload import EncryptionMetadata


def build_metadata(
    alg_id: str,
    nonce: Optional[bytes] = None,
    salt: Optional[bytes] = None,
    tag: Optional[bytes] = None,
    kdf: Optional[str] = None,
    iterations: Optional[int] = None,
    notes: Optional[str] = None,
) -> EncryptionMetadata:
    """Build EncryptionMetadata with optional fields."""
    return EncryptionMetadata(
        alg_id=alg_id,
        version=SCHEMA_VERSION,
        nonce=nonce,
        salt=salt,
        tag=tag,
        kdf=kdf,
        iterations=iterations,
        created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        notes=notes,
    )


def metadata_to_dict(meta: EncryptionMetadata) -> dict:
    """Serialize metadata for JSON (bytes as base64)."""
    return meta.model_dump_json_safe()


def metadata_from_dict(d: dict) -> EncryptionMetadata:
    """Deserialize metadata from JSON."""
    return EncryptionMetadata.from_json_safe(d)
