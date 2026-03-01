"""Base64/JSON wrappers and binary framing for file outputs."""

import base64
import json
from typing import Optional

from crypto_lab.config import MAGIC_HEADER, SCHEMA_VERSION
from crypto_lab.core.metadata import metadata_to_dict, metadata_from_dict
from crypto_lab.models.payload import CipherEnvelope, EncryptionMetadata


def serialize_text_envelope(ciphertext: bytes, metadata: EncryptionMetadata) -> str:
    """Produce a JSON string: header + ciphertext in multiple representations."""
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "header": metadata_to_dict(metadata),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        # Plain view: hex-encoded bytes so it's human-readable without base64.
        "ciphertext_hex": ciphertext.hex(),
    }
    return json.dumps(envelope)


def deserialize_text_envelope(payload: str) -> tuple[bytes, EncryptionMetadata]:
    """Parse JSON envelope; return (ciphertext_bytes, metadata)."""
    data = json.loads(payload)
    meta = metadata_from_dict(data["header"])
    ct = base64.b64decode(data["ciphertext_b64"])
    return ct, meta


def serialize_file_envelope(ciphertext: bytes, metadata: EncryptionMetadata) -> bytes:
    """Binary format: MAGIC_HEADER + 4-byte JSON length (big-endian) + JSON + raw ciphertext."""
    header_json = json.dumps(metadata_to_dict(metadata)).encode("utf-8")
    length_bytes = len(header_json).to_bytes(4, "big")
    return MAGIC_HEADER + length_bytes + header_json + ciphertext


def deserialize_file_envelope(payload: bytes) -> tuple[bytes, EncryptionMetadata]:
    """Parse binary envelope; return (ciphertext_bytes, metadata)."""
    from crypto_lab.config import MAGIC_HEADER
    from crypto_lab.exceptions import InvalidMetadataError

    if len(payload) < len(MAGIC_HEADER) + 4:
        raise InvalidMetadataError("File envelope too short")
    if payload[: len(MAGIC_HEADER)] != MAGIC_HEADER:
        raise InvalidMetadataError("Invalid magic header")
    json_len = int.from_bytes(payload[len(MAGIC_HEADER) : len(MAGIC_HEADER) + 4], "big")
    json_start = len(MAGIC_HEADER) + 4
    json_end = json_start + json_len
    if json_end > len(payload):
        raise InvalidMetadataError("Corrupt envelope: header length exceeds payload")
    header_dict = json.loads(payload[json_start:json_end].decode("utf-8"))
    meta = metadata_from_dict(header_dict)
    ct = payload[json_end:]
    return ct, meta
