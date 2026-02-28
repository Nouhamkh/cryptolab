"""Dataclasses / Pydantic models for encryption inputs, outputs, and metadata."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class EncryptionMetadata(BaseModel):
    """Metadata stored with encrypted data (nonce, salt, tag, algorithm info)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    alg_id: str = Field(..., description="Algorithm identifier")
    version: int = Field(1, description="Schema/metadata version")
    nonce: Optional[bytes] = Field(None, description="Nonce/IV (base64 in JSON)")
    salt: Optional[bytes] = Field(None, description="Salt for KDF (base64 in JSON)")
    tag: Optional[bytes] = Field(None, description="Authentication tag (base64 in JSON)")
    kdf: Optional[str] = Field(None, description="Key derivation function name if PBE")
    iterations: Optional[int] = Field(None, description="KDF iteration count")
    created_at: Optional[str] = Field(
        None, description="ISO timestamp when encrypted"
    )
    notes: Optional[str] = Field(None, description="Optional human notes")

    def model_dump_json_safe(self) -> dict:
        """Serialize for JSON: bytes as base64 strings."""
        d = self.model_dump()
        for key in ("nonce", "salt", "tag"):
            if key in d and d[key] is not None:
                import base64

                d[key] = base64.b64encode(d[key]).decode("ascii")
        return d

    @classmethod
    def from_json_safe(cls, d: dict) -> "EncryptionMetadata":
        """Deserialize from JSON: base64 strings to bytes."""
        import base64

        for key in ("nonce", "salt", "tag"):
            if key in d and d[key] is not None and isinstance(d[key], str):
                d = {**d, key: base64.b64decode(d[key])}
        return cls.model_validate(d)


class CipherEnvelope(BaseModel):
    """Top-level envelope: header (metadata) + ciphertext (base64 for text)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    schema_version: int = Field(1, description="Envelope format version")
    header: dict = Field(..., description="EncryptionMetadata as JSON-safe dict")
    ciphertext_b64: Optional[str] = Field(None, description="Base64 ciphertext for text mode")
    ciphertext_raw: Optional[bytes] = Field(None, description="Raw ciphertext for binary/file")
