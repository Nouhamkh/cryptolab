"""Endpoints to decrypt text and files."""

import base64
from typing import Optional

from fastapi import APIRouter, HTTPException, Header, UploadFile, File, Form
from fastapi.responses import Response

from crypto_lab.config import DEFAULT_PBKDF2_ITERATIONS, MAX_FILE_SIZE_BYTES, REQUIRE_ACK_FOR_EDUCATIONAL
from crypto_lab.core.registry import get_cipher
from crypto_lab.core.serialization import deserialize_text_envelope, deserialize_file_envelope
from crypto_lab.core.metadata import metadata_to_dict
from crypto_lab.models.enums import CipherClass
from crypto_lab.models.payload import EncryptionMetadata
from crypto_lab.exceptions import (
    CipherNotFoundError,
    DecryptionError,
    InvalidMetadataError,
)

from crypto_lab.web.schemas import DecryptTextRequest, DecryptTextResponse

router = APIRouter(prefix="/api", tags=["decrypt"])


def _resolve_key(
    key_b64: Optional[str],
    password: Optional[str],
    min_key_bytes: int,
    metadata: Optional[EncryptionMetadata] = None,
) -> bytes:
    """Resolve key for decryption. Password requires metadata with salt and iterations."""
    if key_b64 and password:
        raise HTTPException(400, "Provide either key_b64 or password, not both")
    if not key_b64 and not password:
        raise HTTPException(400, "Provide key_b64 or password")
    key_len = max(min_key_bytes, 32)
    if key_b64:
        try:
            key = base64.b64decode(key_b64)
        except Exception as e:
            raise HTTPException(400, f"Invalid key_b64: {e}") from e
        if len(key) < min_key_bytes:
            raise HTTPException(400, f"Key must be at least {min_key_bytes} bytes for this algorithm")
        return key
    if not metadata or metadata.salt is None or metadata.iterations is None:
        raise HTTPException(400, "Password decryption requires envelope with salt and iterations (was it encrypted with a password?)")
    from crypto_lab.modern.key_management import derive_key_from_password
    key = derive_key_from_password(password.encode("utf-8"), metadata.salt, key_len, metadata.iterations)
    return key


def _check_educational_ack(classification: CipherClass, acknowledge_educational: Optional[str]):
    if classification != CipherClass.EDUCATIONAL and classification != CipherClass.LEGACY:
        return
    if not REQUIRE_ACK_FOR_EDUCATIONAL:
        return
    if not acknowledge_educational or acknowledge_educational.lower() != "true":
        raise HTTPException(
            403,
            "Educational/legacy algorithms require header X-Acknowledge-Educational: true or query allow_educational=true",
        )


@router.post("/decrypt/text", response_model=DecryptTextResponse)
def decrypt_text(
    body: DecryptTextRequest,
    x_acknowledge_educational: Optional[str] = Header(None, alias="X-Acknowledge-Educational"),
):
    """Decrypt a JSON text envelope. Provide key_b64 or password (must match how it was encrypted)."""
    try:
        ct, meta = deserialize_text_envelope(body.envelope_json)
    except (InvalidMetadataError, ValueError, KeyError) as e:
        raise HTTPException(400, f"Invalid envelope: {e}") from e
    try:
        cipher = get_cipher(meta.alg_id)
    except CipherNotFoundError as e:
        raise HTTPException(404, str(e)) from e
    _check_educational_ack(cipher.classification, x_acknowledge_educational)
    min_key = cipher.min_key_bytes or 32
    key = _resolve_key(body.key_b64, body.password, min_key, meta)
    try:
        plaintext_bytes = cipher.decrypt_bytes(ct, key, meta)
        plaintext = plaintext_bytes.decode("utf-8")
    except DecryptionError as e:
        raise HTTPException(400, str(e)) from e
    return DecryptTextResponse(
        plaintext=plaintext,
        algorithm_id=meta.alg_id,
        metadata=metadata_to_dict(meta),
    )


@router.post("/decrypt/file")
async def decrypt_file(
    key_b64: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    file: UploadFile = File(...),
    x_acknowledge_educational: Optional[str] = Header(None, alias="X-Acknowledge-Educational"),
):
    """Decrypt uploaded binary envelope (CLAB1 format). Returns raw decrypted file."""
    data = await file.read()
    if len(data) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(400, f"File too large (max {MAX_FILE_SIZE_BYTES} bytes)")
    try:
        ct, meta = deserialize_file_envelope(data)
    except (InvalidMetadataError, ValueError, KeyError) as e:
        raise HTTPException(400, f"Invalid envelope: {e}") from e
    try:
        cipher = get_cipher(meta.alg_id)
    except CipherNotFoundError as e:
        raise HTTPException(404, str(e)) from e
    _check_educational_ack(cipher.classification, x_acknowledge_educational)
    min_key = cipher.min_key_bytes or 32
    key = _resolve_key(key_b64, password, min_key, meta)
    try:
        plaintext = cipher.decrypt_bytes(ct, key, meta)
    except DecryptionError as e:
        raise HTTPException(400, str(e)) from e
    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=decrypted.bin"},
    )

