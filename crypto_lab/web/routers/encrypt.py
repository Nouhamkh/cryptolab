"""Endpoints to encrypt text and files."""

import base64
from typing import Optional

from fastapi import APIRouter, HTTPException, Header, UploadFile, File, Form

from crypto_lab.config import DEFAULT_PBKDF2_ITERATIONS, MAX_FILE_SIZE_BYTES, REQUIRE_ACK_FOR_EDUCATIONAL
from crypto_lab.core.registry import get_cipher
from crypto_lab.core.serialization import serialize_text_envelope, serialize_file_envelope
from crypto_lab.core.metadata import metadata_to_dict
from crypto_lab.models.enums import CipherClass
from crypto_lab.models.payload import EncryptionMetadata
from crypto_lab.exceptions import (
    CipherNotFoundError,
    EncryptionError,
    UnsupportedDataTypeError,
)
from crypto_lab.modern.pbes2_kdf import derive_key_pbkdf2

from crypto_lab.web.schemas import EncryptTextRequest, EncryptTextResponse

router = APIRouter(prefix="/api", tags=["encrypt"])


def _resolve_key(
    key_b64: Optional[str],
    password: Optional[str],
    min_key_bytes: int,
    metadata: Optional[EncryptionMetadata] = None,
) -> tuple[bytes, Optional[EncryptionMetadata]]:
    """Resolve key from key_b64 or password. For password, derive via PBKDF2; returns key and optional updated metadata (with salt/kdf/iterations) for encrypt."""
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
        return key, None
    # password
    pwd_bytes = password.encode("utf-8")
    if metadata and metadata.salt is not None and metadata.iterations is not None:
        # Decrypt path: use salt and iterations from envelope
        from crypto_lab.modern.key_management import derive_key_from_password
        key = derive_key_from_password(pwd_bytes, metadata.salt, key_len, metadata.iterations)
        return key, None
    # Encrypt path: new salt
    key, salt = derive_key_pbkdf2(pwd_bytes, None, DEFAULT_PBKDF2_ITERATIONS, key_len)
    # Caller must merge salt/kdf/iterations into metadata
    extra = EncryptionMetadata(
        alg_id="",
        version=1,
        salt=salt,
        kdf="pbkdf2-hmac-sha256",
        iterations=DEFAULT_PBKDF2_ITERATIONS,
    )
    return key, extra


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


@router.post("/encrypt/text", response_model=EncryptTextResponse)
def encrypt_text(
    body: EncryptTextRequest,
    x_acknowledge_educational: Optional[str] = Header(None, alias="X-Acknowledge-Educational"),
):
    """Encrypt plaintext with the given algorithm. Provide key_b64 (base64 raw key) or password."""
    try:
        cipher = get_cipher(body.algorithm_id)
    except CipherNotFoundError as e:
        raise HTTPException(404, str(e)) from e
    _check_educational_ack(cipher.classification, x_acknowledge_educational)
    if not cipher.supports_text:
        raise HTTPException(400, "This algorithm does not support text encryption")
    min_key = cipher.min_key_bytes or 32
    key, extra_meta = _resolve_key(body.key_b64, body.password, min_key, None)
    try:
        plaintext_bytes = body.plaintext.encode("utf-8")
        ct, meta = cipher.encrypt_bytes(plaintext_bytes, key)
    except EncryptionError as e:
        raise HTTPException(400, str(e)) from e
    if extra_meta:
        meta = EncryptionMetadata(
            alg_id=meta.alg_id,
            version=meta.version,
            nonce=meta.nonce,
            salt=extra_meta.salt,
            tag=meta.tag,
            kdf=extra_meta.kdf,
            iterations=extra_meta.iterations,
            created_at=meta.created_at,
            notes=meta.notes,
        )
    envelope_json = serialize_text_envelope(ct, meta)
    return EncryptTextResponse(
        envelope_json=envelope_json,
        algorithm_id=body.algorithm_id,
        metadata=metadata_to_dict(meta),
    )


@router.post("/encrypt/file")
async def encrypt_file(
    algorithm_id: str = Form(...),
    key_b64: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    file: UploadFile = File(...),
    x_acknowledge_educational: Optional[str] = Header(None, alias="X-Acknowledge-Educational"),
):
    """Encrypt uploaded file. Returns binary envelope (CLAB1 format)."""
    try:
        cipher = get_cipher(algorithm_id)
    except CipherNotFoundError as e:
        raise HTTPException(404, str(e)) from e
    _check_educational_ack(cipher.classification, x_acknowledge_educational)
    if not cipher.supports_file:
        raise HTTPException(400, "This algorithm does not support file encryption")
    min_key = cipher.min_key_bytes or 32
    key, extra_meta = _resolve_key(key_b64, password, min_key, None)
    data = await file.read()
    if len(data) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(400, f"File too large (max {MAX_FILE_SIZE_BYTES} bytes)")
    try:
        ct, meta = cipher.encrypt_bytes(data, key)
    except EncryptionError as e:
        raise HTTPException(400, str(e)) from e
    if extra_meta:
        meta = EncryptionMetadata(
            alg_id=meta.alg_id,
            version=meta.version,
            nonce=meta.nonce,
            salt=extra_meta.salt,
            tag=meta.tag,
            kdf=extra_meta.kdf,
            iterations=extra_meta.iterations,
            created_at=meta.created_at,
            notes=meta.notes,
        )
    payload = serialize_file_envelope(ct, meta)
    from fastapi.responses import Response
    return Response(
        content=payload,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=encrypted.bin"},
    )

