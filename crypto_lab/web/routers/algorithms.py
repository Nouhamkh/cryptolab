"""List algorithms and key generation."""

from fastapi import APIRouter, HTTPException

from crypto_lab.core.registry import list_ciphers
from crypto_lab.models.enums import CipherClass, DataType
from crypto_lab.modern.key_management import generate_key

router = APIRouter(prefix="/api", tags=["algorithms"])


def _normalize_meta(meta: dict) -> dict:
    """Ensure classification and other enums are JSON-serializable strings."""
    out = dict(meta)
    if "classification" in out and hasattr(out["classification"], "value"):
        out["classification"] = out["classification"].value
    return out


@router.get("/key/generate")
def generate_random_key(bytes: int = 32):
    """Generate a random key (base64). Use bytes=32 for AES-GCM, ChaCha20, Fernet."""
    if bytes < 1 or bytes > 64:
        raise HTTPException(400, "bytes must be between 1 and 64")
    key = generate_key(bytes)
    import base64
    return {"key_b64": base64.b64encode(key).decode("ascii")}


@router.get("/algorithms")
def get_algorithms(
    classification: str | None = None,
    data_type: str | None = None,
):
    """List registered ciphers. Filter by classification (educational, legacy, modern_recommended) or data_type (text, file)."""
    cls_filter = None
    if classification:
        try:
            cls_filter = CipherClass(classification)
        except ValueError:
            pass
    dt_filter = None
    if data_type:
        try:
            dt_filter = DataType(data_type)
        except ValueError:
            pass
    items = list_ciphers(classification=cls_filter, data_type=dt_filter)
    return {"algorithms": [_normalize_meta(m) for m in items]}


@router.get("/algorithms/modern")
def get_modern_algorithms():
    """List only modern recommended ciphers (default tab)."""
    items = list_ciphers(classification=CipherClass.MODERN_RECOMMENDED)
    return {"algorithms": [_normalize_meta(m) for m in items]}


@router.get("/algorithms/educational")
def get_educational_algorithms():
    """List educational (toy) ciphers. For teaching only."""
    items = list_ciphers(classification=CipherClass.EDUCATIONAL)
    return {"algorithms": [_normalize_meta(m) for m in items]}
