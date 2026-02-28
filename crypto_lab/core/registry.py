"""Central cipher registry and factory for instantiation."""

from typing import Any, Callable, Optional

from crypto_lab.models.enums import CipherClass, CipherStrength, DataType

# Registry: alg_id -> { "factory": callable, "meta": dict }
_REGISTRY: dict[str, dict[str, Any]] = {}


def register_cipher(
    algorithm_id: str,
    factory: Callable[[], Any],
    display_name: str,
    classification: CipherClass,
    family: str,
    strength: str,
    supports_text: bool = True,
    supports_file: bool = False,
    min_key_bytes: Optional[int] = None,
    doc_url: Optional[str] = None,
) -> None:
    """Register a cipher implementation."""
    _REGISTRY[algorithm_id] = {
        "factory": factory,
        "meta": {
            "algorithm_id": algorithm_id,
            "display_name": display_name,
            "classification": classification,
            "family": family,
            "strength": strength,
            "supports_text": supports_text,
            "supports_file": supports_file,
            "min_key_bytes": min_key_bytes,
            "doc_url": doc_url,
        },
    }


def get_cipher(algorithm_id: str):
    """Return an instance of the cipher for the given algorithm_id."""
    if algorithm_id not in _REGISTRY:
        from crypto_lab.exceptions import CipherNotFoundError
        raise CipherNotFoundError(f"Unknown algorithm: {algorithm_id}")
    return _REGISTRY[algorithm_id]["factory"]()


def list_ciphers(
    classification: Optional[CipherClass] = None,
    strength: Optional[CipherStrength] = None,
    data_type: Optional[DataType] = None,
) -> list[dict]:
    """List registered ciphers, optionally filtered."""
    result = []
    for alg_id, entry in _REGISTRY.items():
        meta = entry["meta"].copy()
        if classification is not None and meta["classification"] != classification:
            continue
        if strength is not None and meta["strength"] != strength.value:
            continue
        if data_type is not None:
            if data_type == DataType.TEXT and not meta["supports_text"]:
                continue
            if data_type == DataType.FILE and not meta["supports_file"]:
                continue
        result.append(meta)
    return result
