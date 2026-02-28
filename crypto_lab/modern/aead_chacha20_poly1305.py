"""ChaCha20-Poly1305 AEAD cipher using cryptography (modern, recommended)."""

from __future__ import annotations

import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from crypto_lab.core.base_cipher import BaseCipher
from crypto_lab.core.metadata import build_metadata
from crypto_lab.core.registry import register_cipher
from crypto_lab.exceptions import EncryptionError, DecryptionError
from crypto_lab.models.enums import CipherClass, CipherFamily, CipherStrength
from crypto_lab.models.payload import EncryptionMetadata


class ChaCha20Poly1305Cipher(BaseCipher):
    """ChaCha20-Poly1305 AEAD cipher (nonce-based stream cipher with MAC)."""

    algorithm_id = "chacha20_poly1305"
    display_name = "ChaCha20-Poly1305"
    classification = CipherClass.MODERN_RECOMMENDED
    family = CipherFamily.SYMMETRIC_AEAD
    strength = CipherStrength.STRONG
    supports_text = True
    supports_file = True
    min_key_bytes = 32  # 256-bit key

    _NONCE_LEN = 12
    _TAG_LEN = 16

    def _validate_key(self, key: bytes) -> None:
        if len(key) != 32:
            raise EncryptionError("ChaCha20-Poly1305 key must be 256 bits (32 bytes)")

    def encrypt_bytes(
        self,
        plaintext: bytes,
        key: bytes,
        *,
        aad: Optional[bytes] = None,
        kdf: Optional[str] = None,
        iterations: Optional[int] = None,
    ) -> tuple[bytes, EncryptionMetadata]:
        self._validate_key(key)
        nonce = os.urandom(self._NONCE_LEN)
        aead = ChaCha20Poly1305(key)
        ct_with_tag = aead.encrypt(nonce, plaintext, aad)
        tag = ct_with_tag[-self._TAG_LEN :]
        ciphertext = ct_with_tag[: -self._TAG_LEN]
        meta = build_metadata(
            alg_id=self.algorithm_id,
            nonce=nonce,
            tag=tag,
            kdf=kdf,
            iterations=iterations,
        )
        return ciphertext, meta

    def decrypt_bytes(
        self,
        ciphertext: bytes,
        key: bytes,
        metadata: EncryptionMetadata,
        *,
        aad: Optional[bytes] = None,
    ) -> bytes:
        self._validate_key(key)
        if metadata.nonce is None or metadata.tag is None:
            raise DecryptionError(
                "Missing nonce or tag for ChaCha20-Poly1305 decryption"
            )
        aead = ChaCha20Poly1305(key)
        ct_with_tag = ciphertext + metadata.tag
        try:
            return aead.decrypt(metadata.nonce, ct_with_tag, aad)
        except Exception as exc:
            raise DecryptionError("ChaCha20-Poly1305 decryption failed") from exc


def _factory() -> ChaCha20Poly1305Cipher:
    return ChaCha20Poly1305Cipher()


register_cipher(
    ChaCha20Poly1305Cipher.algorithm_id,
    _factory,
    ChaCha20Poly1305Cipher.display_name,
    ChaCha20Poly1305Cipher.classification,
    ChaCha20Poly1305Cipher.family.value,
    ChaCha20Poly1305Cipher.strength.value,
    supports_text=True,
    supports_file=True,
    min_key_bytes=ChaCha20Poly1305Cipher.min_key_bytes,
    doc_url="docs/crypto_principles.md#chacha20-poly1305",
)

