"""AES-GCM AEAD cipher using cryptography (modern, recommended)."""

from __future__ import annotations

import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_lab.core.base_cipher import BaseCipher
from crypto_lab.core.metadata import build_metadata
from crypto_lab.core.registry import register_cipher
from crypto_lab.exceptions import EncryptionError, DecryptionError
from crypto_lab.models.enums import CipherClass, CipherFamily, CipherStrength
from crypto_lab.models.payload import EncryptionMetadata


class AesGcmCipher(BaseCipher):
    """AES-GCM AEAD cipher.

    Provides confidentiality and integrity. This is a modern, recommended scheme
    when used with a unique nonce per key and strong key management.
    """

    algorithm_id = "aes_gcm"
    display_name = "AES-GCM"
    classification = CipherClass.MODERN_RECOMMENDED
    family = CipherFamily.SYMMETRIC_AEAD
    strength = CipherStrength.STRONG
    supports_text = True
    supports_file = True
    min_key_bytes = 32  # 256-bit default

    _NONCE_LEN = 12
    _TAG_LEN = 16

    def _validate_key(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise EncryptionError("AES-GCM key must be 128, 192, or 256 bits")

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
        aesgcm = AESGCM(key)
        ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
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
            raise DecryptionError("Missing nonce or tag for AES-GCM decryption")
        aesgcm = AESGCM(key)
        ct_with_tag = ciphertext + metadata.tag
        try:
            return aesgcm.decrypt(metadata.nonce, ct_with_tag, aad)
        except Exception as exc:  # cryptography raises InvalidTag on failure
            raise DecryptionError("AES-GCM decryption failed") from exc


def _factory() -> AesGcmCipher:
    return AesGcmCipher()


register_cipher(
    AesGcmCipher.algorithm_id,
    _factory,
    AesGcmCipher.display_name,
    AesGcmCipher.classification,
    AesGcmCipher.family.value,
    AesGcmCipher.strength.value,
    supports_text=True,
    supports_file=True,
    min_key_bytes=AesGcmCipher.min_key_bytes,
    doc_url="docs/crypto_principles.md#aes-gcm",
)

