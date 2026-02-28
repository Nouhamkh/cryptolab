"""Fernet scheme using cryptography (modern, opinionated AEAD-like API)."""

from __future__ import annotations

import base64
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from crypto_lab.core.base_cipher import BaseCipher
from crypto_lab.core.metadata import build_metadata
from crypto_lab.core.registry import register_cipher
from crypto_lab.exceptions import EncryptionError, DecryptionError
from crypto_lab.models.enums import CipherClass, CipherFamily, CipherStrength
from crypto_lab.models.payload import EncryptionMetadata


class FernetCipher(BaseCipher):
    """Fernet symmetric encryption (encrypt-then-MAC with fixed parameters)."""

    algorithm_id = "fernet"
    display_name = "Fernet"
    classification = CipherClass.MODERN_RECOMMENDED
    family = CipherFamily.SYMMETRIC_AEAD
    strength = CipherStrength.STRONG
    supports_text = True
    supports_file = True
    min_key_bytes = 32  # 32 raw bytes mapped to Fernet key

    def _to_fernet_key(self, key: bytes) -> bytes:
        if len(key) != 32:
            raise EncryptionError("Fernet key must be exactly 32 bytes before encoding")
        return base64.urlsafe_b64encode(key)

    def encrypt_bytes(
        self,
        plaintext: bytes,
        key: bytes,
        *,
        kdf: Optional[str] = None,
        iterations: Optional[int] = None,
    ) -> tuple[bytes, EncryptionMetadata]:
        f_key = self._to_fernet_key(key)
        cipher = Fernet(f_key)
        token = cipher.encrypt(plaintext)
        # Fernet encapsulates IV, timestamp, and MAC; no separate nonce/tag.
        meta = build_metadata(
            alg_id=self.algorithm_id,
            kdf=kdf,
            iterations=iterations,
        )
        return token, meta

    def decrypt_bytes(
        self,
        ciphertext: bytes,
        key: bytes,
        metadata: EncryptionMetadata,
    ) -> bytes:
        f_key = self._to_fernet_key(key)
        cipher = Fernet(f_key)
        try:
            return cipher.decrypt(ciphertext)
        except InvalidToken as exc:
            raise DecryptionError("Fernet decryption failed (invalid token)") from exc


def _factory() -> FernetCipher:
    return FernetCipher()


register_cipher(
    FernetCipher.algorithm_id,
    _factory,
    FernetCipher.display_name,
    FernetCipher.classification,
    FernetCipher.family.value,
    FernetCipher.strength.value,
    supports_text=True,
    supports_file=True,
    min_key_bytes=FernetCipher.min_key_bytes,
    doc_url="docs/crypto_principles.md#fernet",
)

