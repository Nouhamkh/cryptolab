"""Vigenère cipher (educational only)."""

from crypto_lab.core.base_cipher import BaseCipher
from crypto_lab.core.metadata import build_metadata
from crypto_lab.core.registry import register_cipher
from crypto_lab.models.enums import CipherClass, CipherFamily, CipherStrength
from crypto_lab.models.payload import EncryptionMetadata


class VigenereCipher(BaseCipher):
    """Vigenère cipher (repeating key). For teaching only – never use for real data."""

    algorithm_id = "vigenere"
    display_name = "Vigenère"
    classification = CipherClass.EDUCATIONAL
    family = CipherFamily.CLASSICAL
    strength = CipherStrength.DEMO_ONLY
    supports_text = True
    supports_file = False
    min_key_bytes = 1

    def encrypt_bytes(self, plaintext: bytes, key: bytes, **kwargs) -> tuple[bytes, EncryptionMetadata]:
        key_stream = (key * (len(plaintext) // len(key) + 1))[: len(plaintext)]
        result = bytes((p + k) % 256 for p, k in zip(plaintext, key_stream))
        meta = build_metadata(self.algorithm_id)
        return result, meta

    def decrypt_bytes(self, ciphertext: bytes, key: bytes, metadata: EncryptionMetadata, **kwargs) -> bytes:
        key_stream = (key * (len(ciphertext) // len(key) + 1))[: len(ciphertext)]
        return bytes((c - k) % 256 for c, k in zip(ciphertext, key_stream))


def _factory():
    return VigenereCipher()


register_cipher(
    VigenereCipher.algorithm_id,
    _factory,
    VigenereCipher.display_name,
    VigenereCipher.classification,
    VigenereCipher.family.value,
    VigenereCipher.strength.value,
    supports_text=True,
    supports_file=False,
    min_key_bytes=1,
    doc_url="docs/crypto_principles.md#classical-ciphers",
)
