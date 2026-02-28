"""Caesar cipher (educational only)."""

from crypto_lab.core.base_cipher import BaseCipher
from crypto_lab.core.metadata import build_metadata
from crypto_lab.core.registry import register_cipher
from crypto_lab.models.enums import CipherClass, CipherFamily, CipherStrength
from crypto_lab.models.payload import EncryptionMetadata


class CaesarCipher(BaseCipher):
    """Caesar shift cipher. For teaching only – never use for real data."""

    algorithm_id = "caesar"
    display_name = "Caesar"
    classification = CipherClass.EDUCATIONAL
    family = CipherFamily.CLASSICAL
    strength = CipherStrength.DEMO_ONLY
    supports_text = True
    supports_file = False
    min_key_bytes = 1  # shift 0-255

    def encrypt_bytes(self, plaintext: bytes, key: bytes, **kwargs) -> tuple[bytes, EncryptionMetadata]:
        shift = key[0] % 256
        result = bytearray()
        for b in plaintext:
            result.append((b + shift) % 256)
        meta = build_metadata(self.algorithm_id, notes=f"shift={shift}")
        return bytes(result), meta

    def decrypt_bytes(self, ciphertext: bytes, key: bytes, metadata: EncryptionMetadata, **kwargs) -> bytes:
        shift = key[0] % 256
        result = bytearray()
        for b in ciphertext:
            result.append((b - shift) % 256)
        return bytes(result)


def _factory():
    return CaesarCipher()


register_cipher(
    CaesarCipher.algorithm_id,
    _factory,
    CaesarCipher.display_name,
    CaesarCipher.classification,
    CaesarCipher.family.value,
    CaesarCipher.strength.value,
    supports_text=True,
    supports_file=False,
    min_key_bytes=1,
    doc_url="docs/crypto_principles.md#classical-ciphers",
)
