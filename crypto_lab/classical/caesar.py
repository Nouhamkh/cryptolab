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
    # One-byte key interpreted as a shift in the A–Z / a–z alphabet (mod 26).
    min_key_bytes = 1

    def encrypt_bytes(self, plaintext: bytes, key: bytes, **kwargs) -> tuple[bytes, EncryptionMetadata]:
        # Classical Caesar: shift alphabetic characters within A–Z / a–z, leave others unchanged.
        shift = key[0] % 26
        result = bytearray()
        for b in plaintext:
            if 65 <= b <= 90:  # 'A'-'Z'
                base = 65
                offset = (b - base + shift) % 26
                result.append(base + offset)
            elif 97 <= b <= 122:  # 'a'-'z'
                base = 97
                offset = (b - base + shift) % 26
                result.append(base + offset)
            else:
                result.append(b)
        meta = build_metadata(self.algorithm_id, notes=f"shift={shift}")
        return bytes(result), meta

    def decrypt_bytes(self, ciphertext: bytes, key: bytes, metadata: EncryptionMetadata, **kwargs) -> bytes:
        shift = key[0] % 26
        result = bytearray()
        for b in ciphertext:
            if 65 <= b <= 90:  # 'A'-'Z'
                base = 65
                offset = (b - base - shift) % 26
                result.append(base + offset)
            elif 97 <= b <= 122:  # 'a'-'z'
                base = 97
                offset = (b - base - shift) % 26
                result.append(base + offset)
            else:
                result.append(b)
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
