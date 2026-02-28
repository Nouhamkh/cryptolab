"""Rail Fence cipher (educational only)."""

from crypto_lab.core.base_cipher import BaseCipher
from crypto_lab.core.metadata import build_metadata
from crypto_lab.core.registry import register_cipher
from crypto_lab.models.enums import CipherClass, CipherFamily, CipherStrength
from crypto_lab.models.payload import EncryptionMetadata


class RailFenceCipher(BaseCipher):
    """Rail Fence transposition cipher. For teaching only – never use for real data."""

    algorithm_id = "rail_fence"
    display_name = "Rail Fence"
    classification = CipherClass.EDUCATIONAL
    family = CipherFamily.CLASSICAL
    strength = CipherStrength.DEMO_ONLY
    supports_text = True
    supports_file = False
    min_key_bytes = 1  # number of rails (1-255)

    def _rails(self, data: bytes, num_rails: int) -> bytes:
        if num_rails <= 1:
            return data
        rails: list[list[int]] = [[] for _ in range(num_rails)]
        r, step = 0, 1
        for b in data:
            rails[r].append(b)
            r += step
            if r == 0 or r == num_rails - 1:
                step = -step
        return bytes(b for row in rails for b in row)

    def encrypt_bytes(self, plaintext: bytes, key: bytes, **kwargs) -> tuple[bytes, EncryptionMetadata]:
        num_rails = max(1, min(255, key[0] or 3))
        ct = self._rails(plaintext, num_rails)
        meta = build_metadata(self.algorithm_id, notes=f"rails={num_rails}")
        return ct, meta

    def decrypt_bytes(self, ciphertext: bytes, key: bytes, metadata: EncryptionMetadata, **kwargs) -> bytes:
        num_rails = max(1, min(255, key[0] or 3))
        n = len(ciphertext)
        if num_rails <= 1:
            return ciphertext
        # Compute length of each rail (same logic as encryption)
        rails_len = [0] * num_rails
        r, step = 0, 1
        for _ in range(n):
            rails_len[r] += 1
            r += step
            if r == 0 or r == num_rails - 1:
                step = -step
        # Split ciphertext into rails
        start = 0
        rails: list[list[int]] = []
        for length in rails_len:
            rails.append(list(ciphertext[start : start + length]))
            start += length
        # Read off in zigzag order
        result = []
        r, step = 0, 1
        for _ in range(n):
            result.append(rails[r].pop(0))
            r += step
            if r == 0 or r == num_rails - 1:
                step = -step
        return bytes(result)


def _factory():
    return RailFenceCipher()


register_cipher(
    RailFenceCipher.algorithm_id,
    _factory,
    RailFenceCipher.display_name,
    RailFenceCipher.classification,
    RailFenceCipher.family.value,
    RailFenceCipher.strength.value,
    supports_text=True,
    supports_file=False,
    min_key_bytes=1,
    doc_url="docs/crypto_principles.md#classical-ciphers",
)
