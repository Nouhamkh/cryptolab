"""Abstract base classes for ciphers (text/file, symmetric)."""

from abc import ABC, abstractmethod
from typing import Optional

from crypto_lab.models.enums import CipherClass, CipherFamily, CipherStrength, DataType
from crypto_lab.models.payload import EncryptionMetadata


class BaseCipher(ABC):
    """Base interface for all cipher implementations."""

    # Subclasses must set these
    algorithm_id: str = ""
    display_name: str = ""
    classification: CipherClass = CipherClass.EDUCATIONAL
    family: CipherFamily = CipherFamily.CLASSICAL
    strength: CipherStrength = CipherStrength.DEMO_ONLY
    supports_text: bool = True
    supports_file: bool = False
    min_key_bytes: Optional[int] = None

    @property
    def name(self) -> str:
        return self.display_name or self.algorithm_id

    @abstractmethod
    def encrypt_bytes(self, plaintext: bytes, key: bytes, **kwargs) -> tuple[bytes, EncryptionMetadata]:
        """Encrypt raw bytes. Returns (ciphertext, metadata)."""
        ...

    @abstractmethod
    def decrypt_bytes(self, ciphertext: bytes, key: bytes, metadata: EncryptionMetadata, **kwargs) -> bytes:
        """Decrypt raw bytes using provided metadata."""
        ...

    def encrypt_text(self, plaintext: str, key: bytes, **kwargs) -> tuple[str, EncryptionMetadata]:
        """Convenience: encode UTF-8, encrypt, return base64 string and metadata."""
        data = plaintext.encode("utf-8")
        ct, meta = self.encrypt_bytes(data, key, **kwargs)
        import base64
        return base64.b64encode(ct).decode("ascii"), meta

    def decrypt_text(self, ciphertext_b64: str, key: bytes, metadata: EncryptionMetadata, **kwargs) -> str:
        """Convenience: base64 decode, decrypt, return UTF-8 string."""
        import base64
        ct = base64.b64decode(ciphertext_b64)
        plain = self.decrypt_bytes(ct, key, metadata, **kwargs)
        return plain.decode("utf-8")
