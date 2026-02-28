"""Custom exception types for Crypto Lab."""


class CryptoLabError(Exception):
    """Base exception for Crypto Lab."""


class CipherNotFoundError(CryptoLabError):
    """Requested cipher algorithm is not registered or not found."""


class DecryptionError(CryptoLabError):
    """Decryption failed (wrong key, tampered data, or invalid format)."""


class EncryptionError(CryptoLabError):
    """Encryption failed (invalid input or configuration)."""


class InvalidMetadataError(CryptoLabError):
    """Metadata envelope is invalid or unsupported version."""


class UnsupportedDataTypeError(CryptoLabError):
    """Cipher does not support the requested data type (e.g. file vs text)."""


class KeyDerivationError(CryptoLabError):
    """Key derivation (KDF) failed."""
