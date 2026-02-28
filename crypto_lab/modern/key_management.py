"""Key generation and in-memory key handling."""

import os
from typing import Optional

from crypto_lab.exceptions import KeyDerivationError


def generate_key(num_bytes: int) -> bytes:
    """Generate a cryptographically random key using os.urandom."""
    if num_bytes < 1 or num_bytes > 1024:
        raise ValueError("num_bytes must be between 1 and 1024")
    return os.urandom(num_bytes)


def derive_key_from_password(
    password: bytes,
    salt: bytes,
    key_len: int,
    iterations: int = 600_000,
) -> bytes:
    """Derive a key using PBKDF2-HMAC-SHA256. Used by PBE flows."""
    import hashlib
    import hmac

    if key_len < 1 or key_len > 64:
        raise ValueError("key_len must be between 1 and 64 for SHA256")
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=key_len)
