"""PBKDF2-HMAC key derivation for password-based encryption."""

import os
from typing import Optional

from crypto_lab.config import DEFAULT_PBKDF2_ITERATIONS
from crypto_lab.modern.key_management import derive_key_from_password


def derive_key_pbkdf2(
    password: bytes,
    salt: Optional[bytes] = None,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    key_len: int = 32,
) -> tuple[bytes, bytes]:
    """Derive a key and return (key, salt). If salt is None, generate a random one."""
    if salt is None:
        salt = os.urandom(16)
    key = derive_key_from_password(password, salt, key_len, iterations)
    return key, salt
