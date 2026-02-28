"""Roundtrip tests for modern AEAD and Fernet ciphers."""

from crypto_lab.modern import AesGcmCipher, ChaCha20Poly1305Cipher, FernetCipher


def _roundtrip(cipher_cls, key: bytes, plaintext: bytes) -> None:
    cipher = cipher_cls()
    ct, meta = cipher.encrypt_bytes(plaintext, key)
    recovered = cipher.decrypt_bytes(ct, key, meta)
    assert recovered == plaintext


def test_aes_gcm_roundtrip():
    key = b"\x01" * 32
    _roundtrip(AesGcmCipher, key, b"hello aes-gcm")


def test_chacha20_poly1305_roundtrip():
    key = b"\x02" * 32
    _roundtrip(ChaCha20Poly1305Cipher, key, b"hello chacha20-poly1305")


def test_fernet_roundtrip():
    key = b"\x03" * 32
    _roundtrip(FernetCipher, key, b"hello fernet")

