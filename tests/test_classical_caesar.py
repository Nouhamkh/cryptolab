"""Basic tests for classical ciphers (Caesar/Vigenere/RailFence)."""

from crypto_lab.classical import CaesarCipher, VigenereCipher, RailFenceCipher


def _roundtrip(cipher_cls, key: bytes, text: str) -> None:
    cipher = cipher_cls()
    ct, meta = cipher.encrypt_bytes(text.encode("utf-8"), key)
    recovered = cipher.decrypt_bytes(ct, key, meta).decode("utf-8")
    assert recovered == text


def test_caesar_roundtrip():
    _roundtrip(CaesarCipher, b"\x05", "hello caesar")


def test_vigenere_roundtrip():
    _roundtrip(VigenereCipher, b"KEY", "hello vigenere")


def test_rail_fence_roundtrip():
    _roundtrip(RailFenceCipher, b"\x03", "rail fence cipher")

