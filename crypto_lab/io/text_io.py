"""Encoding/decoding, UTF-8 handling, newline normalization."""


def encode_text(s: str) -> bytes:
    """Encode string to UTF-8 bytes."""
    return s.encode("utf-8")


def decode_text(b: bytes) -> str:
    """Decode UTF-8 bytes to string. Replace invalid sequences."""
    return b.decode("utf-8", errors="replace")
