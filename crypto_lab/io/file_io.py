"""Safe file handling with size limits."""

from pathlib import Path

from crypto_lab.config import MAX_FILE_SIZE_BYTES


def read_file_safe(path: Path | str, max_size: int = MAX_FILE_SIZE_BYTES) -> bytes:
    """Read file contents; raise if file exceeds max_size."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {path}")
    size = path.stat().st_size
    if size > max_size:
        raise ValueError(f"File too large: {size} > {max_size}")
    return path.read_bytes()


def write_file_safe(path: Path | str, data: bytes) -> None:
    """Write bytes to file safely (overwrites)."""
    Path(path).write_bytes(data)
