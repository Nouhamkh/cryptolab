"""Global settings, algorithm registry toggles, and paths."""

import os
from pathlib import Path

# Package root
PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent

# Schema / format version for envelopes
SCHEMA_VERSION = 1
MAGIC_HEADER = b"CLAB1"

# Default KDF iterations (PBKDF2-HMAC-SHA256)
DEFAULT_PBKDF2_ITERATIONS = 600_000

# Max file size for in-memory handling (10 MiB)
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024

# Whether to allow educational/legacy algorithms via API without explicit flag
REQUIRE_ACK_FOR_EDUCATIONAL = True
