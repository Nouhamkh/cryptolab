"""Enums for cipher classification and data types."""

from enum import Enum


class CipherClass(str, Enum):
    """How the algorithm is intended to be used."""

    EDUCATIONAL = "educational"  # Toy / teaching only
    LEGACY = "legacy"  # Historically used, now discouraged
    MODERN_RECOMMENDED = "modern_recommended"  # Safe for real-world use when used correctly


class CipherFamily(str, Enum):
    """Family of the cipher."""

    CLASSICAL = "classical"
    SYMMETRIC_AEAD = "symmetric_aead"
    SYMMETRIC_LEGACY = "symmetric_legacy"
    ASYMMETRIC = "asymmetric"
    STREAM = "stream"
    BLOCK = "block"


class CipherStrength(str, Enum):
    """Security strength / recommendation level."""

    DEMO_ONLY = "demo_only"  # Not safe for real data
    WEAK = "weak"
    STRONG = "strong"
    FUTURE = "future"
    DEPRECATED = "deprecated"


class DataType(str, Enum):
    """Supported input/output type."""

    TEXT = "text"
    FILE = "file"
