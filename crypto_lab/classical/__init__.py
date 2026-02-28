"""Classical / educational ciphers (teaching only – never use for real data)."""

# Import implementations so they register themselves
from crypto_lab.classical.caesar import CaesarCipher
from crypto_lab.classical.rail_fence import RailFenceCipher
from crypto_lab.classical.vigenere import VigenereCipher

__all__ = ["CaesarCipher", "VigenereCipher", "RailFenceCipher"]
