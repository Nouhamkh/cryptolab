#!/usr/bin/env python3
"""
Test case for Caesar cipher shift 20 bug report.
User reported: "for hello in shift 20 it doesnt show byffi it shows |y"

This test verifies that Caesar cipher with shift 20 on "hello" produces "byffi".
"""

from crypto_lab.classical.caesar import CaesarCipher

def test_caesar_shift_20_hello():
    """Test Caesar cipher with shift 20 on 'hello'."""
    cipher = CaesarCipher()
    
    # Create key for shift 20
    key = bytes([20])
    plaintext = b"hello"
    expected_ciphertext = b"byffi"
    
    # Encrypt
    ciphertext, metadata = cipher.encrypt_bytes(plaintext, key)
    
    print(f"Plaintext: {plaintext}")
    print(f"Shift: 20")
    print(f"Expected ciphertext: {expected_ciphertext}")
    print(f"Actual ciphertext: {ciphertext}")
    print(f"Match: {ciphertext == expected_ciphertext}")
    
    # Verify decryption
    decrypted = cipher.decrypt_bytes(ciphertext, key, metadata)
    print(f"Decrypted: {decrypted}")
    print(f"Decryption works: {decrypted == plaintext}")
    
    # Character by character analysis
    print("\nCharacter-by-character breakdown:")
    for p, c in zip(plaintext, ciphertext):
        p_char = chr(p)
        c_char = chr(c)
        print(f"  '{p_char}' (0x{p:02x}) -> '{c_char}' (0x{c:02x})")
    
    assert ciphertext == expected_ciphertext, f"Expected {expected_ciphertext}, got {ciphertext}"
    assert decrypted == plaintext, f"Decryption failed"
    
    print("\n✓ All tests passed!")

if __name__ == "__main__":
    test_caesar_shift_20_hello()
