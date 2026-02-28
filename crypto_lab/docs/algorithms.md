# Algorithm Catalog

| Algorithm ID         | Display name        | Classification     | Family          | Strength  | Text | File | Min key (bytes) |
|----------------------|---------------------|--------------------|-----------------|-----------|------|------|------------------|
| caesar               | Caesar              | educational        | classical       | demo_only | Yes  | No   | 1                |
| vigenere             | Vigenère            | educational        | classical       | demo_only | Yes  | No   | 1                |
| rail_fence           | Rail Fence          | educational        | classical       | demo_only | Yes  | No   | 1                |
| aes_gcm              | AES-GCM             | modern_recommended | symmetric_aead  | strong    | Yes  | Yes  | 32               |
| chacha20_poly1305    | ChaCha20-Poly1305   | modern_recommended | symmetric_aead  | strong    | Yes  | Yes  | 32               |
| fernet               | Fernet              | modern_recommended | symmetric_aead  | strong    | Yes  | Yes  | 32               |

- **Educational**: For teaching only; do not use for real data.
- **Modern recommended**: AEAD or Fernet; suitable for real-world use when implemented and used correctly (this project is for demo only).
- **Strength**: `demo_only` = not safe for real data; `strong` = accepted modern security strength.

See [crypto_principles.md](crypto_principles.md) for concepts (AEAD, KDF, key management, pitfalls).
