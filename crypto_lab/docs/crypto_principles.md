# Crypto Principles

## Classical ciphers

Caesar, Vigenère, and Rail Fence are **for teaching only**. They are trivially broken (frequency analysis, short keys, no authentication) and must **never** be used for real data.

## Modern AEAD

- **AEAD** (Authenticated Encryption with Associated Data) provides both **confidentiality** and **integrity**: the ciphertext is encrypted and a tag is verified on decryption so tampering is detected.
- **AES-GCM** and **ChaCha20-Poly1305** are AEAD schemes used in TLS and many libraries. We use the `cryptography` library; no homemade crypto.
- **Nonce/IV**: Must be **unique** per encryption under the same key. Reuse with the same key can break security. We generate a random nonce per encryption and store it in the envelope.
- **Fernet** is a higher-level design (encrypt-then-MAC with fixed parameters); we expose it as a single “algorithm” for convenience.

## Key derivation (KDF)

- **Password vs key**: A **key** is a fixed-size secret (e.g. 32 bytes). A **password** is human-chosen and variable length; it must not be used directly as a key.
- **PBKDF2-HMAC-SHA256**: We use it to derive a key from a password. Each encryption uses a **random salt** (stored in metadata); decryption uses the same salt and iteration count from the envelope.
- **Iterations**: Higher values slow brute-force; we use a high default (e.g. 600_000) and store the value in metadata so decryption can reproduce it.

## Key management

- **V1**: Keys exist only in memory per request; we do not write them to disk. For file encryption, the user must supply the key or password again when decrypting.
- **Randomness**: Keys and nonces are generated with `os.urandom` / the `cryptography` library, not `random`.

## Pitfalls to avoid

- **No ECB or bare AES-CBC** in the “recommended” set; we only expose AEAD (or Fernet) for modern use.
- **No nonce reuse**: Each encryption gets a fresh nonce.
- **Encoding**: Text is normalized to UTF-8; we clearly separate “text” (UTF-8 string) vs “bytes” (file/binary) paths.
- **Constant-time comparison**: Where applicable (e.g. tag verification), the underlying library uses constant-time comparison; we do not implement our own.
