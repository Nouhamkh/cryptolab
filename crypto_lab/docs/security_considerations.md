# Security considerations

This document summarizes how Crypto Lab handles security and what to be aware of when using or extending it.

## Intended use

- **Learning and demonstration only.** Do not use this project to protect sensitive or production data.
- The project has **not** undergone formal security review or penetration testing.
- For real-world encryption, use established tools and libraries (e.g. `cryptography`, age, GnuPG) and follow current best practices.

## Design choices

- **Modern algorithms**: Only AEAD (AES-GCM, ChaCha20-Poly1305) or Fernet are in the “modern recommended” set. No ECB, no bare CBC, no custom constructions.
- **Nonces**: Generated with `os.urandom` per encryption; never reused under the same key. Stored in the envelope for decryption.
- **Keys**: Generated with `os.urandom` or derived via PBKDF2-HMAC-SHA256. Not written to disk in V1.
- **Password-based encryption**: PBKDF2 with a high iteration count (default 600_000); random salt per encryption, stored in metadata.
- **Educational/legacy algorithms**: Clearly labeled; API requires explicit acknowledgment (e.g. header `X-Acknowledge-Educational: true`) so they are not used by mistake.

## Defaults

- **PBKDF2 iterations**: 600_000 (configurable in `config.DEFAULT_PBKDF2_ITERATIONS`).
- **Key sizes**: 32 bytes (256-bit) for modern ciphers; algorithm-specific minimums enforced.
- **File size limit**: 10 MiB per file to avoid excessive memory use (configurable in `config.MAX_FILE_SIZE_BYTES`).

## Warnings for educational/legacy ciphers

- **UI**: The “Educational” tab shows a prominent warning: *For teaching only. These ciphers are not safe for real data. Never use for production.*
- **API**: Requests that use an educational or legacy algorithm must include the header `X-Acknowledge-Educational: true` (or equivalent as configured); otherwise the API returns 403.
- **Docs**: [crypto_principles.md](crypto_principles.md) and [algorithms.md](algorithms.md) state that classical ciphers are for teaching only and must never be used for real data.

## Reporting issues

If you believe you have found a security-sensitive bug, please do not open a public issue. Prefer private disclosure to the project maintainer if one is listed.
