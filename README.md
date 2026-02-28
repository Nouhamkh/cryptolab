# Crypto Playground: Educational & Modern Cryptography Lab (Python)

A single application to encrypt and decrypt data using classical (educational) and modern (production-style) ciphers. Built for **learning, demonstration, and portfolio purposes**—not to replace existing cryptographic tools.

## Features

- **Algorithm categories**
  - **Educational**: Caesar, Vigenère, Rail Fence (teaching only; never use for real data).
  - **Modern recommended**: AES-GCM, ChaCha20-Poly1305, Fernet (AEAD; suitable for real-world use when implemented correctly—this project is demo only).
- **Text and file encryption** with consistent metadata (nonce, salt, tag, algorithm info).
- **Web UI** and **REST API** for encrypt/decrypt and algorithm listing.
- **Password-based encryption** via PBKDF2-HMAC-SHA256 with configurable iterations.

## Security disclaimer

**This project is for learning and demonstration only.**

- Although it uses well-known algorithms and best practices (e.g. AEAD, unique nonces, strong KDF), it has **not** undergone formal security review.
- Do not rely on it for protecting sensitive or production data.
- Use established libraries and tools (e.g. `cryptography`, age, GPG) for real security needs.

See [crypto_lab/docs/security_considerations.md](crypto_lab/docs/security_considerations.md) for design choices, defaults, and warnings for educational/legacy ciphers.

## Architecture overview

- **Web** (FastAPI) → **API** (encrypt/decrypt/algorithms) → **Core** (registry, serialization, metadata) → **Ciphers** (classical + modern) → **cryptography** library.
- **Text** outputs: JSON envelope with base64 ciphertext and a metadata header.
- **File** outputs: binary envelope with magic header `CLAB1`, length-prefixed JSON metadata, then raw ciphertext.

See [docs/architecture.md](crypto_lab/docs/architecture.md) for more detail and diagrams.

## Quickstart

```bash
# From project root
pip install -r requirements.txt
python -m uvicorn crypto_lab.web.app:app --reload
```

Open http://127.0.0.1:8000 for the playground UI, or http://127.0.0.1:8000/docs for the OpenAPI docs.

**Example: encrypt text with AES-GCM via API**

```bash
# Generate a key
KEY=$(curl -s "http://127.0.0.1:8000/api/key/generate?bytes=32" | python -c "import sys,json; print(json.load(sys.stdin)['key_b64'])")

# Encrypt
curl -s -X POST http://127.0.0.1:8000/api/encrypt/text \
  -H "Content-Type: application/json" \
  -d "{\"algorithm_id\":\"aes_gcm\",\"plaintext\":\"Hello World\",\"key_b64\":\"$KEY\"}"
```

## Algorithm catalog

| Algorithm           | Classification     | Strength  | Text | File | Notes                          |
|--------------------|--------------------|-----------|------|------|--------------------------------|
| Caesar             | Educational        | Demo only | Yes  | No   | Teaching only                  |
| Vigenère           | Educational        | Demo only | Yes  | No   | Teaching only                  |
| Rail Fence         | Educational        | Demo only | Yes  | No   | Teaching only                  |
| AES-GCM            | Modern recommended | Strong    | Yes  | Yes  | AEAD; 128/192/256-bit keys    |
| ChaCha20-Poly1305  | Modern recommended | Strong    | Yes  | Yes  | AEAD; 256-bit key             |
| Fernet             | Modern recommended | Strong    | Yes  | Yes  | Encrypt-then-MAC; 256-bit key |

See [crypto_lab/docs/algorithms.md](crypto_lab/docs/algorithms.md) and [crypto_lab/docs/crypto_principles.md](crypto_lab/docs/crypto_principles.md) for more detail.

## Development

- **Tests**: `pytest` from project root (uses `pyproject.toml` test path).
- **Adding a cipher**: Implement `BaseCipher` in `crypto_lab/classical` or `crypto_lab/modern`, then call `register_cipher(...)` so the registry and UI pick it up.
