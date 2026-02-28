"""Tests for web API."""

import base64

import pytest
from fastapi.testclient import TestClient

# Import app after crypto_lab so ciphers are registered when app loads
from crypto_lab.web.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_get_algorithms(client):
    r = client.get("/api/algorithms")
    assert r.status_code == 200
    data = r.json()
    assert "algorithms" in data
    assert len(data["algorithms"]) >= 6  # caesar, vigenere, rail_fence, aes_gcm, chacha20_poly1305, fernet


def test_get_modern_algorithms(client):
    r = client.get("/api/algorithms/modern")
    assert r.status_code == 200
    data = r.json()
    assert all(a["classification"] == "modern_recommended" for a in data["algorithms"])


def test_generate_key(client):
    r = client.get("/api/key/generate?bytes=32")
    assert r.status_code == 200
    data = r.json()
    assert "key_b64" in data
    key = base64.b64decode(data["key_b64"])
    assert len(key) == 32
