"""Request/response Pydantic models for the API."""

from pydantic import BaseModel, Field


class EncryptTextRequest(BaseModel):
    algorithm_id: str
    plaintext: str
    key_b64: str | None = None
    password: str | None = None


class EncryptTextResponse(BaseModel):
    envelope_json: str
    algorithm_id: str
    metadata: dict


class DecryptTextRequest(BaseModel):
    envelope_json: str
    key_b64: str | None = None
    password: str | None = None


class DecryptTextResponse(BaseModel):
    plaintext: str
    algorithm_id: str
    metadata: dict
