"""Tests for /encrypt and /decrypt endpoints in the security-privacy service."""

from __future__ import annotations

from typing import Dict, Any

from fastapi.testclient import TestClient

from luki_sec.main import app
import luki_sec.main as main_mod


client = TestClient(app)


def test_encrypt_decrypt_roundtrip() -> None:
    """Data encrypted via /encrypt should round-trip through /decrypt."""
    payload: Dict[str, Any] = {"secret": "value", "nested": {"x": 1, "y": 2}}

    response = client.post("/encrypt", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert "encrypted_data" in data
    encrypted = data["encrypted_data"]
    assert isinstance(encrypted, str) and encrypted

    response2 = client.post("/decrypt", params={"encrypted_data": encrypted})

    assert response2.status_code == 200
    data2 = response2.json()
    assert data2["decrypted_data"] == payload


def test_encrypt_returns_503_when_service_missing(monkeypatch) -> None:
    """If encryption_service is not initialised, /encrypt should return 503."""
    original = main_mod.encryption_service
    try:
        main_mod.encryption_service = None
        response = client.post("/encrypt", json={"foo": "bar"})
        assert response.status_code == 503
        data = response.json()
        assert "Encryption service not available" in data.get("detail", "")
    finally:
        main_mod.encryption_service = original
