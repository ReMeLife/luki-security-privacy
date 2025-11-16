"""Tests for the /policy/enforce endpoint."""

from __future__ import annotations

from typing import Dict, Any

import pytest
from fastapi.testclient import TestClient

from luki_sec.main import app
from luki_sec.consent.engine import ConsentEngine
from luki_sec.consent.storage import InMemoryConsentStorage
from luki_sec.consent.models import ConsentScope


client = TestClient(app)


@pytest.mark.asyncio
async def test_policy_enforce_allows_when_consent_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = InMemoryConsentStorage()
    engine = ConsentEngine(storage)
    engine.grant_consent(
        user_id="user_123",
        scope=ConsentScope.ELR_INTERESTS,
        purpose="Testing",
        granted_by="admin",
    )

    async def _get_engine() -> ConsentEngine:
        return engine

    monkeypatch.setattr("luki_sec.main.get_consent_engine", lambda: engine)

    payload: Dict[str, Any] = {
        "user_id": "user_123",
        "requester_role": "agent",
        "requested_scopes": [ConsentScope.ELR_INTERESTS.value],
    }

    response = client.post("/policy/enforce", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["allowed"] is True
    assert data["reason"] == "consent_valid"
    assert ConsentScope.ELR_INTERESTS.value in data["scopes_checked"]


@pytest.mark.asyncio
async def test_policy_enforce_denied_when_no_consent(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = InMemoryConsentStorage()
    engine = ConsentEngine(storage)

    monkeypatch.setattr("luki_sec.main.get_consent_engine", lambda: engine)

    payload: Dict[str, Any] = {
        "user_id": "user_123",
        "requester_role": "agent",
        "requested_scopes": [ConsentScope.ELR_INTERESTS.value],
    }

    response = client.post("/policy/enforce", json=payload)

    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["error"] == "consent_denied"


def test_policy_enforce_invalid_scopes() -> None:
    payload: Dict[str, Any] = {
        "user_id": "user_123",
        "requester_role": "agent",
        "requested_scopes": ["not_a_real_scope"],
    }

    response = client.post("/policy/enforce", json=payload)

    assert response.status_code == 400
    data = response.json()
    assert data["detail"]["error"] == "invalid_scopes"
    assert "not_a_real_scope" in data["detail"]["scopes"]


def test_policy_enforce_no_scopes_returns_allowed() -> None:
    payload: Dict[str, Any] = {
        "user_id": "user_123",
        "requester_role": "agent",
        "requested_scopes": [],
    }

    response = client.post("/policy/enforce", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["allowed"] is True
    assert data["reason"] == "no_scopes_requested"
    assert data["scopes_checked"] == []
