"""Tests for ConsentManager integration with consent engine and storage."""

from __future__ import annotations

from typing import Dict, Any

import pytest

from luki_sec.consent.manager import ConsentManager
from luki_sec.consent.engine import ConsentEngine
from luki_sec.consent.storage import InMemoryConsentStorage
from luki_sec.consent.models import ConsentScope


class TestConsentManager:
    """Test high-level consent manager behaviour."""

    def setup_method(self) -> None:
        storage = InMemoryConsentStorage()
        engine = ConsentEngine(storage)
        self.manager = ConsentManager(engine=engine)

    @pytest.mark.asyncio
    async def test_update_consent_grant_and_get(self) -> None:
        """Grant a consent scope and retrieve it via the manager."""
        payload: Dict[str, Any] = {
            "grants": [
                {
                    "scope": ConsentScope.ELR_INTERESTS.value,
                    "purpose": "Personalized recommendations",
                }
            ],
            "revokes": [],
            "actor": "user_123",
        }

        result = await self.manager.update_consent("user_123", payload)

        assert result["user_id"] == "user_123"
        assert not result["errors"]
        assert ConsentScope.ELR_INTERESTS.value in result["valid_scopes"]
        assert result["updated"]

        summary = await self.manager.get_consent("user_123")
        assert summary["user_id"] == "user_123"
        assert len(summary["consents"]) == 1
        consent = summary["consents"][0]
        assert consent["scope"] == ConsentScope.ELR_INTERESTS.value
        assert consent["status"] == "granted"
        assert ConsentScope.ELR_INTERESTS.value in summary["valid_scopes"]

    @pytest.mark.asyncio
    async def test_update_consent_revoke(self) -> None:
        """Revoking a previously granted consent should remove it from valid scopes."""
        grant_payload: Dict[str, Any] = {
            "grants": [
                {
                    "scope": ConsentScope.ELR_MEMORIES.value,
                    "purpose": "Testing revoke",
                }
            ],
            "revokes": [],
            "actor": "user_123",
        }
        await self.manager.update_consent("user_123", grant_payload)

        revoke_payload: Dict[str, Any] = {
            "grants": [],
            "revokes": [
                {"scope": ConsentScope.ELR_MEMORIES.value}
            ],
            "actor": "user_123",
        }
        result = await self.manager.update_consent("user_123", revoke_payload)

        assert ConsentScope.ELR_MEMORIES.value in result["revoked_scopes"]

        summary = await self.manager.get_consent("user_123")
        statuses = {c["scope"]: c["status"] for c in summary["consents"]}
        assert statuses[ConsentScope.ELR_MEMORIES.value] == "revoked"
        assert ConsentScope.ELR_MEMORIES.value not in summary["valid_scopes"]

    @pytest.mark.asyncio
    async def test_update_consent_invalid_scope_records_errors(self) -> None:
        """Invalid scope strings should be surfaced in the errors list."""
        payload: Dict[str, Any] = {
            "grants": [
                {"scope": "unknown_scope", "purpose": "Invalid test"}
            ],
            "revokes": [
                {"scope": "another_unknown"}
            ],
            "actor": "user_123",
        }

        result = await self.manager.update_consent("user_123", payload)

        assert result["errors"]
        assert any(e.startswith("invalid_scope:") for e in result["errors"])

    @pytest.mark.asyncio
    async def test_get_consent_no_records(self) -> None:
        """get_consent should return empty structures when no records exist."""
        summary = await self.manager.get_consent("no_such_user")

        assert summary["user_id"] == "no_such_user"
        assert summary["consents"] == []
        assert summary["valid_scopes"] == []
