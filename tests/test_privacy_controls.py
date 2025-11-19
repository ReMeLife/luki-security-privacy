"""Tests for PrivacyControls and /privacy settings endpoints."""

from __future__ import annotations

from typing import Dict, Any

import pytest
from fastapi.testclient import TestClient

from luki_sec.privacy.controls import PrivacyControls, PrivacyStorage
from luki_sec.main import app
import luki_sec.main as main_mod


class TestPrivacyControls:
    def setup_method(self) -> None:
        storage = PrivacyStorage(database_url="sqlite:///:memory:")
        self.controls = PrivacyControls(storage=storage)

    @pytest.mark.asyncio
    async def test_update_and_get_settings(self) -> None:
        payload: Dict[str, Any] = {
            "privacy_level": "high",
            "allow_analytics": False,
            "custom_flag": "alpha",
        }

        result = await self.controls.update_settings("user_123", payload)

        assert result["user_id"] == "user_123"
        assert result["privacy_level"] == "high"
        assert result["allow_analytics"] is False
        assert result["extra"]["custom_flag"] == "alpha"

        fetched = await self.controls.get_settings("user_123")
        assert fetched["user_id"] == "user_123"
        assert fetched["privacy_level"] == "high"
        assert fetched["allow_analytics"] is False
        assert fetched["extra"]["custom_flag"] == "alpha"

    @pytest.mark.asyncio
    async def test_get_settings_creates_default_when_missing(self) -> None:
        fetched = await self.controls.get_settings("new_user")

        assert fetched["user_id"] == "new_user"
        assert isinstance(fetched["data_retention_days"], int)


class TestPrivacyEndpoints:
    def setup_method(self) -> None:
        storage = PrivacyStorage(database_url="sqlite:///test_privacy_endpoints.db")
        controls = PrivacyControls(storage=storage)
        main_mod.privacy_controls = controls
        self.client = TestClient(app)

    def test_update_privacy_settings_endpoint(self) -> None:
        payload: Dict[str, Any] = {
            "privacy_level": "low",
            "allow_personalization": False,
            "ui_hint": "compact",
        }

        response = self.client.post("/privacy/user_abc/settings", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        settings = data["settings"]
        assert settings["user_id"] == "user_abc"
        assert settings["privacy_level"] == "low"
        assert settings["allow_personalization"] is False
        assert settings["extra"]["ui_hint"] == "compact"

    def test_get_privacy_settings_endpoint(self) -> None:
        payload: Dict[str, Any] = {"privacy_level": "medium"}
        self.client.post("/privacy/user_xyz/settings", json=payload)

        response = self.client.get("/privacy/user_xyz/settings")

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "user_xyz"
        settings = data["settings"]
        assert settings["user_id"] == "user_xyz"
        assert settings["privacy_level"] == "medium"
