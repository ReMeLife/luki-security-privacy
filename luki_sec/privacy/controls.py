from __future__ import annotations

from typing import Optional, Dict, Any

import json
import structlog
from datetime import datetime, UTC

from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker

from ..config import get_security_config


logger = structlog.get_logger(__name__)
Base = declarative_base()


class PrivacySettingsDB(Base):
    __tablename__ = "privacy_settings"

    user_id = Column(String, primary_key=True)
    privacy_level = Column(String, nullable=False)
    data_retention_days = Column(Integer, nullable=False)
    anonymize_data = Column(Boolean, nullable=False)
    allow_analytics = Column(Boolean, nullable=False)
    allow_personalization = Column(Boolean, nullable=False)
    allow_research = Column(Boolean, nullable=False)
    extra = Column(Text)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class PrivacySettings(BaseModel):
    user_id: str
    privacy_level: str = "medium"
    data_retention_days: int = 365
    anonymize_data: bool = True
    allow_analytics: bool = True
    allow_personalization: bool = True
    allow_research: bool = False
    extra: Dict[str, Any] = Field(default_factory=dict)


class PrivacyStorage:
    def __init__(self, database_url: Optional[str] = None):
        config = get_security_config()
        default_url = "sqlite:///privacy.db"
        self.database_url = database_url or default_url
        self.engine = create_engine(self.database_url)
        self.SessionLocal = sessionmaker(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        logger.info("Privacy storage initialised", database_url=self.database_url)

    def get_settings(self, user_id: str) -> Optional[PrivacySettings]:
        with self.SessionLocal() as session:
            row = session.query(PrivacySettingsDB).filter_by(user_id=user_id).first()
            if not row:
                return None

            extra: Dict[str, Any] = {}
            if row.extra:
                try:
                    extra = json.loads(row.extra)
                except json.JSONDecodeError:
                    logger.warning("Invalid privacy extra JSON", user_id=user_id)

            return PrivacySettings(
                user_id=row.user_id,
                privacy_level=row.privacy_level,
                data_retention_days=row.data_retention_days,
                anonymize_data=row.anonymize_data,
                allow_analytics=row.allow_analytics,
                allow_personalization=row.allow_personalization,
                allow_research=row.allow_research,
                extra=extra,
            )

    def upsert_settings(self, settings: PrivacySettings) -> PrivacySettings:
        now = datetime.now(UTC)
        with self.SessionLocal() as session:
            row = session.query(PrivacySettingsDB).filter_by(user_id=settings.user_id).first()
            payload = settings.model_dump()
            extra_json = json.dumps(payload.get("extra") or {}) if payload.get("extra") else None

            if row is None:
                row = PrivacySettingsDB(
                    user_id=settings.user_id,
                    privacy_level=settings.privacy_level,
                    data_retention_days=settings.data_retention_days,
                    anonymize_data=settings.anonymize_data,
                    allow_analytics=settings.allow_analytics,
                    allow_personalization=settings.allow_personalization,
                    allow_research=settings.allow_research,
                    extra=extra_json,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            else:
                row.privacy_level = settings.privacy_level
                row.data_retention_days = settings.data_retention_days
                row.anonymize_data = settings.anonymize_data
                row.allow_analytics = settings.allow_analytics
                row.allow_personalization = settings.allow_personalization
                row.allow_research = settings.allow_research
                row.extra = extra_json
                row.updated_at = now

            session.commit()

        logger.info("Privacy settings updated", user_id=settings.user_id)
        return settings


class PrivacyControls:
    def __init__(self, storage: Optional[PrivacyStorage] = None, database_url: Optional[str] = None):
        self.config = get_security_config()
        self.storage = storage or PrivacyStorage(database_url=database_url)

    async def update_settings(self, user_id: str, settings: Dict[str, Any]) -> Dict[str, Any]:
        current = self.storage.get_settings(user_id)
        if current is None:
            current = PrivacySettings(
                user_id=user_id,
                data_retention_days=self.config.audit_retention_days,
            )

        data = current.model_dump()
        recognised = {
            "privacy_level",
            "data_retention_days",
            "anonymize_data",
            "allow_analytics",
            "allow_personalization",
            "allow_research",
        }

        extra = data.get("extra") or {}

        for key, value in settings.items():
            if key in recognised:
                data[key] = value
            else:
                extra[key] = value

        data["extra"] = extra

        updated = PrivacySettings(**data)
        stored = self.storage.upsert_settings(updated)
        return stored.model_dump()

    async def get_settings(self, user_id: str) -> Dict[str, Any]:
        settings = self.storage.get_settings(user_id)
        if settings is None:
            settings = PrivacySettings(
                user_id=user_id,
                data_retention_days=self.config.audit_retention_days,
            )
            self.storage.upsert_settings(settings)

        return settings.model_dump()
