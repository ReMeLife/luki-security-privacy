from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

from .models import ConsentScope
from .engine import ConsentEngine, get_consent_engine


logger = structlog.get_logger(__name__)


class ConsentGrant(BaseModel):
    scope: str
    purpose: str
    expires_in_days: Optional[int] = None


class ConsentRevoke(BaseModel):
    scope: str


class ConsentUpdateRequest(BaseModel):
    grants: List[ConsentGrant] = Field(default_factory=list)
    revokes: List[ConsentRevoke] = Field(default_factory=list)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    actor: Optional[str] = None


class ConsentManager:
    def __init__(self, engine: Optional[ConsentEngine] = None):
        self.engine = engine or get_consent_engine()

    async def update_consent(self, user_id: str, consent_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            payload = ConsentUpdateRequest(**consent_data)
        except Exception as exc:
            logger.error("Invalid consent update payload", user_id=user_id, error=str(exc))
            raise

        updated_records: List[Dict[str, Any]] = []
        revoked_scopes: List[str] = []
        errors: List[str] = []

        granted_by = payload.actor or user_id

        for grant in payload.grants:
            try:
                scope = ConsentScope(grant.scope)
            except ValueError:
                errors.append(f"invalid_scope:{grant.scope}")
                continue
            try:
                record = self.engine.grant_consent(
                    user_id=user_id,
                    scope=scope,
                    purpose=grant.purpose,
                    granted_by=granted_by,
                    ip_address=payload.ip_address,
                    user_agent=payload.user_agent,
                    expires_in_days=grant.expires_in_days,
                )
                updated_records.append(record.model_dump())
            except Exception as exc:
                logger.error(
                    "Failed to grant consent",
                    user_id=user_id,
                    scope=scope.value,
                    error=str(exc),
                )
                errors.append(f"grant_failed:{scope.value}")

        for revoke in payload.revokes:
            try:
                scope = ConsentScope(revoke.scope)
            except ValueError:
                errors.append(f"invalid_scope:{revoke.scope}")
                continue
            try:
                ok = self.engine.revoke_consent(
                    user_id=user_id,
                    scope=scope,
                    revoked_by=granted_by,
                )
                if ok:
                    revoked_scopes.append(scope.value)
                else:
                    errors.append(f"revoke_not_found:{scope.value}")
            except Exception as exc:
                logger.error(
                    "Failed to revoke consent",
                    user_id=user_id,
                    scope=scope.value,
                    error=str(exc),
                )
                errors.append(f"revoke_failed:{scope.value}")

        bundle = self.engine.get_user_consents(user_id)
        valid_scopes: List[str] = []
        if bundle:
            valid_scopes = [s.value for s in bundle.get_valid_scopes()]

        return {
            "user_id": user_id,
            "updated": updated_records,
            "revoked_scopes": revoked_scopes,
            "valid_scopes": valid_scopes,
            "errors": errors,
        }

    async def get_consent(self, user_id: str) -> Dict[str, Any]:
        bundle = self.engine.get_user_consents(user_id)
        if not bundle:
            return {"user_id": user_id, "consents": [], "valid_scopes": []}

        return {
            "user_id": user_id,
            "consents": [c.model_dump() for c in bundle.consents],
            "valid_scopes": [s.value for s in bundle.get_valid_scopes()],
        }
