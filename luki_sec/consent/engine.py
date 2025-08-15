"""
Consent enforcement engine for LUKi
Runtime consent checking and enforcement logic
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
import structlog

from .models import ConsentScope, ConsentRecord, ConsentBundle, ConsentStatus
from .storage import ConsentStorage
from ..config import get_security_config

logger = structlog.get_logger(__name__)


class ConsentError(Exception):
    """Base exception for consent-related errors"""
    pass


class ConsentDeniedError(ConsentError):
    """Raised when consent is denied or insufficient"""
    pass


class ConsentExpiredError(ConsentError):
    """Raised when consent has expired"""
    pass


class ConsentEngine:
    """Core consent enforcement engine"""
    
    def __init__(self, storage: Optional[ConsentStorage] = None):
        self.storage = storage or ConsentStorage()
        self.config = get_security_config()
    
    def check_consent(self, user_id: str, scope: ConsentScope) -> bool:
        """Check if user has valid consent for scope"""
        try:
            consent_bundle = self.storage.get_user_consents(user_id)
            if not consent_bundle:
                return False
            
            return consent_bundle.has_valid_consent(scope)
            
        except Exception as e:
            logger.error("Error checking consent", user_id=user_id, scope=scope, error=str(e))
            return False
    
    def enforce_scope(self, user_id: str, requester_role: str, 
                     requested_scopes: List[ConsentScope]) -> None:
        """Enforce consent for requested scopes - raises if denied"""
        logger.info("Enforcing consent", user_id=user_id, requester_role=requester_role, 
                   scopes=requested_scopes)
        
        try:
            consent_bundle = self.storage.get_user_consents(user_id)
            if not consent_bundle:
                raise ConsentDeniedError(f"No consent records found for user {user_id}")
            
            for scope in requested_scopes:
                consent = consent_bundle.get_consent(scope)
                
                if not consent:
                    raise ConsentDeniedError(f"No consent record for scope {scope}")
                
                if consent.status == ConsentStatus.REVOKED:
                    raise ConsentDeniedError(f"Consent revoked for scope {scope}")
                
                if consent.status == ConsentStatus.EXPIRED:
                    raise ConsentExpiredError(f"Consent expired for scope {scope}")
                
                if not consent.is_valid():
                    # Auto-expire if past expiration
                    if consent.expires_at and datetime.utcnow() > consent.expires_at:
                        consent.expire()
                        self.storage.update_consent(consent)
                        raise ConsentExpiredError(f"Consent expired for scope {scope}")
                    
                    raise ConsentDeniedError(f"Invalid consent for scope {scope}")
            
            # Log successful access
            logger.info("Consent check passed", user_id=user_id, 
                       requester_role=requester_role, scopes=requested_scopes)
                       
        except Exception as e:
            # Log failed access attempt
            logger.warning("Consent check failed", user_id=user_id, 
                          requester_role=requester_role, scopes=requested_scopes, 
                          error=str(e))
            raise
    
    def grant_consent(self, user_id: str, scope: ConsentScope, purpose: str,
                     granted_by: str, ip_address: Optional[str] = None,
                     user_agent: Optional[str] = None, 
                     expires_in_days: Optional[int] = None) -> ConsentRecord:
        """Grant consent for a specific scope"""
        
        expires_in_days = expires_in_days or self.config.consent_expiry_days
        
        # Check if consent already exists
        existing_bundle = self.storage.get_user_consents(user_id)
        if existing_bundle:
            existing_consent = existing_bundle.get_consent(scope)
            if existing_consent:
                # Update existing consent
                existing_consent.grant(granted_by, ip_address, user_agent, expires_in_days)
                existing_consent.purpose = purpose
                self.storage.update_consent(existing_consent)
                
                logger.info("Updated existing consent", user_id=user_id, scope=scope)
                return existing_consent
        
        # Create new consent record
        consent = ConsentRecord(
            user_id=user_id,
            scope=scope,
            purpose=purpose
        )
        consent.grant(granted_by, ip_address, user_agent, expires_in_days)
        
        self.storage.store_consent(consent)
        
        logger.info("Granted new consent", user_id=user_id, scope=scope, 
                   expires_at=consent.expires_at)
        return consent
    
    def revoke_consent(self, user_id: str, scope: ConsentScope, 
                      revoked_by: str) -> bool:
        """Revoke consent for a specific scope"""
        
        consent_bundle = self.storage.get_user_consents(user_id)
        if not consent_bundle:
            return False
        
        consent = consent_bundle.get_consent(scope)
        if not consent:
            return False
        
        consent.revoke(revoked_by)
        self.storage.update_consent(consent)
        
        logger.info("Revoked consent", user_id=user_id, scope=scope, revoked_by=revoked_by)
        return True
    
    def get_user_consents(self, user_id: str) -> Optional[ConsentBundle]:
        """Get all consents for a user"""
        return self.storage.get_user_consents(user_id)
    
    def export_consent_history(self, user_id: str) -> Dict[str, Any]:
        """Export complete consent history for compliance requests"""
        consent_bundle = self.storage.get_user_consents(user_id)
        if not consent_bundle:
            return {"user_id": user_id, "consents": []}
        
        return {
            "user_id": user_id,
            "exported_at": datetime.utcnow().isoformat(),
            "consents": [consent.dict() for consent in consent_bundle.consents]
        }


# Global consent engine instance
_consent_engine: Optional[ConsentEngine] = None


def get_consent_engine() -> ConsentEngine:
    """Get the global consent engine instance"""
    global _consent_engine
    if _consent_engine is None:
        _consent_engine = ConsentEngine()
    return _consent_engine


# Convenience functions
def check_consent(user_id: str, scope: ConsentScope) -> bool:
    """Check if user has valid consent for scope"""
    return get_consent_engine().check_consent(user_id, scope)


def enforce_scope(user_id: str, requester_role: str, 
                 requested_scopes: List[ConsentScope]) -> None:
    """Enforce consent for requested scopes - raises if denied"""
    get_consent_engine().enforce_scope(user_id, requester_role, requested_scopes)


def grant_consent(user_id: str, scope: ConsentScope, purpose: str,
                 granted_by: str, ip_address: Optional[str] = None,
                 user_agent: Optional[str] = None, 
                 expires_in_days: Optional[int] = None) -> ConsentRecord:
    """Grant consent for a specific scope"""
    return get_consent_engine().grant_consent(
        user_id, scope, purpose, granted_by, ip_address, user_agent, expires_in_days
    )


def revoke_consent(user_id: str, scope: ConsentScope, revoked_by: str) -> bool:
    """Revoke consent for a specific scope"""
    return get_consent_engine().revoke_consent(user_id, scope, revoked_by)
