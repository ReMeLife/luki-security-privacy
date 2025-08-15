"""
Consent data models for LUKi
GDPR/HIPAA compliant consent record structures
"""

from datetime import datetime, timedelta, UTC
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import uuid


class ConsentScope(str, Enum):
    """Granular consent scopes for different data categories"""
    # ELR Data Categories
    ELR_BASIC = "elr_basic"                    # Name, age, basic demographics
    ELR_INTERESTS = "elr_interests"            # Hobbies, preferences, activities
    ELR_MEMORIES = "elr_memories"              # Personal memories, life events
    ELR_HEALTH = "elr_health"                  # Health-related information
    ELR_FAMILY = "elr_family"                  # Family relationships, contacts
    ELR_LOCATION = "elr_location"              # Location data, addresses
    
    # Processing Categories
    ANALYTICS = "analytics"                     # Data analytics and insights
    PERSONALIZATION = "personalization"        # Personalized recommendations
    RESEARCH = "research"                       # Research and development
    CARE_COORDINATION = "care_coordination"     # Care team coordination
    
    # AI/ML Categories
    MODEL_TRAINING = "model_training"           # Training AI models
    FEDERATED_LEARNING = "federated_learning"  # Federated learning participation
    DIFFERENTIAL_PRIVACY = "differential_privacy"  # DP-enabled analytics


class ConsentStatus(str, Enum):
    """Consent record status"""
    GRANTED = "granted"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PENDING = "pending"


class ConsentRecord(BaseModel):
    """Individual consent record"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = Field(..., description="User identifier")
    scope: ConsentScope = Field(..., description="Consent scope")
    status: ConsentStatus = Field(default=ConsentStatus.PENDING)
    
    # Timestamps
    granted_at: Optional[datetime] = Field(default=None)
    revoked_at: Optional[datetime] = Field(default=None)
    expires_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    
    # Audit trail
    granted_by: Optional[str] = Field(default=None, description="Who granted consent")
    revoked_by: Optional[str] = Field(default=None, description="Who revoked consent")
    ip_address: Optional[str] = Field(default=None, description="IP address when granted")
    user_agent: Optional[str] = Field(default=None, description="User agent when granted")
    
    # Legal basis (GDPR Article 6)
    legal_basis: str = Field(default="consent", description="Legal basis for processing")
    purpose: str = Field(..., description="Purpose of data processing")
    
    # Additional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    def is_valid(self) -> bool:
        """Check if consent is currently valid"""
        if self.status != ConsentStatus.GRANTED:
            return False
            
        if self.expires_at and datetime.now(UTC) > self.expires_at:
            return False
            
        return True
    
    def grant(self, granted_by: str, ip_address: Optional[str] = None, 
              user_agent: Optional[str] = None, expires_in_days: int = 365) -> None:
        """Grant consent"""
        self.status = ConsentStatus.GRANTED
        self.granted_at = datetime.now(UTC)
        self.granted_by = granted_by
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)
        self.updated_at = datetime.now(UTC)
    
    def revoke(self, revoked_by: str) -> None:
        """Revoke consent"""
        self.status = ConsentStatus.REVOKED
        self.revoked_at = datetime.now(UTC)
        self.revoked_by = revoked_by
        self.updated_at = datetime.now(UTC)
    
    def expire(self) -> None:
        """Mark consent as expired"""
        self.status = ConsentStatus.EXPIRED
        self.updated_at = datetime.now(UTC)


class ConsentBundle(BaseModel):
    """Collection of related consent records"""
    user_id: str
    consents: List[ConsentRecord] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    
    def get_consent(self, scope: ConsentScope) -> Optional[ConsentRecord]:
        """Get consent record for specific scope"""
        for consent in self.consents:
            if consent.scope == scope:
                return consent
        return None
    
    def has_valid_consent(self, scope: ConsentScope) -> bool:
        """Check if user has valid consent for scope"""
        consent = self.get_consent(scope)
        return consent is not None and consent.is_valid()
    
    def get_valid_scopes(self) -> List[ConsentScope]:
        """Get all scopes with valid consent"""
        return [c.scope for c in self.consents if c.is_valid()]
