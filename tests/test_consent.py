"""
Tests for consent management module
"""

import pytest
from datetime import datetime, timedelta
from luki_sec.consent.models import ConsentRecord, ConsentScope, ConsentStatus, ConsentBundle
from luki_sec.consent.engine import ConsentEngine, ConsentDeniedError, ConsentExpiredError
from luki_sec.consent.storage import InMemoryConsentStorage


class TestConsentModels:
    """Test consent data models"""
    
    def test_consent_record_creation(self):
        """Test creating a consent record"""
        consent = ConsentRecord(
            user_id="user_123",
            scope=ConsentScope.ELR_INTERESTS,
            purpose="Personalized recommendations"
        )
        
        assert consent.user_id == "user_123"
        assert consent.scope == ConsentScope.ELR_INTERESTS
        assert consent.status == ConsentStatus.PENDING
        assert not consent.is_valid()
    
    def test_consent_grant(self):
        """Test granting consent"""
        consent = ConsentRecord(
            user_id="user_123",
            scope=ConsentScope.ELR_INTERESTS,
            purpose="Personalized recommendations"
        )
        
        consent.grant("admin", "192.168.1.1", "TestAgent/1.0")
        
        assert consent.status == ConsentStatus.GRANTED
        assert consent.is_valid()
        assert consent.granted_by == "admin"
        assert consent.ip_address == "192.168.1.1"
    
    def test_consent_revoke(self):
        """Test revoking consent"""
        consent = ConsentRecord(
            user_id="user_123",
            scope=ConsentScope.ELR_INTERESTS,
            purpose="Personalized recommendations"
        )
        
        consent.grant("admin")
        assert consent.is_valid()
        
        consent.revoke("user_123")
        assert not consent.is_valid()
        assert consent.status == ConsentStatus.REVOKED
    
    def test_consent_expiry(self):
        """Test consent expiration"""
        consent = ConsentRecord(
            user_id="user_123",
            scope=ConsentScope.ELR_INTERESTS,
            purpose="Personalized recommendations"
        )
        
        # Grant with short expiry
        consent.grant("admin", expires_in_days=0)
        consent.expires_at = datetime.utcnow() - timedelta(minutes=1)
        
        assert not consent.is_valid()


class TestConsentEngine:
    """Test consent enforcement engine"""
    
    def setup_method(self):
        """Setup test environment"""
        self.storage = InMemoryConsentStorage()
        self.engine = ConsentEngine(self.storage)
    
    def test_grant_and_check_consent(self):
        """Test granting and checking consent"""
        # Grant consent
        consent = self.engine.grant_consent(
            user_id="user_123",
            scope=ConsentScope.ELR_INTERESTS,
            purpose="Testing",
            granted_by="admin"
        )
        
        assert consent.is_valid()
        
        # Check consent
        has_consent = self.engine.check_consent("user_123", ConsentScope.ELR_INTERESTS)
        assert has_consent
        
        # Check non-existent consent
        has_consent = self.engine.check_consent("user_123", ConsentScope.ELR_HEALTH)
        assert not has_consent
    
    def test_enforce_scope_success(self):
        """Test successful scope enforcement"""
        # Grant multiple consents
        self.engine.grant_consent("user_123", ConsentScope.ELR_INTERESTS, "Testing", "admin")
        self.engine.grant_consent("user_123", ConsentScope.ELR_MEMORIES, "Testing", "admin")
        
        # Should not raise exception
        self.engine.enforce_scope(
            "user_123", 
            "agent", 
            [ConsentScope.ELR_INTERESTS, ConsentScope.ELR_MEMORIES]
        )
    
    def test_enforce_scope_denied(self):
        """Test scope enforcement denial"""
        # Grant only one consent
        self.engine.grant_consent("user_123", ConsentScope.ELR_INTERESTS, "Testing", "admin")
        
        # Should raise exception for missing consent
        with pytest.raises(ConsentDeniedError):
            self.engine.enforce_scope(
                "user_123",
                "agent",
                [ConsentScope.ELR_INTERESTS, ConsentScope.ELR_HEALTH]
            )
    
    def test_enforce_scope_expired(self):
        """Test scope enforcement with expired consent"""
        # Grant consent with short expiry
        consent = self.engine.grant_consent(
            "user_123", 
            ConsentScope.ELR_INTERESTS, 
            "Testing", 
            "admin",
            expires_in_days=0
        )
        
        # Manually expire
        consent.expires_at = datetime.utcnow() - timedelta(minutes=1)
        self.storage.update_consent(consent)
        
        # Should raise exception for expired consent
        with pytest.raises(ConsentExpiredError):
            self.engine.enforce_scope("user_123", "agent", [ConsentScope.ELR_INTERESTS])
    
    def test_revoke_consent(self):
        """Test consent revocation"""
        # Grant consent
        self.engine.grant_consent("user_123", ConsentScope.ELR_INTERESTS, "Testing", "admin")
        
        # Verify granted
        assert self.engine.check_consent("user_123", ConsentScope.ELR_INTERESTS)
        
        # Revoke consent
        success = self.engine.revoke_consent("user_123", ConsentScope.ELR_INTERESTS, "user_123")
        assert success
        
        # Verify revoked
        assert not self.engine.check_consent("user_123", ConsentScope.ELR_INTERESTS)
    
    def test_export_consent_history(self):
        """Test consent history export"""
        # Grant multiple consents
        self.engine.grant_consent("user_123", ConsentScope.ELR_INTERESTS, "Testing", "admin")
        self.engine.grant_consent("user_123", ConsentScope.ELR_MEMORIES, "Testing", "admin")
        
        # Export history
        history = self.engine.export_consent_history("user_123")
        
        assert history["user_id"] == "user_123"
        assert len(history["consents"]) == 2
        assert "exported_at" in history


class TestConsentBundle:
    """Test consent bundle functionality"""
    
    def test_consent_bundle_operations(self):
        """Test consent bundle operations"""
        bundle = ConsentBundle(user_id="user_123")
        
        # Add consents
        consent1 = ConsentRecord(
            user_id="user_123",
            scope=ConsentScope.ELR_INTERESTS,
            purpose="Testing"
        )
        consent1.grant("admin")
        
        consent2 = ConsentRecord(
            user_id="user_123",
            scope=ConsentScope.ELR_MEMORIES,
            purpose="Testing"
        )
        consent2.grant("admin")
        
        bundle.consents = [consent1, consent2]
        
        # Test operations
        assert bundle.has_valid_consent(ConsentScope.ELR_INTERESTS)
        assert bundle.has_valid_consent(ConsentScope.ELR_MEMORIES)
        assert not bundle.has_valid_consent(ConsentScope.ELR_HEALTH)
        
        valid_scopes = bundle.get_valid_scopes()
        assert ConsentScope.ELR_INTERESTS in valid_scopes
        assert ConsentScope.ELR_MEMORIES in valid_scopes
        assert len(valid_scopes) == 2
