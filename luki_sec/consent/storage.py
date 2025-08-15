"""
Consent storage adapters for LUKi
Database adapters for consent record persistence
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, UTC
import json
import structlog
from sqlalchemy import create_engine, Column, String, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session

from .models import ConsentRecord, ConsentBundle, ConsentScope, ConsentStatus

logger = structlog.get_logger(__name__)

Base = declarative_base()


class ConsentRecordDB(Base):
    """SQLAlchemy model for consent records"""
    __tablename__ = "consent_records"
    
    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False, index=True)
    scope = Column(String, nullable=False)
    status = Column(String, nullable=False)
    
    granted_at = Column(DateTime)
    revoked_at = Column(DateTime)
    expires_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    
    granted_by = Column(String)
    revoked_by = Column(String)
    ip_address = Column(String)
    user_agent = Column(Text)
    
    legal_basis = Column(String, nullable=False)
    purpose = Column(Text, nullable=False)
    consent_metadata = Column(Text)  # JSON string


class ConsentStorage:
    """Storage adapter for consent records"""
    
    def __init__(self, database_url: Optional[str] = None):
        # Default to SQLite for development
        self.database_url = database_url or "sqlite:///consent.db"
        self.engine = create_engine(self.database_url)
        self.SessionLocal = sessionmaker(bind=self.engine)
        
        # Create tables
        Base.metadata.create_all(bind=self.engine)
    
    def _to_db_model(self, consent: ConsentRecord) -> ConsentRecordDB:
        """Convert ConsentRecord to database model"""
        return ConsentRecordDB(
            id=consent.id,
            user_id=consent.user_id,
            scope=consent.scope.value,
            status=consent.status.value,
            granted_at=consent.granted_at,
            revoked_at=consent.revoked_at,
            expires_at=consent.expires_at,
            created_at=consent.created_at,
            updated_at=consent.updated_at,
            granted_by=consent.granted_by,
            revoked_by=consent.revoked_by,
            ip_address=consent.ip_address,
            user_agent=consent.user_agent,
            legal_basis=consent.legal_basis,
            purpose=consent.purpose,
            consent_metadata=json.dumps(consent.metadata) if consent.metadata else None
        )
    
    def _from_db_model(self, db_consent: ConsentRecordDB) -> ConsentRecord:
        """Convert database model to ConsentRecord"""
        metadata = {}
        if db_consent.consent_metadata:
            try:
                metadata = json.loads(db_consent.consent_metadata)
            except json.JSONDecodeError:
                logger.warning("Invalid metadata JSON", consent_id=db_consent.id)
        
        return ConsentRecord(
            id=db_consent.id,
            user_id=db_consent.user_id,
            scope=ConsentScope(db_consent.scope),
            status=ConsentStatus(db_consent.status),
            granted_at=db_consent.granted_at,
            revoked_at=db_consent.revoked_at,
            expires_at=db_consent.expires_at,
            created_at=db_consent.created_at,
            updated_at=db_consent.updated_at,
            granted_by=db_consent.granted_by,
            revoked_by=db_consent.revoked_by,
            ip_address=db_consent.ip_address,
            user_agent=db_consent.user_agent,
            legal_basis=db_consent.legal_basis,
            purpose=db_consent.purpose,
            metadata=metadata
        )
    
    def store_consent(self, consent: ConsentRecord) -> bool:
        """Store a new consent record"""
        try:
            with self.SessionLocal() as session:
                db_consent = self._to_db_model(consent)
                session.add(db_consent)
                session.commit()
                
                logger.info("Stored consent record", consent_id=consent.id, 
                           user_id=consent.user_id, scope=consent.scope)
                return True
                
        except Exception as e:
            logger.error("Failed to store consent", consent_id=consent.id, error=str(e))
            return False
    
    def update_consent(self, consent: ConsentRecord) -> bool:
        """Update an existing consent record"""
        try:
            with self.SessionLocal() as session:
                db_consent = session.query(ConsentRecordDB).filter_by(id=consent.id).first()
                if not db_consent:
                    logger.warning("Consent record not found for update", consent_id=consent.id)
                    return False
                
                # Update fields
                db_consent.status = consent.status.value
                db_consent.granted_at = consent.granted_at
                db_consent.revoked_at = consent.revoked_at
                db_consent.expires_at = consent.expires_at
                db_consent.updated_at = consent.updated_at
                db_consent.granted_by = consent.granted_by
                db_consent.revoked_by = consent.revoked_by
                db_consent.ip_address = consent.ip_address
                db_consent.user_agent = consent.user_agent
                db_consent.legal_basis = consent.legal_basis
                db_consent.purpose = consent.purpose
                db_consent.consent_metadata = json.dumps(consent.metadata) if consent.metadata else None
                
                session.commit()
                
                logger.info("Updated consent record", consent_id=consent.id)
                return True
                
        except Exception as e:
            logger.error("Failed to update consent", consent_id=consent.id, error=str(e))
            return False
    
    def get_consent(self, consent_id: str) -> Optional[ConsentRecord]:
        """Get a specific consent record by ID"""
        try:
            with self.SessionLocal() as session:
                db_consent = session.query(ConsentRecordDB).filter_by(id=consent_id).first()
                if db_consent:
                    return self._from_db_model(db_consent)
                return None
                
        except Exception as e:
            logger.error("Failed to get consent", consent_id=consent_id, error=str(e))
            return None
    
    def get_user_consents(self, user_id: str) -> Optional[ConsentBundle]:
        """Get all consent records for a user"""
        try:
            with self.SessionLocal() as session:
                db_consents = session.query(ConsentRecordDB).filter_by(user_id=user_id).all()
                
                if not db_consents:
                    return None
                
                consents = [self._from_db_model(db_consent) for db_consent in db_consents]
                
                return ConsentBundle(
                    user_id=user_id,
                    consents=consents,
                    created_at=min(c.created_at for c in consents),
                    updated_at=max(c.updated_at for c in consents)
                )
                
        except Exception as e:
            logger.error("Failed to get user consents", user_id=user_id, error=str(e))
            return None
    
    def get_consents_by_scope(self, scope: ConsentScope) -> List[ConsentRecord]:
        """Get all consent records for a specific scope"""
        try:
            with self.SessionLocal() as session:
                db_consents = session.query(ConsentRecordDB).filter_by(scope=scope.value).all()
                return [self._from_db_model(db_consent) for db_consent in db_consents]
                
        except Exception as e:
            logger.error("Failed to get consents by scope", scope=scope, error=str(e))
            return []
    
    def delete_user_consents(self, user_id: str) -> bool:
        """Delete all consent records for a user (GDPR right to be forgotten)"""
        try:
            with self.SessionLocal() as session:
                deleted_count = session.query(ConsentRecordDB).filter_by(user_id=user_id).delete()
                session.commit()
                
                logger.info("Deleted user consents", user_id=user_id, count=deleted_count)
                return True
                
        except Exception as e:
            logger.error("Failed to delete user consents", user_id=user_id, error=str(e))
            return False
    
    def cleanup_expired_consents(self) -> int:
        """Clean up expired consent records"""
        try:
            with self.SessionLocal() as session:
                now = datetime.now(UTC)
                
                # Mark expired consents
                expired_consents = session.query(ConsentRecordDB).filter(
                    ConsentRecordDB.expires_at < now,
                    ConsentRecordDB.status == ConsentStatus.GRANTED.value
                ).all()
                
                for consent in expired_consents:
                    consent.status = ConsentStatus.EXPIRED.value
                    consent.updated_at = now
                
                session.commit()
                
                logger.info("Cleaned up expired consents", count=len(expired_consents))
                return len(expired_consents)
                
        except Exception as e:
            logger.error("Failed to cleanup expired consents", error=str(e))
            return 0


class InMemoryConsentStorage(ConsentStorage):
    """In-memory storage for testing"""
    
    def __init__(self):
        self.consents: Dict[str, ConsentRecord] = {}
        self.user_consents: Dict[str, List[str]] = {}
    
    def store_consent(self, consent: ConsentRecord) -> bool:
        """Store consent in memory"""
        self.consents[consent.id] = consent
        
        if consent.user_id not in self.user_consents:
            self.user_consents[consent.user_id] = []
        
        if consent.id not in self.user_consents[consent.user_id]:
            self.user_consents[consent.user_id].append(consent.id)
        
        return True
    
    def update_consent(self, consent: ConsentRecord) -> bool:
        """Update consent in memory"""
        if consent.id in self.consents:
            self.consents[consent.id] = consent
            return True
        return False
    
    def get_consent(self, consent_id: str) -> Optional[ConsentRecord]:
        """Get consent from memory"""
        return self.consents.get(consent_id)
    
    def get_user_consents(self, user_id: str) -> Optional[ConsentBundle]:
        """Get user consents from memory"""
        if user_id not in self.user_consents:
            return None
        
        consents = []
        for consent_id in self.user_consents[user_id]:
            consent = self.consents.get(consent_id)
            if consent:
                consents.append(consent)
        
        if not consents:
            return None
        
        return ConsentBundle(
            user_id=user_id,
            consents=consents,
            created_at=min(c.created_at for c in consents),
            updated_at=max(c.updated_at for c in consents)
        )
