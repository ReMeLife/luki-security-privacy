"""
Audit logging for LUKi
Immutable audit trail for security and compliance
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum
from pydantic import BaseModel
import json
import structlog

from ..crypto.hash import HashChain, secure_hash
from ..config import get_security_config

logger = structlog.get_logger(__name__)


class AuditEventType(str, Enum):
    """Types of audit events"""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    TOKEN_REFRESH = "token_refresh"
    
    # Access events
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    PERMISSION_CHECK = "permission_check"
    CONSENT_CHECK = "consent_check"
    
    # Administrative events
    USER_CREATED = "user_created"
    USER_MODIFIED = "user_modified"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    CONSENT_GRANTED = "consent_granted"
    CONSENT_REVOKED = "consent_revoked"
    
    # Security events
    ENCRYPTION_KEY_ROTATION = "key_rotation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    POLICY_VIOLATION = "policy_violation"
    EMERGENCY_ACCESS = "emergency_access"
    
    # System events
    SYSTEM_START = "system_start"
    SYSTEM_SHUTDOWN = "system_shutdown"
    BACKUP_CREATED = "backup_created"
    DATA_EXPORT = "data_export"


class AuditEvent(BaseModel):
    """Individual audit event"""
    id: str
    event_type: AuditEventType
    timestamp: datetime = datetime.utcnow()
    
    # Actor information
    user_id: Optional[str] = None
    role: Optional[str] = None
    session_id: Optional[str] = None
    
    # Resource information
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    
    # Action details
    action: str
    outcome: str  # success, failure, denied
    
    # Context
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    location: Optional[str] = None
    
    # Additional data
    details: Dict[str, Any] = {}
    
    # Integrity
    hash: Optional[str] = None
    previous_hash: Optional[str] = None
    
    def to_audit_string(self) -> str:
        """Convert to string for hashing"""
        audit_data = {
            "id": self.id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "role": self.role,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "action": self.action,
            "outcome": self.outcome,
            "ip_address": self.ip_address,
            "details": self.details
        }
        
        return json.dumps(audit_data, sort_keys=True, separators=(',', ':'))
    
    def compute_hash(self, previous_hash: str = None) -> str:
        """Compute hash for integrity verification"""
        audit_string = self.to_audit_string()
        
        if previous_hash:
            combined = f"{previous_hash}:{audit_string}"
        else:
            combined = audit_string
        
        return secure_hash(combined.encode('utf-8'))


class AuditLogger:
    """Audit logging system with integrity protection"""
    
    def __init__(self, storage_backend: Optional[Any] = None):
        self.storage = storage_backend or InMemoryAuditStorage()
        self.hash_chain = HashChain()
        self.config = get_security_config()
    
    def log_event(self, event_type: AuditEventType, action: str, outcome: str,
                  user_id: str = None, role: str = None, session_id: str = None,
                  resource_type: str = None, resource_id: str = None,
                  ip_address: str = None, user_agent: str = None,
                  location: str = None, details: Dict[str, Any] = None) -> AuditEvent:
        """Log an audit event"""
        
        import uuid
        
        event = AuditEvent(
            id=str(uuid.uuid4()),
            event_type=event_type,
            user_id=user_id,
            role=role,
            session_id=session_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            outcome=outcome,
            ip_address=ip_address,
            user_agent=user_agent,
            location=location,
            details=details or {}
        )
        
        # Compute hash with chain integrity
        event.previous_hash = self.hash_chain.current_hash
        event.hash = event.compute_hash(event.previous_hash)
        
        # Update hash chain
        self.hash_chain.add_entry(event.to_audit_string().encode('utf-8'))
        
        # Store event
        self.storage.store_event(event)
        
        logger.info("Audit event logged", 
                   event_type=event_type, 
                   user_id=user_id,
                   action=action,
                   outcome=outcome)
        
        return event
    
    def log_access(self, user_id: str, resource_type: str, resource_id: str,
                  action: str, outcome: str, role: str = None,
                  ip_address: str = None, details: Dict[str, Any] = None) -> AuditEvent:
        """Log data access event"""
        return self.log_event(
            event_type=AuditEventType.DATA_ACCESS,
            action=action,
            outcome=outcome,
            user_id=user_id,
            role=role,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            details=details
        )
    
    def log_authentication(self, user_id: str, outcome: str, 
                          ip_address: str = None, user_agent: str = None,
                          details: Dict[str, Any] = None) -> AuditEvent:
        """Log authentication event"""
        event_type = AuditEventType.LOGIN_SUCCESS if outcome == "success" else AuditEventType.LOGIN_FAILURE
        
        return self.log_event(
            event_type=event_type,
            action="authenticate",
            outcome=outcome,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details
        )
    
    def log_consent_action(self, user_id: str, action: str, scope: str,
                          granted_by: str = None, details: Dict[str, Any] = None) -> AuditEvent:
        """Log consent-related action"""
        event_type = AuditEventType.CONSENT_GRANTED if action == "grant" else AuditEventType.CONSENT_REVOKED
        
        return self.log_event(
            event_type=event_type,
            action=f"{action}_consent",
            outcome="success",
            user_id=user_id,
            details={
                "scope": scope,
                "granted_by": granted_by,
                **(details or {})
            }
        )
    
    def log_security_event(self, event_type: AuditEventType, action: str,
                          user_id: str = None, details: Dict[str, Any] = None) -> AuditEvent:
        """Log security-related event"""
        return self.log_event(
            event_type=event_type,
            action=action,
            outcome="detected",
            user_id=user_id,
            details=details
        )
    
    def get_events(self, user_id: str = None, event_type: AuditEventType = None,
                  start_time: datetime = None, end_time: datetime = None,
                  limit: int = 100) -> List[AuditEvent]:
        """Retrieve audit events with filters"""
        return self.storage.get_events(user_id, event_type, start_time, end_time, limit)
    
    def verify_integrity(self, events: List[AuditEvent] = None) -> bool:
        """Verify audit trail integrity"""
        if events is None:
            events = self.storage.get_events(limit=10000)  # Get all events
        
        if not events:
            return True
        
        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)
        
        # Verify hash chain
        previous_hash = None
        for event in events:
            expected_hash = event.compute_hash(previous_hash)
            
            if event.hash != expected_hash:
                logger.error("Audit integrity violation", 
                           event_id=event.id,
                           expected_hash=expected_hash,
                           actual_hash=event.hash)
                return False
            
            previous_hash = event.hash
        
        logger.info("Audit integrity verified", event_count=len(events))
        return True
    
    def export_audit_trail(self, user_id: str = None, 
                          start_time: datetime = None,
                          end_time: datetime = None) -> Dict[str, Any]:
        """Export audit trail for compliance"""
        events = self.get_events(user_id, None, start_time, end_time, limit=10000)
        
        return {
            "export_timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "start_time": start_time.isoformat() if start_time else None,
            "end_time": end_time.isoformat() if end_time else None,
            "event_count": len(events),
            "events": [event.dict() for event in events],
            "integrity_verified": self.verify_integrity(events)
        }


class InMemoryAuditStorage:
    """In-memory audit storage for testing"""
    
    def __init__(self):
        self.events: List[AuditEvent] = []
    
    def store_event(self, event: AuditEvent) -> bool:
        """Store audit event"""
        self.events.append(event)
        return True
    
    def get_events(self, user_id: str = None, event_type: AuditEventType = None,
                  start_time: datetime = None, end_time: datetime = None,
                  limit: int = 100) -> List[AuditEvent]:
        """Get filtered audit events"""
        filtered_events = self.events
        
        if user_id:
            filtered_events = [e for e in filtered_events if e.user_id == user_id]
        
        if event_type:
            filtered_events = [e for e in filtered_events if e.event_type == event_type]
        
        if start_time:
            filtered_events = [e for e in filtered_events if e.timestamp >= start_time]
        
        if end_time:
            filtered_events = [e for e in filtered_events if e.timestamp <= end_time]
        
        # Sort by timestamp (newest first)
        filtered_events.sort(key=lambda e: e.timestamp, reverse=True)
        
        return filtered_events[:limit]


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def log_access(user_id: str, resource_type: str, resource_id: str,
              action: str, outcome: str, role: str = None,
              ip_address: str = None, details: Dict[str, Any] = None) -> AuditEvent:
    """Log data access event"""
    return get_audit_logger().log_access(
        user_id, resource_type, resource_id, action, outcome, role, ip_address, details
    )


def log_authentication(user_id: str, outcome: str, 
                      ip_address: str = None, user_agent: str = None,
                      details: Dict[str, Any] = None) -> AuditEvent:
    """Log authentication event"""
    return get_audit_logger().log_authentication(
        user_id, outcome, ip_address, user_agent, details
    )


def log_consent_action(user_id: str, action: str, scope: str,
                      granted_by: str = None, details: Dict[str, Any] = None) -> AuditEvent:
    """Log consent action"""
    return get_audit_logger().log_consent_action(
        user_id, action, scope, granted_by, details
    )
