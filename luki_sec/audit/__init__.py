"""
Audit Subpackage for LUKi Security & Privacy Module

Provides audit logging capabilities, event types, and compliance tracking
for security operations and data access.
"""

from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Optional, Dict, Any
from enum import Enum
import uuid

from ..constants import AuditEventTypes


class AuditSeverity(str, Enum):
    """Audit event severity levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """
    Represents an audit event for security logging.
    
    Attributes:
        event_type: Type of audit event
        user_id: User associated with the event (if applicable)
        severity: Event severity level
        message: Human-readable description
        details: Additional structured data
        timestamp: When the event occurred
        event_id: Unique identifier for the event
        ip_address: Source IP address (if applicable)
        user_agent: Client user agent (if applicable)
    """
    event_type: str
    user_id: Optional[str] = None
    severity: AuditSeverity = AuditSeverity.INFO
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary for logging/storage"""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "user_id": self.user_id,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent
        }


def create_consent_event(
    event_type: str,
    user_id: str,
    scope: str,
    granted_by: Optional[str] = None,
    ip_address: Optional[str] = None
) -> AuditEvent:
    """
    Create a consent-related audit event.
    
    Args:
        event_type: Type of consent event
        user_id: User whose consent changed
        scope: Consent scope affected
        granted_by: Who granted/revoked (if applicable)
        ip_address: Source IP address
        
    Returns:
        AuditEvent configured for consent tracking
    """
    details: Dict[str, Any] = {"scope": scope}
    if granted_by:
        details["granted_by"] = granted_by
    
    return AuditEvent(
        event_type=event_type,
        user_id=user_id,
        severity=AuditSeverity.INFO,
        message=f"Consent {event_type} for scope '{scope}'",
        details=details,
        ip_address=ip_address
    )


def create_data_access_event(
    user_id: str,
    resource: str,
    action: str,
    accessor_id: Optional[str] = None,
    ip_address: Optional[str] = None
) -> AuditEvent:
    """
    Create a data access audit event.
    
    Args:
        user_id: User whose data was accessed
        resource: Resource that was accessed
        action: Action performed (read, write, delete)
        accessor_id: Who accessed the data
        ip_address: Source IP address
        
    Returns:
        AuditEvent configured for data access tracking
    """
    details: Dict[str, Any] = {
        "resource": resource,
        "action": action
    }
    if accessor_id:
        details["accessor_id"] = accessor_id
    
    return AuditEvent(
        event_type=AuditEventTypes.DATA_ACCESS,
        user_id=user_id,
        severity=AuditSeverity.INFO,
        message=f"Data {action} on resource '{resource}'",
        details=details,
        ip_address=ip_address
    )


def create_security_event(
    event_type: str,
    message: str,
    user_id: Optional[str] = None,
    severity: AuditSeverity = AuditSeverity.WARNING,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None
) -> AuditEvent:
    """
    Create a security-related audit event.
    
    Args:
        event_type: Type of security event
        message: Description of the event
        user_id: User involved (if applicable)
        severity: Event severity
        details: Additional context
        ip_address: Source IP address
        
    Returns:
        AuditEvent configured for security tracking
    """
    return AuditEvent(
        event_type=event_type,
        user_id=user_id,
        severity=severity,
        message=message,
        details=details or {},
        ip_address=ip_address
    )


__all__ = [
    "AuditSeverity",
    "AuditEvent",
    "create_consent_event",
    "create_data_access_event",
    "create_security_event",
]
