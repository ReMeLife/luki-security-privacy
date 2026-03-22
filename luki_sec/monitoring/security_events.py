"""
Security event monitoring for LUKi Security & Privacy
Real-time tracking and aggregation of security events
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from enum import Enum
from dataclasses import dataclass
import threading

logger = logging.getLogger(__name__)


class SecurityEventType(str, Enum):
    """Types of security events"""
    # Authentication events
    FAILED_LOGIN = "failed_login"
    SUSPICIOUS_LOGIN = "suspicious_login"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    
    # Authorization events
    PERMISSION_DENIED = "permission_denied"
    CONSENT_VIOLATION = "consent_violation"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    
    # Injection attempts
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    COMMAND_INJECTION_ATTEMPT = "command_injection_attempt"
    
    # Rate limiting
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    QUOTA_EXCEEDED = "quota_exceeded"
    
    # Data events
    SENSITIVE_DATA_ACCESS = "sensitive_data_access"
    DATA_EXPORT = "data_export"
    BULK_OPERATION = "bulk_operation"
    
    # Anomalies
    UNUSUAL_BEHAVIOR = "unusual_behavior"
    GEO_ANOMALY = "geo_anomaly"
    TIME_ANOMALY = "time_anomaly"


class SecurityEventSeverity(str, Enum):
    """Security event severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityEvent:
    """Individual security event"""
    event_type: SecurityEventType
    severity: SecurityEventSeverity
    timestamp: datetime
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "resource": self.resource,
            "action": self.action,
            "details": self.details
        }


class SecurityEventMonitor:
    """Monitor and aggregate security events"""
    
    def __init__(self, retention_hours: int = 24, alert_threshold: int = 10):
        """
        Initialize security event monitor
        
        Args:
            retention_hours: Hours to retain events
            alert_threshold: Number of events to trigger alert
        """
        self._lock = threading.Lock()
        self.retention_hours = retention_hours
        self.alert_threshold = alert_threshold
        
        # Event storage
        self._events: deque[SecurityEvent] = deque(maxlen=10000)
        
        # Aggregated counts by type and user
        self._event_counts: Dict[SecurityEventType, int] = defaultdict(int)
        self._user_event_counts: Dict[str, Dict[SecurityEventType, int]] = defaultdict(lambda: defaultdict(int))
        self._ip_event_counts: Dict[str, Dict[SecurityEventType, int]] = defaultdict(lambda: defaultdict(int))
        
        # Alert tracking
        self._recent_alerts: List[Dict[str, Any]] = []
    
    def record_event(
        self,
        event_type: SecurityEventType,
        severity: SecurityEventSeverity,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Record a security event
        
        Args:
            event_type: Type of event
            severity: Event severity
            user_id: User identifier
            ip_address: IP address
            user_agent: User agent string
            resource: Resource accessed
            action: Action attempted
            details: Additional details
        """
        with self._lock:
            event = SecurityEvent(
                event_type=event_type,
                severity=severity,
                timestamp=datetime.now(timezone.utc),
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                resource=resource,
                action=action,
                details=details or {}
            )
            
            # Store event
            self._events.append(event)
            
            # Update counts
            self._event_counts[event_type] += 1
            
            if user_id:
                self._user_event_counts[user_id][event_type] += 1
            
            if ip_address:
                self._ip_event_counts[ip_address][event_type] += 1
            
            # Log event
            log_level = {
                SecurityEventSeverity.INFO: logging.INFO,
                SecurityEventSeverity.LOW: logging.INFO,
                SecurityEventSeverity.MEDIUM: logging.WARNING,
                SecurityEventSeverity.HIGH: logging.ERROR,
                SecurityEventSeverity.CRITICAL: logging.CRITICAL
            }.get(severity, logging.WARNING)
            
            logger.log(
                log_level,
                f"Security event: {event_type.value}",
                extra={
                    "event_type": event_type.value,
                    "severity": severity.value,
                    "user_id": user_id,
                    "ip_address": ip_address,
                    "resource": resource,
                    "action": action
                }
            )
            
            # Check for alert conditions
            self._check_alerts(event)
    
    def _check_alerts(self, event: SecurityEvent):
        """Check if event should trigger alerts"""
        # Critical events always alert
        if event.severity == SecurityEventSeverity.CRITICAL:
            self._create_alert(
                event_type=event.event_type,
                message=f"Critical security event: {event.event_type.value}",
                events=[event]
            )
        
        # Check for patterns
        if event.user_id:
            user_events = self._get_recent_events_for_user(event.user_id, minutes=10)
            
            # Multiple failures
            failed_attempts = [e for e in user_events if e.event_type in [
                SecurityEventType.FAILED_LOGIN,
                SecurityEventType.PERMISSION_DENIED,
                SecurityEventType.UNAUTHORIZED_ACCESS
            ]]
            
            if len(failed_attempts) >= self.alert_threshold:
                self._create_alert(
                    event_type=SecurityEventType.BRUTE_FORCE_ATTEMPT,
                    message=f"Possible brute force attack from user {event.user_id}",
                    events=failed_attempts
                )
        
        if event.ip_address:
            ip_events = self._get_recent_events_for_ip(event.ip_address, minutes=10)
            
            # Multiple rate limit violations
            rate_limit_events = [e for e in ip_events if e.event_type == SecurityEventType.RATE_LIMIT_EXCEEDED]
            
            if len(rate_limit_events) >= self.alert_threshold:
                self._create_alert(
                    event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                    message=f"Excessive rate limiting from IP {event.ip_address}",
                    events=rate_limit_events
                )
    
    def _create_alert(self, event_type: SecurityEventType, message: str, events: List[SecurityEvent]):
        """Create security alert"""
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type.value,
            "message": message,
            "event_count": len(events),
            "severity": "high"
        }
        
        self._recent_alerts.append(alert)
        
        # Keep only recent alerts
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.retention_hours)
        self._recent_alerts = [
            a for a in self._recent_alerts
            if datetime.fromisoformat(a["timestamp"]) > cutoff
        ]
        
        logger.error(
            f"Security alert: {message}",
            extra={
                "alert": alert,
                "event_count": len(events)
            }
        )
    
    def _get_recent_events_for_user(self, user_id: str, minutes: int = 10) -> List[SecurityEvent]:
        """Get recent events for user"""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return [
            e for e in self._events
            if e.user_id == user_id and e.timestamp > cutoff
        ]
    
    def _get_recent_events_for_ip(self, ip_address: str, minutes: int = 10) -> List[SecurityEvent]:
        """Get recent events for IP"""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return [
            e for e in self._events
            if e.ip_address == ip_address and e.timestamp > cutoff
        ]
    
    def get_event_summary(self) -> Dict[str, Any]:
        """Get summary of security events"""
        with self._lock:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=self.retention_hours)
            recent_events = [e for e in self._events if e.timestamp > cutoff]
            
            # Count by severity
            severity_counts = defaultdict(int)
            for event in recent_events:
                severity_counts[event.severity.value] += 1
            
            # Top event types
            type_counts = defaultdict(int)
            for event in recent_events:
                type_counts[event.event_type.value] += 1
            
            top_types = sorted(
                type_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            return {
                "total_events": len(recent_events),
                "retention_hours": self.retention_hours,
                "severity_breakdown": dict(severity_counts),
                "top_event_types": dict(top_types),
                "recent_alerts": len(self._recent_alerts),
                "unique_users": len(set(e.user_id for e in recent_events if e.user_id)),
                "unique_ips": len(set(e.ip_address for e in recent_events if e.ip_address))
            }
    
    def get_user_events(self, user_id: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Get events for specific user"""
        with self._lock:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            user_events = [
                e for e in self._events
                if e.user_id == user_id and e.timestamp > cutoff
            ]
            
            return [e.to_dict() for e in user_events]
    
    def get_ip_events(self, ip_address: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Get events for specific IP"""
        with self._lock:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            ip_events = [
                e for e in self._events
                if e.ip_address == ip_address and e.timestamp > cutoff
            ]
            
            return [e.to_dict() for e in ip_events]
    
    def get_alerts(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        with self._lock:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            return [
                a for a in self._recent_alerts
                if datetime.fromisoformat(a["timestamp"]) > cutoff
            ]
    
    def get_high_risk_users(self, threshold: int = 5) -> List[Dict[str, Any]]:
        """Get users with high number of security events"""
        with self._lock:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            recent_events = [e for e in self._events if e.timestamp > cutoff]
            
            user_counts = defaultdict(int)
            user_severities = defaultdict(list)
            
            for event in recent_events:
                if event.user_id:
                    user_counts[event.user_id] += 1
                    user_severities[event.user_id].append(event.severity.value)
            
            high_risk = [
                {
                    "user_id": user_id,
                    "event_count": count,
                    "severity_breakdown": dict(
                        (sev, user_severities[user_id].count(sev))
                        for sev in set(user_severities[user_id])
                    )
                }
                for user_id, count in user_counts.items()
                if count >= threshold
            ]
            
            return sorted(high_risk, key=lambda x: x["event_count"], reverse=True)
    
    def clear_old_events(self):
        """Clear events older than retention period"""
        with self._lock:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=self.retention_hours)
            
            # Clear old events from deque
            while self._events and self._events[0].timestamp < cutoff:
                self._events.popleft()
            
            logger.info(f"Cleared old security events, {len(self._events)} remaining")


# Global security event monitor
_security_monitor: Optional[SecurityEventMonitor] = None


def get_security_monitor() -> SecurityEventMonitor:
    """Get the global security event monitor"""
    global _security_monitor
    if _security_monitor is None:
        _security_monitor = SecurityEventMonitor()
    return _security_monitor
