"""
Anomaly detection for LUKi Security & Privacy
Detects unusual access patterns and potential security threats
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AnomalyAlert:
    """Represents a detected anomaly"""
    alert_id: str
    timestamp: datetime
    severity: str  # low, medium, high, critical
    anomaly_type: str
    user_id: str
    description: str
    details: Dict[str, Any]
    recommended_action: str


class AccessPatternAnalyzer:
    """Analyzes access patterns for anomalies"""
    
    def __init__(self):
        self.access_history: Dict[str, List[Dict]] = defaultdict(list)
        self.baseline_patterns: Dict[str, Dict] = {}
    
    def record_access(
        self,
        user_id: str,
        resource: str,
        action: str,
        timestamp: Optional[datetime] = None
    ):
        """
        Record an access event
        
        Args:
            user_id: User identifier
            resource: Resource accessed
            action: Action performed
            timestamp: Access timestamp
        """
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        access_event = {
            "resource": resource,
            "action": action,
            "timestamp": timestamp.isoformat(),
            "hour": timestamp.hour,
            "day_of_week": timestamp.weekday()
        }
        
        self.access_history[user_id].append(access_event)
        
        # Keep only last 1000 events per user
        if len(self.access_history[user_id]) > 1000:
            self.access_history[user_id] = self.access_history[user_id][-1000:]
    
    def build_baseline(self, user_id: str) -> Dict[str, Any]:
        """
        Build baseline access pattern for user
        
        Args:
            user_id: User identifier
        
        Returns:
            Baseline pattern dictionary
        """
        history = self.access_history.get(user_id, [])
        
        if len(history) < 10:
            return {
                "sufficient_data": False,
                "message": "Insufficient data for baseline"
            }
        
        # Analyze typical access hours
        hours = [event["hour"] for event in history]
        hour_distribution = defaultdict(int)
        for hour in hours:
            hour_distribution[hour] += 1
        
        # Analyze typical days
        days = [event["day_of_week"] for event in history]
        day_distribution = defaultdict(int)
        for day in days:
            day_distribution[day] += 1
        
        # Analyze typical resources
        resources = [event["resource"] for event in history]
        resource_distribution = defaultdict(int)
        for resource in resources:
            resource_distribution[resource] += 1
        
        # Calculate access frequency
        if len(history) >= 2:
            first_access = datetime.fromisoformat(history[0]["timestamp"])
            last_access = datetime.fromisoformat(history[-1]["timestamp"])
            days_span = (last_access - first_access).days or 1
            avg_accesses_per_day = len(history) / days_span
        else:
            avg_accesses_per_day = 0
        
        baseline = {
            "sufficient_data": True,
            "total_accesses": len(history),
            "avg_accesses_per_day": avg_accesses_per_day,
            "typical_hours": [h for h, count in hour_distribution.items() if count > len(history) * 0.1],
            "typical_days": [d for d, count in day_distribution.items() if count > len(history) * 0.1],
            "common_resources": [r for r, count in resource_distribution.items() if count > len(history) * 0.05],
            "created_at": datetime.utcnow().isoformat()
        }
        
        self.baseline_patterns[user_id] = baseline
        
        logger.info(
            f"Built baseline pattern for user {user_id}",
            extra={"user_id": user_id, "total_accesses": len(history)}
        )
        
        return baseline
    
    def detect_anomalies(
        self,
        user_id: str,
        recent_window_hours: int = 1
    ) -> List[AnomalyAlert]:
        """
        Detect anomalies in recent access patterns
        
        Args:
            user_id: User identifier
            recent_window_hours: Hours to analyze
        
        Returns:
            List of detected anomalies
        """
        # Get baseline
        if user_id not in self.baseline_patterns:
            self.build_baseline(user_id)
        
        baseline = self.baseline_patterns.get(user_id, {})
        
        if not baseline.get("sufficient_data"):
            return []
        
        # Get recent accesses
        cutoff_time = datetime.utcnow() - timedelta(hours=recent_window_hours)
        recent_accesses = [
            event for event in self.access_history.get(user_id, [])
            if datetime.fromisoformat(event["timestamp"]) > cutoff_time
        ]
        
        if not recent_accesses:
            return []
        
        anomalies = []
        
        # Check for unusual access frequency
        accesses_per_hour = len(recent_accesses) / recent_window_hours
        expected_per_hour = baseline["avg_accesses_per_day"] / 24
        
        if accesses_per_hour > expected_per_hour * 5:
            anomalies.append(AnomalyAlert(
                alert_id=f"freq_{user_id}_{datetime.utcnow().timestamp()}",
                timestamp=datetime.utcnow(),
                severity="high",
                anomaly_type="unusual_frequency",
                user_id=user_id,
                description=f"Unusual access frequency: {accesses_per_hour:.1f} accesses/hour vs expected {expected_per_hour:.1f}",
                details={
                    "actual_rate": accesses_per_hour,
                    "expected_rate": expected_per_hour,
                    "threshold_multiplier": 5
                },
                recommended_action="Review recent activity and verify user identity"
            ))
        
        # Check for unusual access times
        unusual_hours = [
            event for event in recent_accesses
            if event["hour"] not in baseline["typical_hours"]
        ]
        
        if len(unusual_hours) > len(recent_accesses) * 0.5:
            anomalies.append(AnomalyAlert(
                alert_id=f"time_{user_id}_{datetime.utcnow().timestamp()}",
                timestamp=datetime.utcnow(),
                severity="medium",
                anomaly_type="unusual_access_time",
                user_id=user_id,
                description=f"Access at unusual hours: {len(unusual_hours)} out of {len(recent_accesses)} accesses",
                details={
                    "unusual_hours": [e["hour"] for e in unusual_hours],
                    "typical_hours": baseline["typical_hours"]
                },
                recommended_action="Verify if user is accessing from different timezone"
            ))
        
        # Check for unusual resources
        unusual_resources = [
            event for event in recent_accesses
            if event["resource"] not in baseline["common_resources"]
        ]
        
        if len(unusual_resources) > len(recent_accesses) * 0.7:
            anomalies.append(AnomalyAlert(
                alert_id=f"resource_{user_id}_{datetime.utcnow().timestamp()}",
                timestamp=datetime.utcnow(),
                severity="medium",
                anomaly_type="unusual_resource_access",
                user_id=user_id,
                description=f"Accessing unusual resources: {len(unusual_resources)} out of {len(recent_accesses)} accesses",
                details={
                    "unusual_resources": list(set(e["resource"] for e in unusual_resources)),
                    "common_resources": baseline["common_resources"]
                },
                recommended_action="Review if user role or permissions have changed"
            ))
        
        if anomalies:
            logger.warning(
                f"Detected {len(anomalies)} anomalies for user {user_id}",
                extra={
                    "user_id": user_id,
                    "anomaly_count": len(anomalies),
                    "severities": [a.severity for a in anomalies]
                }
            )
        
        return anomalies


class ThreatDetector:
    """Detects potential security threats"""
    
    def __init__(self):
        self.failed_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.blocked_users: Dict[str, datetime] = {}
    
    def record_failed_attempt(
        self,
        user_id: str,
        attempt_type: str,
        timestamp: Optional[datetime] = None
    ) -> Optional[AnomalyAlert]:
        """
        Record failed authentication/authorization attempt
        
        Args:
            user_id: User identifier
            attempt_type: Type of attempt (auth, consent, etc.)
            timestamp: Attempt timestamp
        
        Returns:
            AnomalyAlert if threshold exceeded, None otherwise
        """
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        self.failed_attempts[user_id].append(timestamp)
        
        # Keep only last hour of attempts
        cutoff = datetime.utcnow() - timedelta(hours=1)
        self.failed_attempts[user_id] = [
            t for t in self.failed_attempts[user_id]
            if t > cutoff
        ]
        
        # Check threshold
        recent_failures = len(self.failed_attempts[user_id])
        
        if recent_failures >= 5:
            # Block user temporarily
            self.blocked_users[user_id] = datetime.utcnow() + timedelta(minutes=15)
            
            logger.error(
                f"User {user_id} temporarily blocked due to {recent_failures} failed attempts",
                extra={"user_id": user_id, "failed_attempts": recent_failures}
            )
            
            return AnomalyAlert(
                alert_id=f"threat_{user_id}_{datetime.utcnow().timestamp()}",
                timestamp=datetime.utcnow(),
                severity="critical",
                anomaly_type="brute_force_attempt",
                user_id=user_id,
                description=f"Multiple failed {attempt_type} attempts: {recent_failures} in last hour",
                details={
                    "failed_attempts": recent_failures,
                    "attempt_type": attempt_type,
                    "blocked_until": self.blocked_users[user_id].isoformat()
                },
                recommended_action="User temporarily blocked. Investigate potential account compromise."
            )
        
        return None
    
    def is_blocked(self, user_id: str) -> bool:
        """Check if user is currently blocked"""
        if user_id not in self.blocked_users:
            return False
        
        block_until = self.blocked_users[user_id]
        
        if datetime.utcnow() >= block_until:
            # Block expired
            del self.blocked_users[user_id]
            return False
        
        return True
    
    def unblock_user(self, user_id: str):
        """Manually unblock a user"""
        if user_id in self.blocked_users:
            del self.blocked_users[user_id]
            logger.info(f"User {user_id} manually unblocked")


class AnomalyMonitor:
    """Coordinates anomaly detection across analyzers"""
    
    def __init__(self):
        self.access_analyzer = AccessPatternAnalyzer()
        self.threat_detector = ThreatDetector()
        self.alerts: List[AnomalyAlert] = []
    
    def record_access(self, user_id: str, resource: str, action: str):
        """Record access for pattern analysis"""
        self.access_analyzer.record_access(user_id, resource, action)
    
    def record_failed_attempt(self, user_id: str, attempt_type: str) -> Optional[AnomalyAlert]:
        """Record failed attempt and check for threats"""
        alert = self.threat_detector.record_failed_attempt(user_id, attempt_type)
        if alert:
            self.alerts.append(alert)
        return alert
    
    def check_anomalies(self, user_id: str) -> List[AnomalyAlert]:
        """Check for all types of anomalies"""
        anomalies = self.access_analyzer.detect_anomalies(user_id)
        
        for anomaly in anomalies:
            self.alerts.append(anomaly)
        
        return anomalies
    
    def get_recent_alerts(
        self,
        hours: int = 24,
        severity: Optional[str] = None
    ) -> List[AnomalyAlert]:
        """Get recent alerts"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        recent = [
            alert for alert in self.alerts
            if alert.timestamp > cutoff
        ]
        
        if severity:
            recent = [a for a in recent if a.severity == severity]
        
        return sorted(recent, key=lambda a: a.timestamp, reverse=True)


# Global instance
anomaly_monitor = AnomalyMonitor()
