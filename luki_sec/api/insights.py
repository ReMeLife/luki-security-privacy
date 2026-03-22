"""
Security Insights API

Provides endpoints for querying security metrics, trends, and anomalies.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from luki_sec.monitoring.security_events import (
    get_security_monitor,
    SecurityEventType,
    SecurityEventSeverity
)
from luki_sec.audit.persistent_storage import get_audit_logger
from luki_sec.anomaly.detection import get_anomaly_detector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/security/insights", tags=["security-insights"])


class SecuritySummaryResponse(BaseModel):
    """Summary of security status"""
    status: str
    period_hours: int
    total_events: int
    critical_alerts: int
    high_risk_users: int
    anomalies_detected: int
    top_event_types: Dict[str, int]
    severity_breakdown: Dict[str, int]


class TrendDataPoint(BaseModel):
    """Single data point in a trend"""
    timestamp: str
    value: int
    label: Optional[str] = None


class SecurityTrendResponse(BaseModel):
    """Security trend data"""
    metric: str
    period_hours: int
    data_points: List[TrendDataPoint]
    trend: str  # increasing, decreasing, stable


@router.get("/summary", response_model=SecuritySummaryResponse)
async def get_security_summary(
    hours: int = Query(24, description="Hours to analyze", ge=1, le=168)
) -> SecuritySummaryResponse:
    """
    Get comprehensive security summary.
    
    Provides overview of security posture including:
    - Event counts and severity breakdown
    - Critical alerts
    - High-risk users
    - Top event types
    
    Args:
        hours: Number of hours to analyze (default: 24)
    
    Returns:
        SecuritySummaryResponse: Comprehensive security summary
    """
    try:
        monitor = get_security_monitor()
        
        # Get event summary
        event_summary = monitor.get_event_summary()
        
        # Get alerts
        alerts = monitor.get_alerts(hours=hours)
        critical_alerts = [a for a in alerts if a.get("severity") == "high"]
        
        # Get high-risk users
        high_risk = monitor.get_high_risk_users(threshold=5)
        
        # Try to get anomalies (may fail if not initialized)
        anomalies_count = 0
        try:
            detector = get_anomaly_detector()
            # Count recent anomalies would go here
        except Exception:
            pass
        
        # Determine overall status
        if len(critical_alerts) > 5 or len(high_risk) > 10:
            status = "critical"
        elif len(critical_alerts) > 2 or len(high_risk) > 5:
            status = "warning"
        else:
            status = "healthy"
        
        return SecuritySummaryResponse(
            status=status,
            period_hours=hours,
            total_events=event_summary.get("total_events", 0),
            critical_alerts=len(critical_alerts),
            high_risk_users=len(high_risk),
            anomalies_detected=anomalies_count,
            top_event_types=event_summary.get("top_event_types", {}),
            severity_breakdown=event_summary.get("severity_breakdown", {})
        )
        
    except Exception as e:
        logger.error(f"Failed to generate security summary: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to generate security summary")


@router.get("/events", response_model=Dict[str, Any])
async def query_security_events(
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    hours: int = Query(24, description="Hours to look back", ge=1, le=168),
    limit: int = Query(100, description="Max results", ge=1, le=1000)
) -> Dict[str, Any]:
    """
    Query security events with filters.
    
    Args:
        user_id: Optional user ID filter
        event_type: Optional event type filter
        severity: Optional severity filter
        hours: Hours to look back
        limit: Maximum results
    
    Returns:
        Dict with matching events
    """
    try:
        monitor = get_security_monitor()
        
        if user_id:
            events = monitor.get_user_events(user_id, hours=hours)
        else:
            # Get all recent events from internal storage
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            all_events = [
                e.to_dict() for e in monitor._events
                if e.timestamp > cutoff
            ]
            events = all_events
        
        # Apply filters
        if event_type:
            events = [e for e in events if e.get("event_type") == event_type]
        if severity:
            events = [e for e in events if e.get("severity") == severity]
        
        # Limit results
        events = events[:limit]
        
        return {
            "total_count": len(events),
            "events": events,
            "filters": {
                "user_id": user_id,
                "event_type": event_type,
                "severity": severity,
                "hours": hours
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to query security events: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to query security events")


@router.get("/alerts", response_model=Dict[str, Any])
async def get_security_alerts(
    hours: int = Query(24, description="Hours to look back", ge=1, le=168)
) -> Dict[str, Any]:
    """
    Get security alerts.
    
    Args:
        hours: Hours to look back
    
    Returns:
        Dict with alerts
    """
    try:
        monitor = get_security_monitor()
        alerts = monitor.get_alerts(hours=hours)
        
        return {
            "total_count": len(alerts),
            "alerts": alerts,
            "period_hours": hours
        }
        
    except Exception as e:
        logger.error(f"Failed to get security alerts: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get security alerts")


@router.get("/users/high-risk", response_model=Dict[str, Any])
async def get_high_risk_users(
    threshold: int = Query(5, description="Event count threshold", ge=1)
) -> Dict[str, Any]:
    """
    Get users with high security event counts.
    
    Args:
        threshold: Minimum event count to be considered high-risk
    
    Returns:
        Dict with high-risk users
    """
    try:
        monitor = get_security_monitor()
        high_risk = monitor.get_high_risk_users(threshold=threshold)
        
        return {
            "total_count": len(high_risk),
            "high_risk_users": high_risk,
            "threshold": threshold
        }
        
    except Exception as e:
        logger.error(f"Failed to get high-risk users: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get high-risk users")


@router.get("/trends/{metric}", response_model=SecurityTrendResponse)
async def get_security_trend(
    metric: str,
    hours: int = Query(24, description="Hours to analyze", ge=1, le=168),
    interval_minutes: int = Query(60, description="Data point interval", ge=5, le=1440)
) -> SecurityTrendResponse:
    """
    Get trend data for a security metric.
    
    Supported metrics:
    - failed_logins
    - permission_denied
    - rate_limit_exceeded
    - total_events
    
    Args:
        metric: Metric name
        hours: Hours to analyze
        interval_minutes: Interval between data points
    
    Returns:
        SecurityTrendResponse: Trend data
    """
    try:
        monitor = get_security_monitor()
        
        # Calculate time buckets
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)
        interval = timedelta(minutes=interval_minutes)
        
        # Generate time buckets
        buckets = []
        current = start_time
        while current <= end_time:
            buckets.append(current)
            current += interval
        
        # Count events per bucket
        data_points = []
        for bucket_start in buckets:
            bucket_end = bucket_start + interval
            
            # Count events in this bucket
            count = sum(
                1 for e in monitor._events
                if bucket_start <= e.timestamp < bucket_end
                and (metric == "total_events" or e.event_type.value == metric)
            )
            
            data_points.append(TrendDataPoint(
                timestamp=bucket_start.isoformat(),
                value=count
            ))
        
        # Analyze trend
        if len(data_points) >= 2:
            first_half = sum(dp.value for dp in data_points[:len(data_points)//2])
            second_half = sum(dp.value for dp in data_points[len(data_points)//2:])
            
            if second_half > first_half * 1.2:
                trend = "increasing"
            elif second_half < first_half * 0.8:
                trend = "decreasing"
            else:
                trend = "stable"
        else:
            trend = "insufficient_data"
        
        return SecurityTrendResponse(
            metric=metric,
            period_hours=hours,
            data_points=data_points,
            trend=trend
        )
        
    except Exception as e:
        logger.error(f"Failed to get security trend: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get security trend")


@router.get("/audit/query", response_model=Dict[str, Any])
async def query_audit_logs(
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    outcome: Optional[str] = Query(None, description="Filter by outcome"),
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)"),
    limit: int = Query(100, description="Max results", ge=1, le=1000)
) -> Dict[str, Any]:
    """
    Query persistent audit logs.
    
    Args:
        user_id: Optional user ID filter
        event_type: Optional event type filter
        outcome: Optional outcome filter (success, failure, denied)
        start_date: Optional start date filter
        end_date: Optional end date filter
        limit: Maximum results
    
    Returns:
        Dict with matching audit entries
    """
    try:
        audit_logger = get_audit_logger()
        
        # Parse dates
        start_dt = datetime.fromisoformat(start_date) if start_date else None
        end_dt = datetime.fromisoformat(end_date) if end_date else None
        
        # Query logs
        results = audit_logger.query_logs(
            start_date=start_dt,
            end_date=end_dt,
            user_id=user_id,
            event_type=event_type,
            outcome=outcome,
            limit=limit
        )
        
        return {
            "total_count": len(results),
            "audit_entries": results,
            "filters": {
                "user_id": user_id,
                "event_type": event_type,
                "outcome": outcome,
                "start_date": start_date,
                "end_date": end_date
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to query audit logs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to query audit logs")


@router.get("/stats", response_model=Dict[str, Any])
async def get_security_stats() -> Dict[str, Any]:
    """
    Get comprehensive security statistics.
    
    Returns:
        Dict with various security statistics
    """
    try:
        monitor = get_security_monitor()
        audit_logger = get_audit_logger()
        
        return {
            "security_monitor": monitor.get_event_summary(),
            "audit_logger": audit_logger.get_statistics(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get security stats: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get security stats")
