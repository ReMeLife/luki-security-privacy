"""
ID generation and validation utilities for LUKi
Secure, unique identifier generation for users, sessions, and traces
"""

import uuid
import secrets
import string
from typing import Optional
from datetime import datetime
import structlog

logger = structlog.get_logger(__name__)


def generate_user_id(prefix: str = "user") -> str:
    """Generate unique user ID"""
    timestamp = datetime.utcnow().strftime("%Y%m%d")
    random_part = secrets.token_hex(8)
    return f"{prefix}_{timestamp}_{random_part}"


def generate_session_id() -> str:
    """Generate secure session ID"""
    return f"sess_{secrets.token_urlsafe(32)}"


def generate_trace_id() -> str:
    """Generate trace ID for request tracking"""
    return f"trace_{uuid.uuid4().hex}"


def generate_api_key(prefix: str = "luki") -> str:
    """Generate API key"""
    return f"{prefix}_{secrets.token_urlsafe(40)}"


def generate_consent_id() -> str:
    """Generate consent record ID"""
    return f"consent_{uuid.uuid4()}"


def generate_audit_id() -> str:
    """Generate audit event ID"""
    return f"audit_{uuid.uuid4()}"


def validate_id(id_value: str, expected_prefix: Optional[str] = None) -> bool:
    """Validate ID format"""
    if not id_value or not isinstance(id_value, str):
        return False
    
    if expected_prefix and not id_value.startswith(expected_prefix):
        return False
    
    # Basic format validation
    parts = id_value.split("_")
    if len(parts) < 2:
        return False
    
    return True


def extract_id_info(id_value: str) -> dict:
    """Extract information from ID"""
    if not validate_id(id_value):
        return {"valid": False}
    
    parts = id_value.split("_")
    
    return {
        "valid": True,
        "prefix": parts[0],
        "full_id": id_value,
        "parts": parts
    }
