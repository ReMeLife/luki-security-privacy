"""
Security-Focused Validators for LUKi Security & Privacy Module

Provides validation utilities for user IDs, consent scopes, 
encryption parameters, and policy data.
"""

import re
import logging
from typing import Optional, Any, List

from ..constants import ConsentScopes, PrivacyLevels, ConsentStatus
from ..exceptions import ValidationError, InvalidScopeError

logger = logging.getLogger(__name__)

# =============================================================================
# REGEX PATTERNS
# =============================================================================

USER_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")
KEY_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
SCOPE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

def validate_user_id(
    user_id: Any,
    field_name: str = "user_id",
    required: bool = True
) -> Optional[str]:
    """
    Validate user ID format with security considerations.
    
    Args:
        user_id: User ID to validate
        field_name: Field name for error messages
        required: Whether the field is required
        
    Returns:
        Validated user ID string or None
        
    Raises:
        ValidationError: If validation fails
    """
    if user_id is None or (isinstance(user_id, str) and not user_id.strip()):
        if required:
            raise ValidationError(f"{field_name} is required", field=field_name)
        return None
    
    if not isinstance(user_id, str):
        raise ValidationError(f"{field_name} must be a string", field=field_name)
    
    user_id = user_id.strip()
    
    if len(user_id) > 128:
        raise ValidationError(
            f"{field_name} exceeds maximum length",
            field=field_name
        )
    
    if not USER_ID_PATTERN.match(user_id):
        raise ValidationError(
            f"{field_name} contains invalid characters",
            field=field_name
        )
    
    return user_id


def validate_scope(
    scope: Any,
    field_name: str = "scope",
    required: bool = True
) -> Optional[str]:
    """
    Validate consent scope.
    
    Args:
        scope: Scope to validate
        field_name: Field name for error messages
        required: Whether the field is required
        
    Returns:
        Validated scope string or None
        
    Raises:
        ValidationError: If validation fails
        InvalidScopeError: If scope is not recognized
    """
    if scope is None or (isinstance(scope, str) and not scope.strip()):
        if required:
            raise ValidationError(f"{field_name} is required", field=field_name)
        return None
    
    if not isinstance(scope, str):
        raise ValidationError(f"{field_name} must be a string", field=field_name)
    
    scope = scope.strip().lower()
    
    if scope not in ConsentScopes.ALL:
        raise InvalidScopeError(scope, list(ConsentScopes.ALL))
    
    return scope


def validate_scopes(
    scopes: Any,
    field_name: str = "scopes",
    required: bool = True
) -> List[str]:
    """
    Validate a list of consent scopes.
    
    Args:
        scopes: List of scopes to validate
        field_name: Field name for error messages
        required: Whether the field is required
        
    Returns:
        List of validated scope strings
        
    Raises:
        ValidationError: If validation fails
        InvalidScopeError: If any scope is not recognized
    """
    if scopes is None:
        if required:
            raise ValidationError(f"{field_name} is required", field=field_name)
        return []
    
    if not isinstance(scopes, list):
        raise ValidationError(f"{field_name} must be a list", field=field_name)
    
    validated_scopes = []
    for scope in scopes:
        validated = validate_scope(scope, required=True)
        if validated:
            validated_scopes.append(validated)
    
    return validated_scopes


def validate_consent_status(
    status: Any,
    field_name: str = "status",
    required: bool = True
) -> Optional[str]:
    """
    Validate consent status value.
    
    Args:
        status: Status to validate
        field_name: Field name for error messages
        required: Whether the field is required
        
    Returns:
        Validated status string or None
        
    Raises:
        ValidationError: If validation fails
    """
    if status is None or (isinstance(status, str) and not status.strip()):
        if required:
            raise ValidationError(f"{field_name} is required", field=field_name)
        return None
    
    if not isinstance(status, str):
        raise ValidationError(f"{field_name} must be a string", field=field_name)
    
    status = status.strip().lower()
    
    valid_statuses = (
        ConsentStatus.GRANTED,
        ConsentStatus.REVOKED,
        ConsentStatus.EXPIRED,
        ConsentStatus.PENDING
    )
    
    if status not in valid_statuses:
        raise ValidationError(
            f"Invalid {field_name}: '{status}'",
            field=field_name,
            details={"valid_statuses": list(valid_statuses)}
        )
    
    return status


def validate_privacy_level(
    level: Any,
    field_name: str = "privacy_level",
    required: bool = False
) -> Optional[str]:
    """
    Validate privacy level.
    
    Args:
        level: Privacy level to validate
        field_name: Field name for error messages
        required: Whether the field is required
        
    Returns:
        Validated privacy level string or None
        
    Raises:
        ValidationError: If validation fails
    """
    if level is None or (isinstance(level, str) and not level.strip()):
        if required:
            raise ValidationError(f"{field_name} is required", field=field_name)
        return None
    
    if not isinstance(level, str):
        raise ValidationError(f"{field_name} must be a string", field=field_name)
    
    level = level.strip().lower()
    
    if level not in PrivacyLevels.ALL:
        raise ValidationError(
            f"Invalid {field_name}: '{level}'",
            field=field_name,
            details={"valid_levels": list(PrivacyLevels.ALL)}
        )
    
    return level


def validate_key_id(
    key_id: Any,
    field_name: str = "key_id",
    required: bool = True
) -> Optional[str]:
    """
    Validate encryption key ID format.
    
    Args:
        key_id: Key ID to validate
        field_name: Field name for error messages
        required: Whether the field is required
        
    Returns:
        Validated key ID string or None
        
    Raises:
        ValidationError: If validation fails
    """
    if key_id is None or (isinstance(key_id, str) and not key_id.strip()):
        if required:
            raise ValidationError(f"{field_name} is required", field=field_name)
        return None
    
    if not isinstance(key_id, str):
        raise ValidationError(f"{field_name} must be a string", field=field_name)
    
    key_id = key_id.strip()
    
    if not KEY_ID_PATTERN.match(key_id):
        raise ValidationError(
            f"{field_name} has invalid format",
            field=field_name
        )
    
    return key_id


def validate_encryption_data(
    data: Any,
    field_name: str = "data",
    max_size_bytes: int = 10 * 1024 * 1024  # 10 MB default
) -> bytes:
    """
    Validate data for encryption.
    
    Args:
        data: Data to validate (string or bytes)
        field_name: Field name for error messages
        max_size_bytes: Maximum allowed data size
        
    Returns:
        Validated data as bytes
        
    Raises:
        ValidationError: If validation fails
    """
    if data is None:
        raise ValidationError(f"{field_name} is required", field=field_name)
    
    # Convert to bytes if string
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, bytes):
        raise ValidationError(
            f"{field_name} must be a string or bytes",
            field=field_name
        )
    
    if len(data) > max_size_bytes:
        raise ValidationError(
            f"{field_name} exceeds maximum size of {max_size_bytes} bytes",
            field=field_name,
            details={"size": len(data), "max_size": max_size_bytes}
        )
    
    return data


def validate_expiry_days(
    days: Any,
    field_name: str = "expiry_days",
    required: bool = False,
    min_days: int = 1,
    max_days: int = 3650
) -> Optional[int]:
    """
    Validate consent expiry days.
    
    Args:
        days: Number of days to validate
        field_name: Field name for error messages
        required: Whether the field is required
        min_days: Minimum allowed days
        max_days: Maximum allowed days
        
    Returns:
        Validated days integer or None
        
    Raises:
        ValidationError: If validation fails
    """
    if days is None:
        if required:
            raise ValidationError(f"{field_name} is required", field=field_name)
        return None
    
    try:
        days_int = int(days)
    except (TypeError, ValueError):
        raise ValidationError(f"{field_name} must be an integer", field=field_name)
    
    if days_int < min_days:
        raise ValidationError(
            f"{field_name} must be at least {min_days}",
            field=field_name
        )
    
    if days_int > max_days:
        raise ValidationError(
            f"{field_name} cannot exceed {max_days}",
            field=field_name
        )
    
    return days_int


def sanitize_audit_message(message: str, max_length: int = 1000) -> str:
    """
    Sanitize a message for audit logging.
    
    Args:
        message: Message to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized message safe for logging
    """
    if not message:
        return ""
    
    # Truncate if too long
    if len(message) > max_length:
        message = message[:max_length] + "...[truncated]"
    
    # Remove potential log injection characters
    message = message.replace("\n", " ").replace("\r", " ")
    
    # Remove potential control characters
    message = ''.join(c for c in message if c.isprintable() or c == ' ')
    
    return message
