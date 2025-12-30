"""
Custom Exceptions for LUKi Security & Privacy Module

Provides a unified exception hierarchy for consent management,
encryption operations, policy enforcement, and audit logging.
"""

from typing import Optional, Dict, Any, List


class SecurityError(Exception):
    """
    Base exception for all security module errors.
    
    Attributes:
        message: Human-readable error message
        error_code: Machine-readable error code
        details: Additional context about the error
    """
    
    def __init__(
        self,
        message: str,
        error_code: str = "SECURITY_ERROR",
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses"""
        result: Dict[str, Any] = {
            "error": self.error_code,
            "message": self.message,
        }
        if self.details:
            result["details"] = self.details
        return result


# =============================================================================
# CONSENT ERRORS
# =============================================================================

class ConsentError(SecurityError):
    """Base exception for consent-related errors"""
    
    def __init__(
        self,
        message: str,
        error_code: str = "CONSENT_ERROR",
        user_id: Optional[str] = None,
        scope: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        details = details or {}
        if user_id:
            details["user_id"] = user_id
        if scope:
            details["scope"] = scope
        super().__init__(message, error_code, details)


class ConsentRequiredError(ConsentError):
    """Raised when consent is required but not granted"""
    
    def __init__(
        self,
        scope: str,
        user_id: Optional[str] = None,
        required_scopes: Optional[List[str]] = None
    ):
        details: Dict[str, Any] = {}
        if required_scopes:
            details["required_scopes"] = required_scopes
        super().__init__(
            message=f"Consent required for scope: {scope}",
            error_code="CONSENT_REQUIRED",
            user_id=user_id,
            scope=scope,
            details=details
        )


class ConsentDeniedError(ConsentError):
    """Raised when consent has been explicitly denied"""
    
    def __init__(
        self,
        scope: str,
        user_id: Optional[str] = None
    ):
        super().__init__(
            message=f"Consent denied for scope: {scope}",
            error_code="CONSENT_DENIED",
            user_id=user_id,
            scope=scope
        )


class ConsentExpiredError(ConsentError):
    """Raised when consent has expired"""
    
    def __init__(
        self,
        scope: str,
        user_id: Optional[str] = None,
        expired_at: Optional[str] = None
    ):
        details: Dict[str, Any] = {}
        if expired_at:
            details["expired_at"] = expired_at
        super().__init__(
            message=f"Consent expired for scope: {scope}",
            error_code="CONSENT_EXPIRED",
            user_id=user_id,
            scope=scope,
            details=details
        )


class InvalidScopeError(ConsentError):
    """Raised when an invalid scope is requested"""
    
    def __init__(
        self,
        scope: str,
        valid_scopes: Optional[List[str]] = None
    ):
        details: Dict[str, Any] = {"invalid_scope": scope}
        if valid_scopes:
            details["valid_scopes"] = valid_scopes
        super().__init__(
            message=f"Invalid consent scope: {scope}",
            error_code="INVALID_SCOPE",
            scope=scope,
            details=details
        )


# =============================================================================
# ENCRYPTION ERRORS
# =============================================================================

class EncryptionError(SecurityError):
    """Base exception for encryption-related errors"""
    
    def __init__(
        self,
        message: str,
        error_code: str = "ENCRYPTION_ERROR",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, error_code, details)


class EncryptionFailedError(EncryptionError):
    """Raised when encryption operation fails"""
    
    def __init__(
        self,
        message: str = "Encryption operation failed",
        reason: Optional[str] = None
    ):
        details: Dict[str, Any] = {}
        if reason:
            details["reason"] = reason
        super().__init__(message, "ENCRYPTION_FAILED", details)


class DecryptionFailedError(EncryptionError):
    """Raised when decryption operation fails"""
    
    def __init__(
        self,
        message: str = "Decryption operation failed",
        reason: Optional[str] = None
    ):
        details: Dict[str, Any] = {}
        if reason:
            details["reason"] = reason
        super().__init__(message, "DECRYPTION_FAILED", details)


class KeyNotFoundError(EncryptionError):
    """Raised when encryption key is not found"""
    
    def __init__(
        self,
        key_id: Optional[str] = None
    ):
        details: Dict[str, Any] = {}
        if key_id:
            details["key_id"] = key_id
        super().__init__(
            message="Encryption key not found",
            error_code="KEY_NOT_FOUND",
            details=details
        )


class InvalidKeyError(EncryptionError):
    """Raised when encryption key is invalid"""
    
    def __init__(
        self,
        message: str = "Invalid encryption key",
        reason: Optional[str] = None
    ):
        details: Dict[str, Any] = {}
        if reason:
            details["reason"] = reason
        super().__init__(message, "INVALID_KEY", details)


# =============================================================================
# POLICY ERRORS
# =============================================================================

class PolicyError(SecurityError):
    """Base exception for policy-related errors"""
    
    def __init__(
        self,
        message: str,
        error_code: str = "POLICY_ERROR",
        policy_name: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        details = details or {}
        if policy_name:
            details["policy"] = policy_name
        super().__init__(message, error_code, details)


class PolicyViolationError(PolicyError):
    """Raised when a policy is violated"""
    
    def __init__(
        self,
        policy_name: str,
        violation_reason: str
    ):
        super().__init__(
            message=f"Policy violation: {violation_reason}",
            error_code="POLICY_VIOLATION",
            policy_name=policy_name,
            details={"reason": violation_reason}
        )


class AccessDeniedError(PolicyError):
    """Raised when access is denied by policy"""
    
    def __init__(
        self,
        resource: str,
        reason: Optional[str] = None
    ):
        details: Dict[str, Any] = {"resource": resource}
        if reason:
            details["reason"] = reason
        super().__init__(
            message=f"Access denied to resource: {resource}",
            error_code="ACCESS_DENIED",
            details=details
        )


# =============================================================================
# AUDIT ERRORS
# =============================================================================

class AuditError(SecurityError):
    """Base exception for audit-related errors"""
    
    def __init__(
        self,
        message: str,
        error_code: str = "AUDIT_ERROR",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, error_code, details)


class AuditLogError(AuditError):
    """Raised when audit logging fails"""
    
    def __init__(
        self,
        message: str = "Failed to write audit log",
        event_type: Optional[str] = None
    ):
        details: Dict[str, Any] = {}
        if event_type:
            details["event_type"] = event_type
        super().__init__(message, "AUDIT_LOG_ERROR", details)


# =============================================================================
# VALIDATION ERRORS
# =============================================================================

class ValidationError(SecurityError):
    """Raised when input validation fails"""
    
    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        details = details or {}
        if field:
            details["field"] = field
        super().__init__(message, "VALIDATION_ERROR", details)
