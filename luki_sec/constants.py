"""
Constants for LUKi Security & Privacy Module

Centralized configuration for security parameters, consent scopes,
policy defaults, and cryptographic settings.
"""

from typing import Final, Tuple

# =============================================================================
# SERVICE IDENTIFICATION
# =============================================================================

SERVICE_NAME: Final[str] = "luki-security-privacy"
SERVICE_VERSION: Final[str] = "1.0.0"

# =============================================================================
# CONSENT SCOPES
# =============================================================================

class ConsentScopes:
    """Consent scope identifiers for data processing"""
    # Core data scopes
    BASIC_PROFILE: Final[str] = "basic_profile"
    MEMORY_STORAGE: Final[str] = "memory_storage"
    MEMORY_RETRIEVAL: Final[str] = "memory_retrieval"
    CONVERSATION_HISTORY: Final[str] = "conversation_history"
    
    # Analytics scopes
    ANALYTICS: Final[str] = "analytics"
    PERSONALIZATION: Final[str] = "personalization"
    BEHAVIOR_TRACKING: Final[str] = "behavior_tracking"
    
    # Feature scopes
    COGNITIVE_ACTIVITIES: Final[str] = "cognitive_activities"
    LIFE_STORY: Final[str] = "life_story"
    IMAGE_GENERATION: Final[str] = "image_generation"
    REPORTING: Final[str] = "reporting"
    
    # Sharing scopes
    CARER_SHARING: Final[str] = "carer_sharing"
    FAMILY_SHARING: Final[str] = "family_sharing"
    RESEARCH_PARTICIPATION: Final[str] = "research_participation"
    
    ALL: Final[Tuple[str, ...]] = (
        BASIC_PROFILE, MEMORY_STORAGE, MEMORY_RETRIEVAL, CONVERSATION_HISTORY,
        ANALYTICS, PERSONALIZATION, BEHAVIOR_TRACKING,
        COGNITIVE_ACTIVITIES, LIFE_STORY, IMAGE_GENERATION, REPORTING,
        CARER_SHARING, FAMILY_SHARING, RESEARCH_PARTICIPATION
    )
    
    # Default enabled scopes (opt-out model)
    DEFAULT_ENABLED: Final[Tuple[str, ...]] = (
        BASIC_PROFILE, MEMORY_STORAGE, MEMORY_RETRIEVAL, CONVERSATION_HISTORY,
        ANALYTICS, PERSONALIZATION, COGNITIVE_ACTIVITIES, LIFE_STORY,
        IMAGE_GENERATION, REPORTING
    )


# =============================================================================
# CONSENT STATUS
# =============================================================================

class ConsentStatus:
    """Consent record status values"""
    GRANTED: Final[str] = "granted"
    REVOKED: Final[str] = "revoked"
    EXPIRED: Final[str] = "expired"
    PENDING: Final[str] = "pending"


# =============================================================================
# ENCRYPTION CONFIGURATION
# =============================================================================

class EncryptionDefaults:
    """Default encryption parameters"""
    KEY_SIZE_BITS: Final[int] = 256
    IV_SIZE_BYTES: Final[int] = 16
    SALT_SIZE_BYTES: Final[int] = 32
    ITERATIONS: Final[int] = 100000
    DEFAULT_ALGORITHM: Final[str] = "AES-256-GCM"
    
    # Key derivation
    KDF_ALGORITHM: Final[str] = "PBKDF2"
    KDF_HASH: Final[str] = "SHA256"


# =============================================================================
# POLICY DEFAULTS
# =============================================================================

class PolicyDefaults:
    """Default policy configuration"""
    CONSENT_EXPIRY_DAYS: Final[int] = 365
    SESSION_TIMEOUT_HOURS: Final[int] = 24
    MAX_FAILED_ATTEMPTS: Final[int] = 5
    LOCKOUT_DURATION_MINUTES: Final[int] = 30
    
    # Data retention
    RETENTION_DAYS_DEFAULT: Final[int] = 730  # 2 years
    RETENTION_DAYS_MINIMUM: Final[int] = 30
    RETENTION_DAYS_MAXIMUM: Final[int] = 3650  # 10 years


# =============================================================================
# AUDIT EVENT TYPES
# =============================================================================

class AuditEventTypes:
    """Audit event type identifiers"""
    # Authentication events
    LOGIN_SUCCESS: Final[str] = "login_success"
    LOGIN_FAILURE: Final[str] = "login_failure"
    LOGOUT: Final[str] = "logout"
    SESSION_EXPIRED: Final[str] = "session_expired"
    
    # Consent events
    CONSENT_GRANTED: Final[str] = "consent_granted"
    CONSENT_REVOKED: Final[str] = "consent_revoked"
    CONSENT_EXPIRED: Final[str] = "consent_expired"
    CONSENT_CHECKED: Final[str] = "consent_checked"
    
    # Data access events
    DATA_ACCESS: Final[str] = "data_access"
    DATA_EXPORT: Final[str] = "data_export"
    DATA_DELETION: Final[str] = "data_deletion"
    DATA_MODIFICATION: Final[str] = "data_modification"
    
    # Security events
    ENCRYPTION_PERFORMED: Final[str] = "encryption_performed"
    DECRYPTION_PERFORMED: Final[str] = "decryption_performed"
    KEY_ROTATION: Final[str] = "key_rotation"
    POLICY_VIOLATION: Final[str] = "policy_violation"
    
    # Privacy events
    PRIVACY_SETTINGS_CHANGED: Final[str] = "privacy_settings_changed"
    ANONYMIZATION_PERFORMED: Final[str] = "anonymization_performed"


# =============================================================================
# ERROR CODES
# =============================================================================

class ErrorCodes:
    """Standardized error codes for security module"""
    UNKNOWN_ERROR: Final[str] = "UNKNOWN_ERROR"
    VALIDATION_ERROR: Final[str] = "VALIDATION_ERROR"
    
    # Consent errors
    CONSENT_REQUIRED: Final[str] = "CONSENT_REQUIRED"
    CONSENT_DENIED: Final[str] = "CONSENT_DENIED"
    CONSENT_EXPIRED: Final[str] = "CONSENT_EXPIRED"
    INVALID_SCOPE: Final[str] = "INVALID_SCOPE"
    
    # Encryption errors
    ENCRYPTION_ERROR: Final[str] = "ENCRYPTION_ERROR"
    DECRYPTION_ERROR: Final[str] = "DECRYPTION_ERROR"
    KEY_NOT_FOUND: Final[str] = "KEY_NOT_FOUND"
    INVALID_KEY: Final[str] = "INVALID_KEY"
    
    # Policy errors
    POLICY_VIOLATION: Final[str] = "POLICY_VIOLATION"
    ACCESS_DENIED: Final[str] = "ACCESS_DENIED"
    RATE_LIMITED: Final[str] = "RATE_LIMITED"
    
    # Audit errors
    AUDIT_ERROR: Final[str] = "AUDIT_ERROR"


# =============================================================================
# PRIVACY LEVELS
# =============================================================================

class PrivacyLevels:
    """Privacy level identifiers"""
    PUBLIC: Final[str] = "public"
    INTERNAL: Final[str] = "internal"
    CONFIDENTIAL: Final[str] = "confidential"
    RESTRICTED: Final[str] = "restricted"
    
    ALL: Final[Tuple[str, ...]] = (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED)


# =============================================================================
# DIFFERENTIAL PRIVACY
# =============================================================================

class DifferentialPrivacyDefaults:
    """Default differential privacy parameters"""
    EPSILON: Final[float] = 1.0
    DELTA: Final[float] = 1e-5
    SENSITIVITY: Final[float] = 1.0
    NOISE_MECHANISM: Final[str] = "laplace"


# =============================================================================
# QUANTUM SAFETY
# =============================================================================

class QuantumSafetyDefaults:
    """Quantum-safe cryptography settings"""
    ENABLED: Final[bool] = False
    ALGORITHM: Final[str] = "CRYSTALS-Kyber"
    KEY_SIZE: Final[int] = 1024
