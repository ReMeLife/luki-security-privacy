"""
LUKi Security & Privacy Module
Security, consent, federated learning & privacy-preserving ML utilities for LUKi
"""

__version__ = "0.1.0"
__author__ = "ReMeLife / Singularities Ltd"

# Core exports
from .config import SecurityConfig, get_security_config

# Consent management
from .consent import (
    ConsentRecord, ConsentScope, ConsentStatus, ConsentBundle,
    enforce_scope, check_consent, grant_consent, revoke_consent
)

# Cryptography (JWT and some crypto helpers are optional for test environments)
try:
    from .crypto import (
        encrypt_bytes, decrypt_bytes, generate_key,
        create_jwt, verify_jwt, JWTError,
        KeyManager, rotate_keys,
        hash_password, verify_password, secure_hash,
    )
except ModuleNotFoundError:
    encrypt_bytes = None  # type: ignore[assignment]
    decrypt_bytes = None  # type: ignore[assignment]
    generate_key = None  # type: ignore[assignment]
    create_jwt = None  # type: ignore[assignment]
    verify_jwt = None  # type: ignore[assignment]
    JWTError = Exception  # type: ignore[assignment]
    KeyManager = None  # type: ignore[assignment]
    rotate_keys = None  # type: ignore[assignment]
    hash_password = None  # type: ignore[assignment]
    verify_password = None  # type: ignore[assignment]
    secure_hash = None  # type: ignore[assignment]

# Policy enforcement
from .policy import (
    Role, Permission, RBACManager, check_permission,
    ABACManager, PolicyRule, AttributeContext,
    AuditLogger, AuditEvent, log_access
)

# Privacy protection
from .privacy import (
    laplace_noise, gaussian_noise, DPMechanism,
    PIISanitizer, redact_pii, tokenize_pii,
    KAnonymizer, check_k_anonymity
)

# Utilities
from .utils import (
    generate_user_id, generate_session_id, generate_trace_id, validate_id
)

__all__ = [
    # Config
    "SecurityConfig",
    "get_security_config",
    
    # Consent
    "ConsentRecord",
    "ConsentScope", 
    "ConsentStatus",
    "ConsentBundle",
    "enforce_scope",
    "check_consent",
    "grant_consent",
    "revoke_consent",
    
    # Crypto
    "encrypt_bytes",
    "decrypt_bytes",
    "generate_key",
    "create_jwt",
    "verify_jwt",
    "JWTError",
    "KeyManager",
    "rotate_keys",
    "hash_password",
    "verify_password",
    "secure_hash",
    
    # Policy
    "Role",
    "Permission",
    "RBACManager",
    "check_permission",
    "ABACManager",
    "PolicyRule",
    "AttributeContext",
    "AuditLogger",
    "AuditEvent",
    "log_access",
    
    # Privacy
    "laplace_noise",
    "gaussian_noise",
    "DPMechanism",
    "PIISanitizer",
    "redact_pii",
    "tokenize_pii",
    "KAnonymizer",
    "check_k_anonymity",
    
    # Utils
    "generate_user_id",
    "generate_session_id",
    "generate_trace_id",
    "validate_id",
]
