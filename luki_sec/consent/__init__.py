"""
Consent management module for LUKi
GDPR/HIPAA compliant consent tracking and enforcement
"""

from .models import ConsentRecord, ConsentScope, ConsentStatus, ConsentBundle
from .engine import enforce_scope, check_consent, grant_consent, revoke_consent
from .storage import ConsentStorage

__all__ = [
    "ConsentRecord",
    "ConsentScope", 
    "ConsentStatus",
    "ConsentBundle",
    "enforce_scope",
    "check_consent",
    "grant_consent",
    "revoke_consent",
    "ConsentStorage",
]
