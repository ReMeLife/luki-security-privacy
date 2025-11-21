"""
LUKi Security & Privacy Module - FastAPI Application
Provides consent management, privacy controls, and security features
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from typing import List, Dict, Any
import logging
import structlog
import json
import base64

from pydantic import BaseModel, Field

from .config import SecurityConfig
from .consent.models import ConsentScope
from .consent.engine import (
    get_consent_engine,
    ConsentDeniedError,
    ConsentExpiredError,
)
from .consent.manager import ConsentManager
from .privacy.controls import PrivacyControls
from .crypto.encrypt import (
    encrypt_bytes,
    decrypt_bytes,
    generate_key,
    EncryptionError,
    DecryptionError,
)

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Global settings
settings = SecurityConfig()

# Initialize services
consent_manager = None
privacy_controls = None
encryption_service = None


class EncryptionService:
    """AES-GCM based encryption service using a process-local key."""

    def __init__(self) -> None:
        self._key = generate_key(settings.encryption_key_size)

    async def encrypt(self, data: Dict[str, Any]) -> str:
        """Encrypt a JSON-serializable dict and return base64 string."""
        try:
            plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
            encrypted = encrypt_bytes(self._key, plaintext)
            return base64.b64encode(encrypted).decode("ascii")
        except EncryptionError as exc:
            logger.error("Encryption service failed", error=str(exc))
            raise

    async def decrypt(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt a base64-encoded string back into a dict."""
        try:
            raw = base64.b64decode(encrypted_data.encode("ascii"))
            plaintext = decrypt_bytes(self._key, raw)
            return json.loads(plaintext.decode("utf-8"))
        except (DecryptionError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.error("Decryption service failed", error=str(exc))
            raise


class PolicyEnforcementRequest(BaseModel):
    user_id: str
    requester_role: str
    requested_scopes: List[str] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)


class SecurityConfigOut(BaseModel):
    """Subset of security configuration exposed via API for admin/ops UI."""

    crypto_backend: str
    dp_mechanism: str
    fl_backend: str
    consent_expiry_days: int
    audit_retention_days: int
    rbac_enabled: bool
    abac_enabled: bool
    anomaly_detection_enabled: bool
    anomaly_threshold: float
    anomaly_retrain_days: int
    debug_mode: bool
    log_level: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global consent_manager, privacy_controls, encryption_service
    
    logger.info("Starting LUKi Security & Privacy Module", version="0.1.0")
    
    try:
        # Initialize services only if not already provided (for testing/injection)
        if consent_manager is None:
            consent_manager = ConsentManager()
        if privacy_controls is None:
            privacy_controls = PrivacyControls()
        if encryption_service is None:
            encryption_service = EncryptionService()
        
        logger.info("✅ Security services initialized successfully")
        
    except Exception as e:
        logger.error("❌ Failed to initialize security services", error=str(e))
        # Continue startup even if some services fail
        
    yield
    
    logger.info("Shutting down LUKi Security & Privacy Module")

# Create FastAPI app
app = FastAPI(
    title="LUKi Security & Privacy Module",
    description="Consent management, privacy controls, and security features for LUKi",
    version="0.1.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    status = {
        "status": "healthy",
        "service": "luki-security-privacy",
        "version": "0.1.0",
        "environment": "production",
        "components": {
            "consent_manager": consent_manager is not None,
            "privacy_controls": privacy_controls is not None,
            "encryption_service": encryption_service is not None
        }
    }
    
    return status


@app.get("/security/config", response_model=SecurityConfigOut)
async def get_security_config():
    """Return a sanitized view of security configuration for admin/ops tools.

    This is intended for internal dashboards and configuration UIs; it should
    not be exposed directly to end users.
    """

    return SecurityConfigOut(
        crypto_backend=str(settings.crypto_backend),
        dp_mechanism=str(settings.dp_mechanism),
        fl_backend=str(settings.fl_backend),
        consent_expiry_days=settings.consent_expiry_days,
        audit_retention_days=settings.audit_retention_days,
        rbac_enabled=settings.rbac_enabled,
        abac_enabled=settings.abac_enabled,
        anomaly_detection_enabled=settings.anomaly_detection_enabled,
        anomaly_threshold=settings.anomaly_threshold,
        anomaly_retrain_days=settings.anomaly_retrain_days,
        debug_mode=settings.debug_mode,
        log_level=settings.log_level,
    )

@app.post("/consent/{user_id}")
async def update_consent(user_id: str, consent_data: dict):
    """Update user consent preferences"""
    if not consent_manager:
        raise HTTPException(status_code=503, detail="Consent manager not available")
    
    try:
        result = await consent_manager.update_consent(user_id, consent_data)
        logger.info("Consent updated", user_id=user_id)
        return {"status": "success", "consent": result}
    except Exception as e:
        logger.error("Failed to update consent", user_id=user_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/consent/{user_id}")
async def get_consent(user_id: str):
    """Get user consent preferences"""
    if not consent_manager:
        raise HTTPException(status_code=503, detail="Consent manager not available")
    
    try:
        consent = await consent_manager.get_consent(user_id)
        return {"user_id": user_id, "consent": consent}
    except Exception as e:
        logger.error("Failed to get consent", user_id=user_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/privacy/{user_id}/settings")
async def update_privacy_settings(user_id: str, privacy_settings: dict):
    """Update user privacy settings"""
    if not privacy_controls:
        raise HTTPException(status_code=503, detail="Privacy controls not available")
    
    try:
        result = await privacy_controls.update_settings(user_id, privacy_settings)
        logger.info("Privacy settings updated", user_id=user_id)
        return {"status": "success", "settings": result}
    except Exception as e:
        logger.error("Failed to update privacy settings", user_id=user_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/privacy/{user_id}/settings")
async def get_privacy_settings(user_id: str):
    """Get user privacy settings"""
    if not privacy_controls:
        raise HTTPException(status_code=503, detail="Privacy controls not available")
    
    try:
        settings = await privacy_controls.get_settings(user_id)
        return {"user_id": user_id, "settings": settings}
    except Exception as e:
        logger.error("Failed to get privacy settings", user_id=user_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/encrypt")
async def encrypt_data(data: dict):
    """Encrypt sensitive data"""
    if not encryption_service:
        raise HTTPException(status_code=503, detail="Encryption service not available")
    
    try:
        encrypted = await encryption_service.encrypt(data)
        return {"encrypted_data": encrypted}
    except Exception as e:
        logger.error("Failed to encrypt data", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/decrypt")
async def decrypt_data(encrypted_data: str):
    """Decrypt sensitive data"""
    if not encryption_service:
        raise HTTPException(status_code=503, detail="Encryption service not available")
    
    try:
        decrypted = await encryption_service.decrypt(encrypted_data)
        return {"decrypted_data": decrypted}
    except Exception as e:
        logger.error("Failed to decrypt data", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/policy/enforce")
async def enforce_policy(request: PolicyEnforcementRequest):
    if not request.requested_scopes:
        return {
            "allowed": True,
            "scopes_checked": [],
            "reason": "no_scopes_requested",
        }

    scopes: List[ConsentScope] = []
    invalid_scopes: List[str] = []

    for raw in request.requested_scopes:
        try:
            scopes.append(ConsentScope(raw))
        except ValueError:
            invalid_scopes.append(raw)

    if invalid_scopes:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_scopes", "scopes": invalid_scopes},
        )

    engine = get_consent_engine()

    try:
        engine.enforce_scope(request.user_id, request.requester_role, scopes)
        return {
            "allowed": True,
            "scopes_checked": [s.value for s in scopes],
            "reason": "consent_valid",
        }
    except ConsentExpiredError as exc:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "consent_expired",
                "message": str(exc),
                "scopes_checked": [s.value for s in scopes],
            },
        )
    except ConsentDeniedError as exc:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "consent_denied",
                "message": str(exc),
                "scopes_checked": [s.value for s in scopes],
            },
        )
    except Exception as exc:
        logger.error(
            "Policy enforcement failed",
            user_id=request.user_id,
            requester_role=request.requester_role,
            error=str(exc),
        )
        raise HTTPException(status_code=500, detail="Failed to enforce policy")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "LUKi Security & Privacy Module",
        "version": "0.1.0",
        "status": "operational"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
