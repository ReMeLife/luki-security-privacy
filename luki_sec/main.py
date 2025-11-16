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

from pydantic import BaseModel, Field

from .config import SecurityConfig
from .consent.models import ConsentScope
from .consent.engine import (
    get_consent_engine,
    ConsentDeniedError,
    ConsentExpiredError,
)

# Try to import modules, fall back to mock classes if not available
try:
    from .consent.manager import ConsentManager
except ImportError:
    class ConsentManager:
        async def update_consent(self, user_id: str, consent_data: dict):
            return {"status": "mock", "user_id": user_id, "data": consent_data}
        
        async def get_consent(self, user_id: str):
            return {"user_id": user_id, "consent": {"analytics": True, "marketing": False}}

try:
    from .privacy.controls import PrivacyControls
except ImportError:
    class PrivacyControls:
        async def update_settings(self, user_id: str, settings: dict):
            return {"status": "mock", "user_id": user_id, "settings": settings}
        
        async def get_settings(self, user_id: str):
            return {"user_id": user_id, "privacy_level": "medium", "data_retention": 30}

try:
    from .crypto.encryption import EncryptionService
except ImportError:
    class EncryptionService:
        async def encrypt(self, data: dict):
            return "mock_encrypted_" + str(hash(str(data)))
        
        async def decrypt(self, encrypted_data: str):
            return {"decrypted": "mock_data", "original": encrypted_data}

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


class PolicyEnforcementRequest(BaseModel):
    user_id: str
    requester_role: str
    requested_scopes: List[str] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global consent_manager, privacy_controls, encryption_service
    
    logger.info("Starting LUKi Security & Privacy Module", version="0.1.0")
    
    try:
        # Initialize services
        consent_manager = ConsentManager()
        privacy_controls = PrivacyControls()
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
