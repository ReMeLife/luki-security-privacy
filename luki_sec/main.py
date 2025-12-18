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
from .crypto.quantum_readiness import (
    get_quantum_status,
    get_quantum_threat_brief,
    get_quantum_readiness_checker,
)
from .crypto.quantum_safe import (
    get_kyber,
    get_hybrid_kem,
    check_quantum_backend,
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
    # Get quantum backend status
    quantum_backends = check_quantum_backend()
    kyber = get_kyber()
    kyber_status = kyber.get_status()
    
    status = {
        "status": "healthy",
        "service": "luki-security-privacy",
        "version": "0.1.0",
        "environment": "production",
        "components": {
            "consent_manager": consent_manager is not None,
            "privacy_controls": privacy_controls is not None,
            "encryption_service": encryption_service is not None,
            "quantum_safe": True,
        },
        "quantum_readiness": {
            "status": "groundwork",
            "kyber_backend": kyber_status.get("backend", "unknown"),
            "production_ready": kyber_status.get("production_ready", False),
            "hybrid_available": True,
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
    if privacy_controls is not None:
        try:
            privacy_settings = await privacy_controls.get_settings(request.user_id)
            analytics_scopes = {
                ConsentScope.ANALYTICS,
                ConsentScope.DIFFERENTIAL_PRIVACY,
            }
            personalization_scopes = {ConsentScope.PERSONALIZATION}
            research_scopes = {
                ConsentScope.RESEARCH,
                ConsentScope.MODEL_TRAINING,
                ConsentScope.FEDERATED_LEARNING,
            }

            blocked_scopes: List[str] = []

            if not privacy_settings.get("allow_analytics", True):
                blocked_scopes.extend(
                    s.value for s in scopes if s in analytics_scopes
                )
            if not privacy_settings.get("allow_personalization", True):
                blocked_scopes.extend(
                    s.value for s in scopes if s in personalization_scopes
                )
            if not privacy_settings.get("allow_research", False):
                blocked_scopes.extend(
                    s.value for s in scopes if s in research_scopes
                )

            if blocked_scopes:
                blocked_scopes = sorted(set(blocked_scopes))
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "privacy_flags_denied",
                        "message": "Requested scopes are disabled by user privacy settings.",
                        "scopes_checked": [s.value for s in scopes],
                        "scopes_blocked": blocked_scopes,
                    },
                )
        except HTTPException:
            raise
        except Exception as exc:
            logger.error(
                "Privacy settings check failed",
                user_id=request.user_id,
                requester_role=request.requester_role,
                error=str(exc),
            )

    engine = get_consent_engine()

    try:
        processing_scopes = {
            ConsentScope.ANALYTICS,
            ConsentScope.PERSONALIZATION,
            ConsentScope.DIFFERENTIAL_PRIVACY,
        }
        scope_set = set(scopes)
        has_only_processing = scope_set and scope_set.issubset(processing_scopes)

        if has_only_processing:
            try:
                consent_bundle = engine.get_user_consents(request.user_id)
            except Exception as exc:
                logger.error(
                    "Consent bundle lookup failed during processing default-allow check",
                    user_id=request.user_id,
                    requester_role=request.requester_role,
                    error=str(exc),
                )
                consent_bundle = None

            missing_bundle = consent_bundle is None
            missing_all_processing_consents = False
            if consent_bundle is not None:
                try:
                    missing_all_processing_consents = True
                    for scope in scope_set:
                        consent = consent_bundle.get_consent(scope)
                        if consent is not None:
                            missing_all_processing_consents = False
                            break
                except Exception as exc:
                    logger.error(
                        "Failed to inspect processing consent records; falling back to strict enforcement",
                        user_id=request.user_id,
                        requester_role=request.requester_role,
                        error=str(exc),
                    )
                    missing_all_processing_consents = False

            if missing_bundle or missing_all_processing_consents:
                logger.info(
                    "Default-allow processing scopes with no explicit consent record",
                    user_id=request.user_id,
                    requester_role=request.requester_role,
                    scopes=[s.value for s in scopes],
                )
                return {
                    "allowed": True,
                    "scopes_checked": [s.value for s in scopes],
                    "reason": "default_allow_processing_no_consent_record",
                }
    except Exception as exc:
        logger.error(
            "Processing default-allow check failed; falling back to strict enforcement",
            user_id=request.user_id,
            requester_role=request.requester_role,
            error=str(exc),
        )

    # Default-allow semantics for core ELR memories:
    # If only the elr_memories scope is requested and the user has no
    # explicit consent record for that scope (or no consent bundle at all),
    # treat this as allowed-by-default so basic ELR storage/retrieval works
    # for new users. Explicit revocations/expiry still flow through normal
    # consent enforcement.
    try:
        elr_only = {
            ConsentScope.ELR_MEMORIES,
        }
        scope_set = set(scopes)
        has_only_elr = scope_set and scope_set.issubset(elr_only)

        if has_only_elr:
            try:
                consent_bundle = engine.get_user_consents(request.user_id)
            except Exception as exc:
                logger.error(
                    "Consent bundle lookup failed during ELR default-allow check",
                    user_id=request.user_id,
                    requester_role=request.requester_role,
                    error=str(exc),
                )
                consent_bundle = None

            missing_bundle = consent_bundle is None
            missing_elr_consent = False
            if consent_bundle is not None:
                try:
                    elr_consent = consent_bundle.get_consent(ConsentScope.ELR_MEMORIES)
                    missing_elr_consent = elr_consent is None
                except Exception as exc:
                    logger.error(
                        "Failed to inspect ELR consent record; falling back to default allow",
                        user_id=request.user_id,
                        requester_role=request.requester_role,
                        error=str(exc),
                    )
                    missing_elr_consent = True

            if missing_bundle or missing_elr_consent:
                logger.info(
                    "Default-allow elr_memories with no explicit consent record",
                    user_id=request.user_id,
                    requester_role=request.requester_role,
                )
                return {
                    "allowed": True,
                    "scopes_checked": [s.value for s in scopes],
                    "reason": "default_allow_elr_no_consent_record",
                }
    except Exception as exc:
        # On any unexpected failure in the default-allow branch,
        # fall back to normal consent enforcement.
        logger.error(
            "ELR default-allow check failed; falling back to strict enforcement",
            user_id=request.user_id,
            requester_role=request.requester_role,
            error=str(exc),
        )

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

# =============================================================================
# QUANTUM-SAFE CRYPTOGRAPHY ENDPOINTS
# =============================================================================

@app.get("/quantum/status")
async def quantum_status():
    """
    Get comprehensive quantum readiness status.
    
    Returns detailed information about:
    - Current quantum threat assessment
    - Algorithm readiness (symmetric, KEM, signatures)
    - Post-quantum library availability
    - Migration status and recommendations
    
    This endpoint provides transparency about LUKi's quantum security posture.
    """
    from datetime import datetime, UTC
    
    status = get_quantum_status()
    
    return {
        "service": "luki-security-privacy",
        "quantum_readiness": status,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/quantum/threat")
async def quantum_threat():
    """
    Get a brief quantum threat assessment.
    
    Returns a concise summary of the current quantum computing threat
    to cryptographic systems and LUKi's preparedness.
    """
    return get_quantum_threat_brief()


@app.get("/quantum/algorithms")
async def quantum_algorithms():
    """
    Get status of quantum-safe algorithms.
    
    Returns information about implemented post-quantum algorithms
    and their current operational status.
    """
    kyber = get_kyber()
    hybrid = get_hybrid_kem()
    backends = check_quantum_backend()
    
    return {
        "backends_available": backends,
        "kyber": kyber.get_status(),
        "hybrid_kem": hybrid.get_status(),
        "supported_security_levels": [
            {
                "level": "kyber512",
                "nist_level": 1,
                "equivalent_classical": "AES-128",
                "recommended": False,
            },
            {
                "level": "kyber768",
                "nist_level": 3,
                "equivalent_classical": "AES-192",
                "recommended": False,
            },
            {
                "level": "kyber1024",
                "nist_level": 5,
                "equivalent_classical": "AES-256",
                "recommended": True,
            },
        ],
        "nist_standards": {
            "kyber": "FIPS 203 (ML-KEM)",
            "dilithium": "FIPS 204 (ML-DSA) - Not yet implemented",
        }
    }


@app.post("/quantum/demo/encapsulate")
async def quantum_demo_encapsulate():
    """
    Demo endpoint: Generate Kyber keypair and perform encapsulation.
    
    This demonstrates the quantum-safe key encapsulation in action.
    For demonstration purposes only - keys are ephemeral and not stored.
    
    Use this to verify that quantum-safe cryptography is operational.
    """
    kyber = get_kyber()
    
    # Generate keypair
    public_key, secret_key = kyber.generate_keypair()
    
    # Perform encapsulation (what a sender would do)
    ciphertext, shared_secret = kyber.encapsulate(public_key)
    
    # Verify decapsulation works (what recipient would do)
    recovered_secret = kyber.decapsulate(secret_key, ciphertext)
    
    # Verify round-trip works
    demo_successful = shared_secret == recovered_secret
    
    return {
        "algorithm": "CRYSTALS-Kyber-1024",
        "nist_standard": "FIPS 203 (ML-KEM)",
        "demo_successful": demo_successful,
        "key_sizes": {
            "public_key_bytes": len(public_key),
            "secret_key_bytes": len(secret_key),
            "ciphertext_bytes": len(ciphertext),
            "shared_secret_bytes": len(shared_secret),
        },
        "backend": kyber.get_status()["backend"],
        "production_ready": kyber.get_status()["production_ready"],
        "note": "This is a demonstration - keys are ephemeral and not stored"
    }


@app.post("/quantum/demo/hybrid")
async def quantum_demo_hybrid():
    """
    Demo endpoint: Perform hybrid (classical + quantum) key encapsulation.
    
    Demonstrates the hybrid approach combining:
    - X25519 (classical elliptic curve Diffie-Hellman)
    - CRYSTALS-Kyber (post-quantum lattice-based KEM)
    
    This provides security even if one algorithm is broken.
    """
    hybrid = get_hybrid_kem()
    
    # Generate hybrid keypair (both classical and quantum)
    keypair = hybrid.generate_keypair()
    
    # Perform hybrid encapsulation
    ciphertext_bundle, shared_secret = hybrid.encapsulate(
        keypair["classical_public"],
        keypair["quantum_public"]
    )
    
    # Verify decapsulation recovers the same secret
    recovered_secret = hybrid.decapsulate(
        keypair["classical_private"],
        keypair["quantum_private"],
        ciphertext_bundle
    )
    
    demo_successful = shared_secret == recovered_secret
    
    return {
        "type": "hybrid",
        "algorithms": {
            "classical": "X25519 (Curve25519 ECDH)",
            "quantum": "CRYSTALS-Kyber-1024",
        },
        "security_model": "Safe if EITHER X25519 OR Kyber remains secure",
        "demo_successful": demo_successful,
        "key_sizes": {
            "classical_public_key_bytes": len(keypair["classical_public"]),
            "quantum_public_key_bytes": len(keypair["quantum_public"]),
            "shared_secret_bytes": len(shared_secret),
        },
        "status": hybrid.get_status(),
        "note": "Hybrid mode provides defense-in-depth against both classical and quantum attacks"
    }


# =============================================================================
# ROOT ENDPOINT
# =============================================================================

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "LUKi Security & Privacy Module",
        "version": "0.1.0",
        "status": "operational",
        "features": {
            "consent_management": True,
            "privacy_controls": True,
            "encryption": True,
            "quantum_ready": True,
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
