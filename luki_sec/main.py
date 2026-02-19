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
from .api import insights
from .middleware import correlation_middleware, request_logging_middleware
from .operational_metrics import operational_metrics
from .policy.audit import get_audit_logger, AuditEventType
from .policy.decision_cache import get_decision_cache

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

# Register request middleware (reverse order: last registered = runs first).
app.middleware("http")(request_logging_middleware)
app.middleware("http")(correlation_middleware)

# Include API routers
app.include_router(insights.router)

@app.get("/health")
async def health_check(deep: bool = False):
    """Health check endpoint.

    With ``?deep=true``, performs functional verification of core
    components (encryption round-trip, consent engine availability)
    rather than just null-checks.
    """
    components = {
        "consent_manager": "ready" if consent_manager is not None else "unavailable",
        "privacy_controls": "ready" if privacy_controls is not None else "unavailable",
        "encryption_service": "ready" if encryption_service is not None else "unavailable",
    }

    if deep:
        # Verify encryption service can round-trip a test payload.
        if encryption_service is not None:
            try:
                test_data = {"_health": "check"}
                encrypted = await encryption_service.encrypt(test_data)
                decrypted = await encryption_service.decrypt(encrypted)
                components["encryption_service"] = (
                    "healthy" if decrypted == test_data else "degraded"
                )
            except Exception as exc:
                components["encryption_service"] = f"error: {type(exc).__name__}"

        # Verify consent engine is accessible.
        try:
            engine = get_consent_engine()
            components["consent_engine"] = "healthy" if engine else "unavailable"
        except Exception as exc:
            components["consent_engine"] = f"error: {type(exc).__name__}"

    all_ok = all(
        v in ("ready", "healthy")
        for v in components.values()
    )

    return {
        "status": "healthy" if all_ok else "degraded",
        "service": "luki-security-privacy",
        "version": "0.1.0",
        "components": components,
    }


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
        # Invalidate cached policy decisions so the new consent takes
        # effect immediately instead of waiting for TTL expiry.
        get_decision_cache().invalidate_user(user_id)
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
        # Invalidate cached policy decisions – privacy flags affect
        # which scopes are allowed.
        get_decision_cache().invalidate_user(user_id)
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

    import time as _time
    _start = _time.monotonic()
    try:
        encrypted = await encryption_service.encrypt(data)
        operational_metrics.record_call("encrypt", _time.monotonic() - _start, success=True)
        return {"encrypted_data": encrypted}
    except Exception as e:
        operational_metrics.record_call("encrypt", _time.monotonic() - _start, success=False)
        logger.error("Failed to encrypt data", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/decrypt")
async def decrypt_data(encrypted_data: str):
    """Decrypt sensitive data"""
    if not encryption_service:
        raise HTTPException(status_code=503, detail="Encryption service not available")

    import time as _time
    _start = _time.monotonic()
    try:
        decrypted = await encryption_service.decrypt(encrypted_data)
        operational_metrics.record_call("decrypt", _time.monotonic() - _start, success=True)
        return {"decrypted_data": decrypted}
    except Exception as e:
        operational_metrics.record_call("decrypt", _time.monotonic() - _start, success=False)
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

    # Check the decision cache for a recent ALLOW for this exact
    # user + scopes + role combination (short TTL, ~60 s).
    _dcache = get_decision_cache()
    _scope_key = frozenset(s.value for s in scopes)
    cached_decision = _dcache.get(request.user_id, _scope_key, request.requester_role)
    if cached_decision is not None:
        return cached_decision
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
                _result = {
                    "allowed": True,
                    "scopes_checked": [s.value for s in scopes],
                    "reason": "default_allow_processing_no_consent_record",
                }
                _dcache.put(request.user_id, _scope_key, request.requester_role, _result)
                return _result
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
                _result = {
                    "allowed": True,
                    "scopes_checked": [s.value for s in scopes],
                    "reason": "default_allow_elr_no_consent_record",
                }
                _dcache.put(request.user_id, _scope_key, request.requester_role, _result)
                return _result
    except Exception as exc:
        # On any unexpected failure in the default-allow branch,
        # fall back to normal consent enforcement.
        logger.error(
            "ELR default-allow check failed; falling back to strict enforcement",
            user_id=request.user_id,
            requester_role=request.requester_role,
            error=str(exc),
        )

    audit = get_audit_logger()

    try:
        engine.enforce_scope(request.user_id, request.requester_role, scopes)
        operational_metrics.record_policy_decision(allowed=True)

        # Record successful policy check in audit trail
        audit.log_event(
            event_type=AuditEventType.CONSENT_CHECK,
            action="enforce_policy",
            outcome="success",
            user_id=request.user_id,
            role=request.requester_role,
            details={
                "scopes": [s.value for s in scopes],
                "context": request.context or {},
            },
        )

        _result = {
            "allowed": True,
            "scopes_checked": [s.value for s in scopes],
            "reason": "consent_valid",
        }
        _dcache.put(request.user_id, _scope_key, request.requester_role, _result)
        return _result
    except ConsentExpiredError as exc:
        operational_metrics.record_policy_decision(allowed=False)
        audit.log_event(
            event_type=AuditEventType.CONSENT_CHECK,
            action="enforce_policy",
            outcome="denied",
            user_id=request.user_id,
            role=request.requester_role,
            details={"reason": "consent_expired", "scopes": [s.value for s in scopes]},
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "consent_expired",
                "message": str(exc),
                "scopes_checked": [s.value for s in scopes],
            },
        )
    except ConsentDeniedError as exc:
        operational_metrics.record_policy_decision(allowed=False)
        audit.log_event(
            event_type=AuditEventType.CONSENT_CHECK,
            action="enforce_policy",
            outcome="denied",
            user_id=request.user_id,
            role=request.requester_role,
            details={"reason": "consent_denied", "scopes": [s.value for s in scopes]},
        )
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

@app.get("/metrics")
async def get_metrics():
    """Operational metrics for consent, encryption, and policy enforcement.

    Returns counters, latency histograms, policy allow/deny ratios,
    and policy decision cache statistics.
    """
    metrics = operational_metrics.get_metrics()
    metrics["policy_decision_cache"] = get_decision_cache().get_stats()
    return metrics


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
