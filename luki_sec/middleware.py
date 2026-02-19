"""
Middleware for LUKi Security & Privacy Module.

Provides:
- Request correlation: generates/propagates X-Trace-ID for cross-service tracing.
- PII-safe structured request logging: logs request metadata without body
  content to avoid accidentally persisting sensitive data.
- Policy audit integration: records policy enforcement decisions to the
  audit trail automatically.
"""

import logging
import time
import uuid
from contextvars import ContextVar
from typing import Optional

import structlog
from fastapi import Request

logger = structlog.get_logger()

# Context variable for the active trace ID.
_trace_id_var: ContextVar[Optional[str]] = ContextVar("trace_id", default=None)


def get_trace_id() -> Optional[str]:
    """Return the trace ID for the current async context."""
    return _trace_id_var.get()


async def correlation_middleware(request: Request, call_next):
    """
    Extract or generate a trace ID and attach it to the response.

    Incoming headers ``X-Trace-ID`` or ``X-Request-ID`` are honoured;
    otherwise a new ID is generated.  The ID is stored in a context
    variable so downstream code (audit logger, metrics) can reference it.
    """
    trace_id = (
        request.headers.get("x-trace-id")
        or request.headers.get("x-request-id")
        or uuid.uuid4().hex[:16]
    )
    _trace_id_var.set(trace_id)

    response = await call_next(request)
    response.headers["X-Trace-ID"] = trace_id
    return response


async def request_logging_middleware(request: Request, call_next):
    """
    Log every inbound request with method, path, status, and latency.

    Request and response *bodies* are deliberately excluded to prevent
    PII from entering log storage.  Health probes are logged at debug
    level to reduce noise.
    """
    start = time.monotonic()
    response = await call_next(request)
    latency_ms = round((time.monotonic() - start) * 1000, 1)

    path = request.url.path
    trace_id = _trace_id_var.get()

    # Reduce noise from frequent health probes.
    if path == "/health":
        logger.debug(
            "request",
            method=request.method,
            path=path,
            status=response.status_code,
            latency_ms=latency_ms,
            trace_id=trace_id,
        )
    else:
        logger.info(
            "request",
            method=request.method,
            path=path,
            status=response.status_code,
            latency_ms=latency_ms,
            trace_id=trace_id,
        )

    return response
