"""
Operational metrics for LUKi Security & Privacy Module.

Tracks counters, latencies, and error rates for the core security
operations: consent checks, policy enforcement, encryption/decryption,
and privacy control lookups.  Exposes a structured dict suitable for
the ``/metrics`` endpoint.
"""

import threading
import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from collections import defaultdict
from functools import wraps

logger = logging.getLogger(__name__)


class OperationalMetrics:
    """
    Thread-safe operational metrics collector for the security module.

    Tracks:
    - Counters per operation (calls, successes, errors)
    - Histogram of latencies per operation
    - Policy enforcement outcomes (allow/deny)
    """

    def __init__(self, histogram_limit: int = 500) -> None:
        self._lock = threading.Lock()
        self._histogram_limit = histogram_limit
        self._start_time = datetime.now(timezone.utc)

        # Per-operation counters
        self._calls: Dict[str, int] = defaultdict(int)
        self._errors: Dict[str, int] = defaultdict(int)
        # Latency histograms (bounded deques)
        self._latencies: Dict[str, list] = defaultdict(list)

        # Policy-specific counters
        self._policy_allowed: int = 0
        self._policy_denied: int = 0

    # ------------------------------------------------------------------
    # Recording helpers
    # ------------------------------------------------------------------

    def record_call(
        self,
        operation: str,
        latency_seconds: float,
        success: bool = True,
    ) -> None:
        """Record an operation call with its latency and outcome."""
        with self._lock:
            self._calls[operation] += 1
            if not success:
                self._errors[operation] += 1
            self._latencies[operation].append(latency_seconds)
            # Bound histogram size
            if len(self._latencies[operation]) > self._histogram_limit:
                self._latencies[operation] = self._latencies[operation][
                    -self._histogram_limit :
                ]

    def record_policy_decision(self, allowed: bool) -> None:
        """Record a policy enforcement outcome (allow or deny)."""
        with self._lock:
            if allowed:
                self._policy_allowed += 1
            else:
                self._policy_denied += 1

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def get_metrics(self) -> Dict[str, Any]:
        """Return a structured snapshot of all collected metrics."""
        with self._lock:
            uptime = (datetime.now(timezone.utc) - self._start_time).total_seconds()

            operations: Dict[str, Any] = {}
            for op in set(list(self._calls.keys()) + list(self._latencies.keys())):
                latencies = self._latencies.get(op, [])
                calls = self._calls.get(op, 0)
                errors = self._errors.get(op, 0)
                ops_data: Dict[str, Any] = {
                    "calls": calls,
                    "errors": errors,
                    "error_rate_pct": round(errors / calls * 100, 2) if calls else 0.0,
                }
                if latencies:
                    s = sorted(latencies)
                    ops_data["latency"] = {
                        "min_ms": round(s[0] * 1000, 1),
                        "max_ms": round(s[-1] * 1000, 1),
                        "mean_ms": round(sum(s) / len(s) * 1000, 1),
                        "p95_ms": round(s[int(len(s) * 0.95)] * 1000, 1),
                    }
                operations[op] = ops_data

            return {
                "uptime_seconds": round(uptime, 1),
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "operations": operations,
                "policy": {
                    "allowed": self._policy_allowed,
                    "denied": self._policy_denied,
                    "total": self._policy_allowed + self._policy_denied,
                },
            }

    def reset(self) -> None:
        """Reset all metrics (useful for testing)."""
        with self._lock:
            self._calls.clear()
            self._errors.clear()
            self._latencies.clear()
            self._policy_allowed = 0
            self._policy_denied = 0
            self._start_time = datetime.now(timezone.utc)


# Global metrics instance
operational_metrics = OperationalMetrics()


def track_operation(operation_name: str):
    """
    Decorator that instruments an async function with latency and
    success/error tracking.

    Usage::

        @track_operation("consent_check")
        async def check_consent(user_id: str):
            ...
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start = time.monotonic()
            success = True
            try:
                return await func(*args, **kwargs)
            except Exception:
                success = False
                raise
            finally:
                latency = time.monotonic() - start
                operational_metrics.record_call(
                    operation_name, latency, success=success
                )

        return wrapper

    return decorator
