"""
Policy Decision Cache

Short-lived cache for policy enforcement decisions so that rapid
successive checks for the same user + scope combination (common during
a single chat turn that calls multiple tools) avoid redundant consent
engine lookups.

Design:
- TTL is short (60 s) to limit the window in which a stale decision
  could be served after a user modifies their consent.
- Cache is keyed on (user_id, frozenset(scopes), requester_role).
- Only ALLOW decisions are cached.  Denials are always re-evaluated
  so a freshly-granted consent takes effect immediately.
- Thread-safe via a lock; low contention expected since the cache is
  only read/written inside FastAPI request handlers.
"""

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Optional, Tuple

logger = logging.getLogger(__name__)

# Short TTL so consent changes propagate quickly
_DEFAULT_TTL_SECONDS = 60
_MAX_ENTRIES = 2000


@dataclass(frozen=True)
class _CacheKey:
    user_id: str
    scopes: FrozenSet[str]
    role: str


@dataclass
class _CacheEntry:
    decision: Dict[str, Any]
    expires_at: float  # monotonic timestamp


class PolicyDecisionCache:
    """LRU + TTL cache for policy allow decisions."""

    def __init__(
        self,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        max_entries: int = _MAX_ENTRIES,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._store: OrderedDict[_CacheKey, _CacheEntry] = OrderedDict()

        # Stats
        self._hits = 0
        self._misses = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(
        self,
        user_id: str,
        scopes: FrozenSet[str],
        role: str,
    ) -> Optional[Dict[str, Any]]:
        """Return a cached ALLOW decision, or ``None`` on miss / expiry."""
        key = _CacheKey(user_id, scopes, role)
        now = time.monotonic()

        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            if now >= entry.expires_at:
                del self._store[key]
                self._misses += 1
                return None
            # LRU refresh
            self._store.move_to_end(key)
            self._hits += 1
            return entry.decision

    def put(
        self,
        user_id: str,
        scopes: FrozenSet[str],
        role: str,
        decision: Dict[str, Any],
    ) -> None:
        """Cache an ALLOW decision.  Deny decisions are NOT cached."""
        if not decision.get("allowed"):
            return  # never cache denials

        key = _CacheKey(user_id, scopes, role)
        entry = _CacheEntry(
            decision=decision,
            expires_at=time.monotonic() + self._ttl,
        )

        with self._lock:
            # Upsert
            if key in self._store:
                del self._store[key]
            self._store[key] = entry

            # Evict oldest if over capacity
            while len(self._store) > self._max_entries:
                self._store.popitem(last=False)

    def invalidate_user(self, user_id: str) -> int:
        """Invalidate all cached decisions for a user.

        Call this when a user updates their consent or privacy settings
        so stale allows are not served.

        Returns the number of evicted entries.
        """
        with self._lock:
            keys_to_remove = [k for k in self._store if k.user_id == user_id]
            for k in keys_to_remove:
                del self._store[k]
            if keys_to_remove:
                logger.info(
                    "Invalidated %d cached policy decisions for user %s",
                    len(keys_to_remove), user_id,
                )
            return len(keys_to_remove)

    def get_stats(self) -> Dict[str, Any]:
        """Return cache statistics for the /metrics endpoint."""
        with self._lock:
            total = self._hits + self._misses
            return {
                "entries": len(self._store),
                "max_entries": self._max_entries,
                "ttl_seconds": self._ttl,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_pct": round(self._hits / total * 100, 2) if total else 0.0,
            }

    def clear(self) -> None:
        """Remove all entries (useful for testing)."""
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------
_cache: Optional[PolicyDecisionCache] = None


def get_decision_cache() -> PolicyDecisionCache:
    """Return the global policy decision cache."""
    global _cache
    if _cache is None:
        _cache = PolicyDecisionCache()
    return _cache
