"""
Advanced rate limiting algorithms for LUKi Security & Privacy
Implements token bucket, sliding window, and adaptive rate limiting
"""

import time
import logging
from typing import Any, Dict, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
import threading

logger = logging.getLogger(__name__)


class RateLimitAlgorithm(str, Enum):
    """Rate limiting algorithm types"""
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    LEAKY_BUCKET = "leaky_bucket"


@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    algorithm: RateLimitAlgorithm
    limit: int  # requests
    window_seconds: int  # time window
    burst_limit: Optional[int] = None  # max burst size
    
    def __post_init__(self):
        if self.burst_limit is None:
            self.burst_limit = self.limit


class TokenBucketLimiter:
    """
    Token bucket rate limiter
    Allows bursts up to capacity, refills at steady rate
    """
    
    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket limiter
        
        Args:
            capacity: Maximum tokens (burst size)
            refill_rate: Tokens added per second
        """
        self._lock = threading.Lock()
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.time()
    
    def allow_request(self, tokens: int = 1) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed
        
        Args:
            tokens: Number of tokens to consume
        
        Returns:
            (allowed, metadata)
        """
        with self._lock:
            now = time.time()
            
            # Refill tokens based on time elapsed
            elapsed = now - self.last_refill
            self.tokens = min(
                self.capacity,
                self.tokens + (elapsed * self.refill_rate)
            )
            self.last_refill = now
            
            # Check if enough tokens available
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True, {
                    "remaining": int(self.tokens),
                    "limit": self.capacity,
                    "reset_seconds": 0  # Continuous refill
                }
            else:
                # Calculate when enough tokens will be available
                tokens_needed = tokens - self.tokens
                wait_seconds = tokens_needed / self.refill_rate
                
                return False, {
                    "remaining": 0,
                    "limit": self.capacity,
                    "retry_after": int(wait_seconds) + 1
                }
    
    def get_status(self) -> Dict[str, Any]:
        """Get current bucket status"""
        with self._lock:
            return {
                "algorithm": "token_bucket",
                "capacity": self.capacity,
                "current_tokens": int(self.tokens),
                "refill_rate_per_second": self.refill_rate
            }


class SlidingWindowLimiter:
    """
    Sliding window log rate limiter
    Precise tracking using timestamp log
    """
    
    def __init__(self, limit: int, window_seconds: int):
        """
        Initialize sliding window limiter
        
        Args:
            limit: Maximum requests in window
            window_seconds: Time window in seconds
        """
        self._lock = threading.Lock()
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests: list[float] = []  # Timestamps
    
    def allow_request(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed
        
        Returns:
            (allowed, metadata)
        """
        with self._lock:
            now = time.time()
            window_start = now - self.window_seconds
            
            # Remove requests outside window
            self.requests = [ts for ts in self.requests if ts > window_start]
            
            # Check limit
            if len(self.requests) < self.limit:
                self.requests.append(now)
                return True, {
                    "remaining": self.limit - len(self.requests),
                    "limit": self.limit,
                    "reset_seconds": self.window_seconds
                }
            else:
                # Calculate when oldest request expires
                oldest = min(self.requests)
                retry_after = int(oldest + self.window_seconds - now) + 1
                
                return False, {
                    "remaining": 0,
                    "limit": self.limit,
                    "retry_after": retry_after
                }
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status"""
        with self._lock:
            now = time.time()
            window_start = now - self.window_seconds
            active_requests = [ts for ts in self.requests if ts > window_start]
            
            return {
                "algorithm": "sliding_window",
                "limit": self.limit,
                "window_seconds": self.window_seconds,
                "current_requests": len(active_requests)
            }


class FixedWindowLimiter:
    """
    Fixed window counter rate limiter
    Simple and efficient, may allow short bursts at window boundaries
    """
    
    def __init__(self, limit: int, window_seconds: int):
        """
        Initialize fixed window limiter
        
        Args:
            limit: Maximum requests per window
            window_seconds: Window duration
        """
        self._lock = threading.Lock()
        self.limit = limit
        self.window_seconds = window_seconds
        self.window_start = time.time()
        self.request_count = 0
    
    def allow_request(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed
        
        Returns:
            (allowed, metadata)
        """
        with self._lock:
            now = time.time()
            
            # Check if window has expired
            if now - self.window_start >= self.window_seconds:
                # Reset window
                self.window_start = now
                self.request_count = 0
            
            # Check limit
            if self.request_count < self.limit:
                self.request_count += 1
                reset_seconds = int(self.window_start + self.window_seconds - now)
                
                return True, {
                    "remaining": self.limit - self.request_count,
                    "limit": self.limit,
                    "reset_seconds": reset_seconds
                }
            else:
                reset_seconds = int(self.window_start + self.window_seconds - now)
                
                return False, {
                    "remaining": 0,
                    "limit": self.limit,
                    "retry_after": reset_seconds
                }
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status"""
        with self._lock:
            now = time.time()
            age = now - self.window_start
            
            return {
                "algorithm": "fixed_window",
                "limit": self.limit,
                "window_seconds": self.window_seconds,
                "current_count": self.request_count,
                "window_age_seconds": int(age)
            }


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that adjusts limits based on behavior
    """
    
    def __init__(
        self,
        base_limit: int,
        window_seconds: int,
        burst_multiplier: float = 2.0,
        penalty_multiplier: float = 0.5
    ):
        """
        Initialize adaptive rate limiter
        
        Args:
            base_limit: Base rate limit
            window_seconds: Time window
            burst_multiplier: Multiplier for good behavior
            penalty_multiplier: Multiplier for bad behavior
        """
        self._lock = threading.Lock()
        self.base_limit = base_limit
        self.window_seconds = window_seconds
        self.burst_multiplier = burst_multiplier
        self.penalty_multiplier = penalty_multiplier
        
        # Per-identifier tracking
        self.identifiers: Dict[str, Dict[str, Any]] = {}
    
    def allow_request(self, identifier: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed
        
        Args:
            identifier: Client identifier (user_id, IP, etc.)
        
        Returns:
            (allowed, metadata)
        """
        with self._lock:
            now = time.time()
            
            # Get or create identifier state
            if identifier not in self.identifiers:
                self.identifiers[identifier] = {
                    "current_limit": self.base_limit,
                    "window_start": now,
                    "request_count": 0,
                    "violations": 0,
                    "last_violation": None
                }
            
            state = self.identifiers[identifier]
            
            # Reset window if expired
            if now - state["window_start"] >= self.window_seconds:
                # Adjust limit based on behavior
                if state["request_count"] < state["current_limit"] * 0.8:
                    # Good behavior: increase limit
                    state["current_limit"] = min(
                        int(state["current_limit"] * 1.1),
                        int(self.base_limit * self.burst_multiplier)
                    )
                elif state["violations"] > 0:
                    # Bad behavior: decrease limit
                    state["current_limit"] = max(
                        int(state["current_limit"] * 0.9),
                        int(self.base_limit * self.penalty_multiplier)
                    )
                
                state["window_start"] = now
                state["request_count"] = 0
                state["violations"] = 0
            
            # Check limit
            if state["request_count"] < state["current_limit"]:
                state["request_count"] += 1
                reset_seconds = int(state["window_start"] + self.window_seconds - now)
                
                return True, {
                    "remaining": state["current_limit"] - state["request_count"],
                    "limit": state["current_limit"],
                    "reset_seconds": reset_seconds,
                    "adaptive": True
                }
            else:
                # Record violation
                state["violations"] += 1
                state["last_violation"] = now
                reset_seconds = int(state["window_start"] + self.window_seconds - now)
                
                logger.warning(
                    f"Rate limit violation for {identifier}",
                    extra={
                        "identifier": identifier,
                        "current_limit": state["current_limit"],
                        "violations": state["violations"]
                    }
                )
                
                return False, {
                    "remaining": 0,
                    "limit": state["current_limit"],
                    "retry_after": reset_seconds,
                    "violations": state["violations"]
                }
    
    def get_status(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Get status for identifier"""
        with self._lock:
            if identifier not in self.identifiers:
                return None
            
            state = self.identifiers[identifier]
            now = time.time()
            
            return {
                "algorithm": "adaptive",
                "identifier": identifier,
                "current_limit": state["current_limit"],
                "base_limit": self.base_limit,
                "request_count": state["request_count"],
                "violations": state["violations"],
                "window_age_seconds": int(now - state["window_start"])
            }


class RateLimiterFactory:
    """Factory for creating rate limiters"""
    
    @staticmethod
    def create(config: RateLimitConfig):
        """
        Create rate limiter from config
        
        Args:
            config: Rate limit configuration
        
        Returns:
            Rate limiter instance
        """
        if config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            refill_rate = config.limit / config.window_seconds
            return TokenBucketLimiter(
                capacity=config.burst_limit,
                refill_rate=refill_rate
            )
        
        elif config.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
            return SlidingWindowLimiter(
                limit=config.limit,
                window_seconds=config.window_seconds
            )
        
        elif config.algorithm == RateLimitAlgorithm.FIXED_WINDOW:
            return FixedWindowLimiter(
                limit=config.limit,
                window_seconds=config.window_seconds
            )
        
        else:
            raise ValueError(f"Unknown algorithm: {config.algorithm}")
