"""Application security controls: sliding-window rate limiter, request size limits, and log sanitization."""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi import HTTPException, Request, status

from app.core.config import settings

LOG_CONTROL_CHARS_RE = re.compile(r"[\r\n\t\x00-\x1f\x7f]")


def sanitize_for_log(value: str, max_len: int = 120) -> str:
    """Sanitize untrusted input before writing to application logs to prevent log injection."""
    cleaned = LOG_CONTROL_CHARS_RE.sub("_", value or "")
    if len(cleaned) > max_len:
        return cleaned[:max_len] + "...[truncated]"
    return cleaned


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding-window rate limiter keyed by client identifier."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def reset(self) -> None:
        """Clear all recorded rate-limit timestamps (useful in automated tests)."""
        with self._lock:
            self._hits.clear()

    def check_request(self, client_key: str) -> None:
        """Raise HTTP 429 if the client has exceeded the allowed request rate."""
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            bucket = self._hits[client_key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self.max_requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error_code": "RATE_LIMIT_EXCEEDED",
                        "message": (
                            f"Rate limit exceeded ({self.max_requests} requests per "
                            f"{self.window_seconds} seconds). Please wait before submitting additional requests."
                        ),
                    },
                )
            bucket.append(now)


rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.rate_limit_requests,
    window_seconds=settings.rate_limit_window_seconds,
)


def enforce_rate_limit(request: Request) -> None:
    """FastAPI dependency enforcing rate limits per client IP."""
    client_host = request.client.host if request.client else "unknown"
    rate_limiter.check_request(client_host)
