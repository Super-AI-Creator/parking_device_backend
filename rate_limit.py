"""In-memory rate limiting for public PIN unlock attempts."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class AttemptLimiter:
    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> None:
        bucket = self._hits[key]
        while bucket and now - bucket[0] > self.window_seconds:
            bucket.popleft()

    def is_blocked(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            self._prune(key, now)
            return len(self._hits[key]) >= self.max_attempts

    def register_failure(self, key: str) -> None:
        now = time.time()
        with self._lock:
            self._prune(key, now)
            self._hits[key].append(now)

    def clear(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def retry_after_seconds(self, key: str) -> int:
        now = time.time()
        with self._lock:
            self._prune(key, now)
            bucket = self._hits.get(key)
            if not bucket:
                return 0
            return max(1, int(self.window_seconds - (now - bucket[0])) + 1)
