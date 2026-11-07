"""Limitador de peticiones por IP (ventana deslizante de 60 s) para evitar abuso del servicio."""
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        if self.per_minute <= 0:
            return True
        now = time.monotonic()
        q = self._hits[key]
        while q and q[0] <= now - 60:
            q.popleft()
        if len(q) >= self.per_minute:
            return False
        q.append(now)
        return True
