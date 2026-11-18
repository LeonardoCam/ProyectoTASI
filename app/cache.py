"""Caché TTL en memoria ("memoria inteligente"): evita repetir análisis de enlaces virales."""
import time
from collections import OrderedDict
from typing import Any, Optional

from . import config


class TTLCache:
    def __init__(self, ttl: int = config.CACHE_TTL, max_entries: int = config.CACHE_MAX_ENTRIES):
        self.ttl = ttl
        self.max_entries = max_entries
        self._data: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        item = self._data.get(key)
        # "<=": en Windows time.monotonic() avanza a saltos de ~15 ms; con "<" una entrada con TTL 0
        # podía seguir viva justo después de crearse (y la prueba test_expiry fallaba a veces).
        if item is None or item[0] <= time.monotonic():
            self._data.pop(key, None)
            self.misses += 1
            return None
        self._data.move_to_end(key)
        self.hits += 1
        return item[1]

    def set(self, key: str, value: Any) -> None:
        self._data[key] = (time.monotonic() + self.ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self.max_entries:
            self._data.popitem(last=False)

    def remaining(self, key: str) -> Optional[float]:
        """Segundos que le quedan a la entrada antes de caducar (None si no existe o ya caducó)."""
        item = self._data.get(key)
        if item is None:
            return None
        left = item[0] - time.monotonic()
        return left if left > 0 else None

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def clear(self) -> None:
        self._data.clear()
        self.hits = self.misses = 0

    def __len__(self) -> int:
        return len(self._data)
