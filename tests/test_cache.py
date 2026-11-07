import time

from app.cache import TTLCache


def test_hit_miss_and_stats():
    c = TTLCache(ttl=10, max_entries=10)
    assert c.get("a") is None
    c.set("a", 1)
    assert c.get("a") == 1
    assert (c.hits, c.misses) == (1, 1)


def test_expiry():
    c = TTLCache(ttl=0, max_entries=10)
    c.set("a", 1)
    time.sleep(0.01)
    assert c.get("a") is None


def test_eviction_lru():
    c = TTLCache(ttl=10, max_entries=2)
    c.set("a", 1); c.set("b", 2); c.get("a"); c.set("c", 3)
    assert c.get("b") is None and c.get("a") == 1 and c.get("c") == 3
