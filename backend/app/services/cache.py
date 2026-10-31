"""Cache: Redis when REDIS_URL is set, otherwise a thread-safe in-memory TTL cache."""
import json
import threading
import time

from ..config import settings


class _MemoryCache:
    def __init__(self):
        self._data: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            expires, value = item
            if expires < time.time():
                self._data.pop(key, None)
                return None
            return value

    def set(self, key: str, value: str, ttl: int = 86400):
        with self._lock:
            if len(self._data) > 5000:
                self._data.clear()
            self._data[key] = (time.time() + ttl, value)


class Cache:
    def __init__(self):
        self.backend = _MemoryCache()
        self.kind = "memory"
        if settings.REDIS_URL:
            try:
                import redis
                client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2)
                client.ping()
                self.backend, self.kind = client, "redis"
            except Exception:
                pass

    def get_json(self, key: str):
        try:
            raw = self.backend.get(key)
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def set_json(self, key: str, value, ttl: int = 86400):
        try:
            if self.kind == "redis":
                self.backend.set(key, json.dumps(value), ex=ttl)
            else:
                self.backend.set(key, json.dumps(value), ttl)
        except Exception:
            pass


cache = Cache()
