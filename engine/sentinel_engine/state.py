"""Per-client sliding-window state and learn-mode baselines, backed by Redis.

M2 (behavior) needs to see a client's recent activity, which a single request
cannot provide. This keeps short-TTL counters per client IP (request rate and
distinct-path fan-out over a rolling window) and, in learn mode, records the set
of parameter names each route normally sees so novelty can be measured later.

All Redis access is best-effort: if Redis is slow or down, reads return None and
the behaviour scorer simply abstains, so the request path never fails on state.
"""

from __future__ import annotations

import os
import time
from typing import Any

WINDOW_SECONDS = int(os.environ.get("SENTINEL_STATE_WINDOW", "10"))
REDIS_URL = os.environ.get("SENTINEL_REDIS_URL", "redis://sentinel-redis:6379/0")
BASELINE_TTL = int(os.environ.get("SENTINEL_BASELINE_TTL", "2592000"))  # 30 days


class ClientState:
    def __init__(self, redis_url: str = REDIS_URL):
        self._url = redis_url
        self._client = None
        self._down_until = 0.0

    def _redis(self):
        if time.time() < self._down_until:
            return None
        if self._client is None:
            try:
                import redis
                self._client = redis.from_url(
                    self._url, socket_connect_timeout=0.2, socket_timeout=0.2,
                    decode_responses=True)
            except Exception:
                self._trip()
                return None
        return self._client

    def _trip(self):
        # Back off from Redis for a short while after a failure.
        self._client = None
        self._down_until = time.time() + 5

    def observe(self, ip: str, path: str, route_id: str, param_names: list[str], learn: bool) -> dict[str, Any] | None:
        """Record this request and return the client's current window stats.

        Returns None if Redis is unavailable (scorers then abstain).
        """
        r = self._redis()
        if r is None or not ip:
            return None
        try:
            now_bucket = ""  # single rolling window via TTL reset
            rk = f"st:{ip}:r"
            pk = f"st:{ip}:p"
            pipe = r.pipeline()
            pipe.incr(rk)
            pipe.expire(rk, WINDOW_SECONDS)
            pipe.sadd(pk, path)
            pipe.expire(pk, WINDOW_SECONDS)
            pipe.scard(pk)
            pipe.get(f"dyn:deny:{ip}")
            deny_idx = 5
            if learn and param_names:
                bk = f"base:{route_id}:params"
                pipe.sadd(bk, *param_names[:50])
                pipe.expire(bk, BASELINE_TTL)
            results = pipe.execute()
            rate = int(results[0])
            fanout = int(results[4])
            denied = results[deny_idx]
            novelty = self._novelty(r, route_id, param_names) if not learn else 0.0
            del now_bucket
            return {"rate": rate, "fanout": fanout, "novelty": novelty,
                    "denied": denied, "window": WINDOW_SECONDS}
        except Exception:
            self._trip()
            return None

    def _novelty(self, r, route_id: str, param_names: list[str]) -> float:
        if not param_names:
            return 0.0
        bk = f"base:{route_id}:params"
        try:
            if not r.exists(bk):
                return 0.0  # nothing learned yet -> do not penalise
            known = r.smembers(bk)
            novel = [p for p in param_names if p not in known]
            return len(novel) / len(param_names)
        except Exception:
            return 0.0

    def clear_client(self, ip: str) -> None:
        r = self._redis()
        if r is None:
            return
        try:
            r.delete(f"st:{ip}:r", f"st:{ip}:p")
        except Exception:
            self._trip()
