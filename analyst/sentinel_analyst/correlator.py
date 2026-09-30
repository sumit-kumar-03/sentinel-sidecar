"""Windowed campaign detection over the event stream.

Two deterministic detectors, complementary to the engine's per-request view:

- distributed credential stuffing: many distinct client IPs hitting one auth
  route within a short window (a botnet spread thin enough that no single IP
  trips the per-client behaviour scorer).
- slow scan: one client IP touching many distinct paths over a long window
  (low-and-slow enumeration that stays under the engine's 10s fan-out window).

State lives in Redis with TTLs; each campaign type has a cooldown so a sustained
attack raises one alert, not thousands.
"""

from __future__ import annotations

import os
import time

AUTH_WINDOW = int(os.environ.get("SENTINEL_CORR_AUTH_WINDOW", "300"))
AUTH_MIN_IPS = int(os.environ.get("SENTINEL_CORR_AUTH_IPS", "8"))
AUTH_MIN_REQS = int(os.environ.get("SENTINEL_CORR_AUTH_REQS", "30"))
SCAN_WINDOW = int(os.environ.get("SENTINEL_CORR_SCAN_WINDOW", "900"))
SCAN_MIN_PATHS = int(os.environ.get("SENTINEL_CORR_SCAN_PATHS", "30"))
COOLDOWN = int(os.environ.get("SENTINEL_CORR_COOLDOWN", "600"))


def _is_auth(path: str, route: str) -> bool:
    hay = f"{path} {route}".lower()
    return any(k in hay for k in ("login", "signin", "sign-in", "auth", "session", "token", "password"))


class Correlator:
    def update(self, r, event: dict) -> list[dict]:
        """Fold one event into the windows; return any campaign alerts raised."""
        ip = event.get("client_ip") or ""
        path = event.get("path") or ""
        route = event.get("route") or "default"
        if not ip:
            return []
        now = int(time.time())
        alerts: list[dict] = []
        if _is_auth(path, route):
            alerts += self._auth(r, route, ip, now)
        alerts += self._scan(r, ip, path, now)
        return alerts

    def _cooldown_ok(self, r, key: str) -> bool:
        try:
            return bool(r.set(key, "1", nx=True, ex=COOLDOWN))
        except Exception:
            return False

    def _auth(self, r, route: str, ip: str, now: int) -> list[dict]:
        ikey, ckey = f"corr:auth:{route}:ips", f"corr:auth:{route}:cnt"
        try:
            pipe = r.pipeline()
            pipe.sadd(ikey, ip); pipe.expire(ikey, AUTH_WINDOW)
            pipe.incr(ckey); pipe.expire(ckey, AUTH_WINDOW)
            pipe.scard(ikey)
            res = pipe.execute()
            distinct, count = int(res[4]), int(res[2])
        except Exception:
            return []
        if distinct >= AUTH_MIN_IPS and count >= AUTH_MIN_REQS and self._cooldown_ok(r, f"corr:cd:auth:{route}"):
            return [{"type": "distributed_stuffing", "ts": now, "route": route,
                     "distinct_ips": distinct, "requests": count, "window_s": AUTH_WINDOW}]
        return []

    def _scan(self, r, ip: str, path: str, now: int) -> list[dict]:
        pkey = f"corr:scan:{ip}:paths"
        try:
            pipe = r.pipeline()
            pipe.sadd(pkey, path); pipe.expire(pkey, SCAN_WINDOW); pipe.scard(pkey)
            distinct = int(pipe.execute()[2])
        except Exception:
            return []
        if distinct >= SCAN_MIN_PATHS and self._cooldown_ok(r, f"corr:cd:scan:{ip}"):
            return [{"type": "slow_scan", "ts": now, "client_ip": ip,
                     "distinct_paths": distinct, "window_s": SCAN_WINDOW}]
        return []
