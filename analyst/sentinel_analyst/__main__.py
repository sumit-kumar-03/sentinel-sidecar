"""Entry point: connect to Redis, optionally wire M5, consume forever."""

from __future__ import annotations

import os
import sys
import time

import redis

from . import appconfig, server
from .applier import Applier
from .consumer import Consumer
from .llm import M5

REDIS_URL = os.environ.get("SENTINEL_REDIS_URL", "redis://sentinel-redis:6379/0")


def main() -> int:
    cfg = appconfig.load()
    r = redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=2)
    for _ in range(30):
        try:
            r.ping(); break
        except Exception:
            time.sleep(1)

    m5 = None
    if cfg.llm_ready:
        m5 = M5(cfg.llm["url"], cfg.llm["model"])
        print(f"sentinel-analyst: M5 enabled via {cfg.llm['url']} ({cfg.llm['model']})", flush=True)
    else:
        print("sentinel-analyst: M5 disabled (analyst.enabled/llm not configured); correlator only", flush=True)

    applier = Applier(r, cfg)
    print(f"sentinel-analyst: auto_actions denylist={applier.denylist_enabled} rules={applier.rules_mode}", flush=True)
    consumer = Consumer(r, cfg, m5=m5, applier=applier)
    server.start_admin(consumer)
    print("sentinel-analyst: consuming events", flush=True)
    consumer.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
