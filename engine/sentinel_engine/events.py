"""Out-of-band event emitter.

Decisions are pushed to a Redis stream by a background worker so the request
path never waits on Redis. If Redis is slow or down the queue drops events
rather than blocking or failing a request. Events carry a redacted sample only
when the decision was not a plain allow.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
from typing import Any

STREAM = os.environ.get("SENTINEL_EVENT_STREAM", "sentinel:events")
STREAM_MAXLEN = int(os.environ.get("SENTINEL_EVENT_MAXLEN", "100000"))
REDIS_URL = os.environ.get("SENTINEL_REDIS_URL", "redis://sentinel-redis:6379/0")
QUEUE_MAX = int(os.environ.get("SENTINEL_EVENT_QUEUE", "10000"))


class EventEmitter:
    def __init__(self, redis_url: str = REDIS_URL):
        self._q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=QUEUE_MAX)
        self._redis_url = redis_url
        self._client = None
        self._dropped = 0
        self._sent = 0
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._run, name="event-emitter", daemon=True)

    def start(self) -> None:
        self._worker.start()

    def emit(self, event: dict[str, Any]) -> None:
        try:
            self._q.put_nowait(event)
        except queue.Full:
            self._dropped += 1

    @property
    def stats(self) -> dict[str, int]:
        return {"sent": self._sent, "dropped": self._dropped, "queued": self._q.qsize()}

    def _connect(self):
        if self._client is None:
            import redis  # imported lazily so tests need no redis running
            self._client = redis.from_url(self._redis_url, socket_connect_timeout=2, socket_timeout=2)
        return self._client

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                event = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                client = self._connect()
                client.xadd(STREAM, {"json": json.dumps(event)}, maxlen=STREAM_MAXLEN, approximate=True)
                self._sent += 1
            except Exception:
                # Redis unavailable: drop this event and retry the connection later.
                self._client = None
                self._dropped += 1
                time.sleep(1)

    def stop(self) -> None:
        self._stop.set()
