"""Redis stream consumer: correlate every event, triage gray-zone ones with M5."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .correlator import Correlator

EVENTS = os.environ.get("SENTINEL_EVENT_STREAM", "sentinel:events")
CAMPAIGNS = os.environ.get("SENTINEL_CAMPAIGN_STREAM", "sentinel:campaigns")
VERDICTS = os.environ.get("SENTINEL_VERDICT_STREAM", "sentinel:verdicts")
GROUP = os.environ.get("SENTINEL_ANALYST_GROUP", "analyst")
STREAM_MAXLEN = int(os.environ.get("SENTINEL_ANALYST_MAXLEN", "50000"))
# Skip M5 if the consumer lags by more than this, so triage never blocks intake.
LAG_SKIP = int(os.environ.get("SENTINEL_M5_LAG_SKIP", "500"))


def _grayzone(event: dict) -> bool:
    # Decisive outcomes (a hard block, or a plain allow) need no LLM opinion.
    if event.get("hard") == "block":
        return False
    return event.get("intended") in ("log", "challenge")


class Consumer:
    def __init__(self, redis_client, cfg, m5=None, applier=None):
        self.r = redis_client
        self.cfg = cfg
        self.m5 = m5
        self.applier = applier
        self.correlator = Correlator()
        # M5 is slow (LLM inference); run it off the intake path so correlation
        # and denylist application stay immediate and are never head-of-line
        # blocked behind a triage call.
        self._m5_pool = ThreadPoolExecutor(max_workers=int(os.environ.get("SENTINEL_M5_WORKERS", "2")))
        self.name = os.environ.get("HOSTNAME", socket.gethostname())
        self.counters = {"events": 0, "campaigns": 0, "verdicts": 0,
                         "m5_calls": 0, "m5_invalid": 0, "m5_skipped_lag": 0}
        self._lock = threading.Lock()
        self._stop = False

    def _ensure_group(self):
        try:
            self.r.xgroup_create(EVENTS, GROUP, id="0", mkstream=True)
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def run_once(self, block_ms: int = 2000, count: int = 50) -> int:
        msgs = self.r.xreadgroup(GROUP, self.name, {EVENTS: ">"}, count=count, block=block_ms)
        if not msgs:
            return 0
        processed = 0
        for _stream, entries in msgs:
            lag = len(entries)
            for msg_id, fields in entries:
                try:
                    event = json.loads(fields.get("json", "{}"))
                    self._process(event, lag)
                except Exception:
                    pass
                finally:
                    self.r.xack(EVENTS, GROUP, msg_id)
                    processed += 1
        return processed

    def _process(self, event: dict, lag: int):
        with self._lock:
            self.counters["events"] += 1
        for alert in self.correlator.update(self.r, event):
            self.r.xadd(CAMPAIGNS, {"json": json.dumps(alert)}, maxlen=STREAM_MAXLEN, approximate=True)
            with self._lock:
                self.counters["campaigns"] += 1
            if self.applier:
                try:
                    self.applier.on_campaign(alert)
                except Exception:
                    pass
        if self.m5 and _grayzone(event):
            if lag > LAG_SKIP:
                with self._lock:
                    self.counters["m5_skipped_lag"] += 1
                return
            self._m5_pool.submit(self._triage, event)

    def _triage(self, event: dict):
        with self._lock:
            self.counters["m5_calls"] += 1
        try:
            verdict = self.m5.triage(event)
        except Exception:
            verdict = None
        if verdict is None:
            with self._lock:
                self.counters["m5_invalid"] += 1
            return
        record = {"ts": time.time(), "request_id": event.get("request_id"),
                  "path": event.get("path"), "client_ip": event.get("client_ip"),
                  "engine_intended": event.get("intended"), "verdict": verdict}
        self.r.xadd(VERDICTS, {"json": json.dumps(record)}, maxlen=STREAM_MAXLEN, approximate=True)
        with self._lock:
            self.counters["verdicts"] += 1
        if self.applier:
            try:
                self.applier.on_verdict(record)
            except Exception:
                pass

    def run_forever(self):
        self._ensure_group()
        while not self._stop:
            try:
                self.run_once()
            except Exception:
                time.sleep(1)

    def stop(self):
        self._stop = True
