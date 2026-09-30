"""Admin/metrics HTTP server for the analyst (internal scraping/ops only).

Endpoints:
  GET  /healthz
  GET  /metrics                    Prometheus counters
  GET  /admin/actions              recent audit log (applied actions)
  GET  /admin/denylist             active dynamic denylist entries
  GET  /admin/proposals            findings awaiting human action
  DELETE /admin/denylist?ip=A.B.C.D   lift a block (audited)
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ADMIN_PORT = 9200
AUDIT = "sentinel:audit"
PROPOSALS = "sentinel:proposals"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _text(self, status, text):
        data = text.encode()
        self.send_response(status)
        self.send_header("content-type", "text/plain; version=0.0.4")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _stream(self, key, n=50):
        try:
            rows = self.server.redis.xrevrange(key, count=n)
            return [json.loads(f.get("json", "{}")) for _id, f in rows]
        except Exception:
            return []

    def _denylist(self):
        out = []
        try:
            for k in self.server.redis.scan_iter(match="dyn:deny:*", count=100):
                if ":count:" in k:
                    continue
                ip = k.split("dyn:deny:", 1)[1]
                val = self.server.redis.get(k)
                ttl = self.server.redis.ttl(k)
                try:
                    info = json.loads(val)
                except (ValueError, TypeError):
                    info = {"raw": val}
                out.append({"ip": ip, "ttl": ttl, **info})
        except Exception:
            pass
        return out

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/healthz":
            self._text(200, "ok\n")
        elif path == "/metrics":
            self._text(200, self.server.metrics())
        elif path == "/admin/actions":
            self._json(200, self._stream(AUDIT))
        elif path == "/admin/proposals":
            self._json(200, self._stream(PROPOSALS))
        elif path == "/admin/denylist":
            self._json(200, self._denylist())
        else:
            self._text(404, "not found\n")

    def do_DELETE(self):
        parts = urllib.parse.urlsplit(self.path)
        if parts.path == "/admin/denylist":
            ip = urllib.parse.parse_qs(parts.query).get("ip", [""])[0]
            if not ip:
                self._json(400, {"error": "ip query param required"})
                return
            try:
                removed = self.server.redis.delete(f"dyn:deny:{ip}")
                import time
                self.server.redis.xadd(AUDIT, {"json": json.dumps(
                    {"ts": time.time(), "action": "manual_lift", "target_ip": ip, "removed": removed})})
                self._json(200, {"lifted": ip, "removed": bool(removed)})
            except Exception as e:
                self._json(500, {"error": str(e)})
        else:
            self._text(404, "not found\n")


def metrics_text(consumer) -> str:
    c = dict(consumer.counters)
    if consumer.applier:
        for k, v in consumer.applier.counters.items():
            c[f"apply_{k}"] = v
    lines = ["# HELP sentinel_analyst_total Analyst counters.",
             "# TYPE sentinel_analyst_total counter"]
    for key, value in c.items():
        lines.append(f'sentinel_analyst_total{{kind="{key}"}} {value}')
    lines.append(f'sentinel_analyst_m5_enabled {1 if consumer.m5 else 0}')
    return "\n".join(lines) + "\n"


def start_admin(consumer):
    srv = ThreadingHTTPServer(("0.0.0.0", ADMIN_PORT), _Handler)
    srv.metrics = lambda: metrics_text(consumer)
    srv.redis = consumer.r
    threading.Thread(target=srv.serve_forever, name="admin", daemon=True).start()
