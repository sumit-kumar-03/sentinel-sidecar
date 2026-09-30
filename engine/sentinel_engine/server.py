"""HTTP ext_authz server plus a small internal admin/metrics server.

Envoy calls the ext_authz server (port 9000) with the original method, path,
selected headers and body of each inspected request. A 200 lets the request
through; a 403/429 blocks or challenges it. The admin server (port 9001) serves
health and Prometheus metrics for internal scraping and is never exposed
publicly.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import appconfig, challenge, ensemble, features as featuremod
from .events import EventEmitter
from .scorers import Context, default_scorers
from .state import ClientState

AUTHZ_PORT = 9000
ADMIN_PORT = 9001
MAX_BODY = 1024 * 1024  # hard cap on what we will read from Envoy


class Engine:
    def __init__(self, cfg: appconfig.EngineConfig, emitter: EventEmitter, state: ClientState):
        self.cfg = cfg
        self.emitter = emitter
        self.state = state
        self.scorers = default_scorers()
        self._m1 = next((s for s in self.scorers if getattr(s, "id", None) == "m1" and hasattr(s, "explain")), None)
        self.counters: dict[str, int] = {a: 0 for a in ensemble.ACTIONS}
        self.counters["total"] = 0
        self.counters["cleared"] = 0
        self.counters["denylisted"] = 0
        self._lock = threading.Lock()

    def decide(self, method: str, raw_path: str, headers: dict[str, str], body: bytes) -> dict[str, Any]:
        feats = featuremod.extract(method, raw_path, headers, body, self.cfg.identity)
        policy = self.cfg.match(method, feats.path)
        match = policy.get("match", {})
        route_id = match.get("path_prefix") or match.get("path_exact") or "default"
        learn = self.cfg.mode == "learn"
        st = self.state.observe(feats.client_ip, feats.path, route_id, feats.param_names, learn)
        cleared = challenge.is_cleared(feats.cookie)
        ctx = Context(features=feats, state=st, llm_endpoint=bool(policy.get("llm_endpoint")))
        decision = ensemble.combine(ctx, self.scorers, policy, self.cfg.mode, cleared=cleared)

        # Feedback loop: an active dynamic-denylist entry (written by the analyst)
        # is decisive here, unless the client is allowlisted. This is how an
        # out-of-band verdict becomes an inline block within seconds.
        deny_reason = None
        denied_raw = st.get("denied") if st else None
        if denied_raw and not self.cfg.is_allowlisted(feats.client_ip):
            try:
                dinfo = json.loads(denied_raw)
            except (ValueError, TypeError):
                dinfo = {"action": "block", "reason": "dynamic_denylist"}
            deny_action = dinfo.get("action", "block")
            deny_reason = dinfo.get("reason", "dynamic_denylist")
            decision.intended = ensemble._worse(decision.intended, deny_action)
            decision.hard = decision.hard or "denylist"
            decision.effective = (decision.intended if self.cfg.mode == "enforce"
                                  else ("log" if decision.intended in ("challenge", "block") else decision.intended))

        with self._lock:
            self.counters["total"] += 1
            self.counters[decision.effective] += 1
            if cleared:
                self.counters["cleared"] += 1
            if deny_reason:
                self.counters["denylisted"] += 1
        self._emit(decision, ctx, headers, cleared, deny_reason)
        return {
            "effective": decision.effective,
            "intended": decision.intended,
            "risk": decision.risk,
            "scores": decision.scores,
            "request_id": headers.get("x-request-id", ""),
        }

    def _emit(self, decision: ensemble.Decision, ctx: Context, headers: dict[str, str], cleared: bool, deny_reason: str | None = None) -> None:
        feats = ctx.features
        event: dict[str, Any] = {
            "ts": time.time(),
            "request_id": headers.get("x-request-id", ""),
            "client_ip": feats.client_ip,
            "method": feats.method,
            "path": feats.path,
            "route": decision.route_id,
            "risk": decision.risk,
            "scores": decision.scores,
            "intended": decision.intended,
            "effective": decision.effective,
            "hard": decision.hard,
            "cleared": cleared,
            "deny_reason": deny_reason,
            "mode": self.cfg.mode,
            "user_agent": feats.user_agent[:256],
        }
        if ctx.state:
            event["behavior"] = {"rate": ctx.state["rate"], "fanout": ctx.state["fanout"]}
        if decision.intended != "allow":
            event["sample"] = {
                "headers": self.cfg.redact_headers(headers),
                "param_names": feats.param_names[:50],
                "values": self._redacted_values(feats),
                "hits": self._m1.explain(ctx) if self._m1 else [],
            }
        self.emitter.emit(event)

    def _redacted_values(self, feats) -> list[str]:
        """Decoded query/body values for the out-of-band analyst, with values of
        redaction-listed fields removed and each value truncated."""
        names = feats.param_names
        values = feats.query_values + feats.body_values
        out = []
        for name, value in zip(names, values):
            if self.cfg.redact_field(name):
                out.append(f"{name}=<redacted>")
            else:
                out.append(value[:200])
        return out[:50]


class _AuthzHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    engine: Engine = None  # set on the server instance below

    def log_message(self, *args):  # silence default stderr logging
        pass

    def _handle(self):
        length = int(self.headers.get("content-length", 0) or 0)
        body = self.rfile.read(min(length, MAX_BODY)) if length else b""
        try:
            result = self.server.engine.decide(self.command, self.path, dict(self.headers), body)
        except Exception:
            # The engine must not throw at Envoy: return 200 so failure_mode_allow
            # is not even needed for engine bugs (fail open on internal error).
            self._respond(200, {"x-sentinel-verdict": "error-open"}, b"")
            return

        rid = result["request_id"]
        common = {
            "x-sentinel-risk": str(result["risk"]),
            "x-sentinel-intended": result["intended"],
            "x-sentinel-verdict": result["effective"],
        }
        if result["effective"] == "block":
            payload = json.dumps({"error": "blocked by sentinel", "request_id": rid, "risk": result["risk"]}).encode()
            self._respond(403, {**common, "content-type": "application/json"}, payload)
        elif result["effective"] == "challenge":
            payload = challenge.page(rid)
            self._respond(429, {**common, "content-type": "text/html; charset=utf-8",
                                "cache-control": "no-store", "retry-after": "2"}, payload)
        else:
            self._respond(200, common, b"")

    def _respond(self, status: int, headers: dict[str, str], body: bytes):
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle


class _AdminHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/healthz":
            self._text(200, "ok\n")
        elif path == "/metrics":
            self._text(200, self.server.engine_metrics())
        else:
            self._text(404, "not found\n")

    def _text(self, status: int, text: str):
        data = text.encode()
        self.send_response(status)
        self.send_header("content-type", "text/plain; version=0.0.4")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _metrics_text(engine: Engine) -> str:
    lines = ["# HELP sentinel_engine_decisions_total Decisions by effective action.",
             "# TYPE sentinel_engine_decisions_total counter"]
    for action in ensemble.ACTIONS:
        lines.append(f'sentinel_engine_decisions_total{{action="{action}"}} {engine.counters[action]}')
    lines.append(f"sentinel_engine_requests_total {engine.counters['total']}")
    lines.append(f"sentinel_engine_cleared_total {engine.counters.get('cleared', 0)}")
    lines.append(f"sentinel_engine_denylisted_total {engine.counters.get('denylisted', 0)}")
    stats = engine.emitter.stats
    for key, value in stats.items():
        lines.append(f'sentinel_engine_events{{state="{key}"}} {value}')
    return "\n".join(lines) + "\n"


def serve(cfg: appconfig.EngineConfig) -> None:
    emitter = EventEmitter()
    emitter.start()
    engine = Engine(cfg, emitter, ClientState())

    authz = ThreadingHTTPServer(("0.0.0.0", AUTHZ_PORT), _AuthzHandler)
    authz.engine = engine
    admin = ThreadingHTTPServer(("0.0.0.0", ADMIN_PORT), _AdminHandler)
    admin.engine_metrics = lambda: _metrics_text(engine)

    threading.Thread(target=admin.serve_forever, name="admin", daemon=True).start()
    authz.serve_forever()
