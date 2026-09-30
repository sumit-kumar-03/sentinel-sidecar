"""Turn analyst findings into bounded, audited actions.

An M5 block/challenge verdict or a slow-scan campaign becomes a dynamic denylist
entry the engine enforces inline (Redis key dyn:deny:{ip} with a TTL). Guardrails:
never touch an allowlisted IP; TTLs escalate on repeat offenders but are capped;
every action is written to an audit stream; and everything is gated by config
(auto_actions.denylist and auto_actions.rules). When not auto-applying, the same
finding is recorded as a proposal for human review instead.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time

AUDIT = os.environ.get("SENTINEL_AUDIT_STREAM", "sentinel:audit")
PROPOSALS = os.environ.get("SENTINEL_PROPOSAL_STREAM", "sentinel:proposals")
BASE_TTL = int(os.environ.get("SENTINEL_DENY_TTL", "3600"))
TTL_CAP_MULT = int(os.environ.get("SENTINEL_DENY_TTL_CAP", "24"))
STREAM_MAXLEN = int(os.environ.get("SENTINEL_AUDIT_MAXLEN", "50000"))
MIN_CONFIDENCE = float(os.environ.get("SENTINEL_APPLY_CONFIDENCE", "0.7"))


class Applier:
    def __init__(self, redis_client, cfg):
        self.r = redis_client
        self.cfg = cfg
        allow = cfg.cfg.get("lists", {}).get("allow", []) if hasattr(cfg, "cfg") else []
        self._allow = []
        for c in allow:
            try:
                self._allow.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass
        auto = (cfg.cfg.get("analyst", {}) if hasattr(cfg, "cfg") else {}).get("auto_actions", {})
        self.denylist_enabled = bool(auto.get("denylist", False))
        self.rules_mode = auto.get("rules", "propose")   # propose | apply | off
        self.counters = {"denies": 0, "proposals": 0, "skipped_allow": 0}

    def _allowlisted(self, ip: str) -> bool:
        if not ip or not self._allow:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self._allow)

    def _audit(self, record: dict) -> None:
        record["ts"] = time.time()
        self.r.xadd(AUDIT, {"json": json.dumps(record)}, maxlen=STREAM_MAXLEN, approximate=True)

    def _propose(self, record: dict) -> None:
        record["ts"] = time.time()
        self.r.xadd(PROPOSALS, {"json": json.dumps(record)}, maxlen=STREAM_MAXLEN, approximate=True)
        self.counters["proposals"] += 1

    def _deny_ip(self, ip: str, action: str, reason: str, source: str) -> None:
        # Escalating, capped TTL for repeat offenders.
        try:
            count = int(self.r.incr(f"dyn:deny:count:{ip}"))
            self.r.expire(f"dyn:deny:count:{ip}", BASE_TTL * TTL_CAP_MULT)
        except Exception:
            count = 1
        ttl = BASE_TTL * min(count, TTL_CAP_MULT)
        payload = json.dumps({"action": action, "reason": reason, "source": source})
        self.r.set(f"dyn:deny:{ip}", payload, ex=ttl)
        self.counters["denies"] += 1
        self._audit({"action": "deny", "target_ip": ip, "block_action": action,
                     "reason": reason, "source": source, "ttl": ttl, "offense": count})

    def on_verdict(self, record: dict) -> None:
        verdict = record.get("verdict", {})
        ip = record.get("client_ip")
        action = verdict.get("recommended_action")
        conf = verdict.get("confidence", 0.0)
        if action not in ("block", "challenge") or conf < MIN_CONFIDENCE or not ip:
            return
        reason = f"m5:{verdict.get('attack_type', 'other')}"
        self._apply_or_propose(ip, action, reason, "m5", conf, record.get("path"))

    def on_campaign(self, alert: dict) -> None:
        if alert.get("type") == "slow_scan" and alert.get("client_ip"):
            self._apply_or_propose(alert["client_ip"], "challenge", "campaign:slow_scan",
                                   "correlator", 1.0, None)
        elif alert.get("type") == "distributed_stuffing":
            # Many IPs; do not mass-block automatically -- always a proposal.
            self._propose({"kind": "rate_limit_route", "route": alert.get("route"),
                           "reason": "campaign:distributed_stuffing", "detail": alert})

    def _apply_or_propose(self, ip: str, action: str, reason: str, source: str,
                          confidence: float, path: str | None) -> None:
        if self._allowlisted(ip):
            self.counters["skipped_allow"] += 1
            self._audit({"action": "skip_allowlisted", "target_ip": ip, "reason": reason})
            return
        if self.denylist_enabled and self.rules_mode == "apply":
            self._deny_ip(ip, action, reason, source)
        else:
            self._propose({"kind": "deny", "target_ip": ip, "block_action": action,
                           "reason": reason, "source": source, "confidence": confidence, "path": path})
