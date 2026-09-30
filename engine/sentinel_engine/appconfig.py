"""Load the rendered engine config and match a request to its route policy.

The config is the fully-defaulted sentinel config that the control plane writes
as engine.json, so the engine never re-validates; it only reads. Route matching
mirrors the renderer: first matching route wins, otherwise the defaults apply.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any

CONFIG_PATH = os.environ.get("SENTINEL_ENGINE_CONFIG", "/rendered/engine.json")


class EngineConfig:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.mode: str = cfg["mode"]
        self.defaults: dict[str, Any] = cfg["defaults"]
        self.routes: list[dict[str, Any]] = cfg["routes"]
        self.redaction: dict[str, Any] = cfg["redaction"]
        self.identity: dict[str, Any] = cfg.get("identity", {})
        self._allow = []
        for c in cfg.get("lists", {}).get("allow", []):
            try:
                self._allow.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass
        self._redact_headers = {h.lower() for h in self.redaction.get("headers", [])}
        self._redact_fields = {f.lower() for f in self.redaction.get("body_fields", [])}

    def match(self, method: str, path: str) -> dict[str, Any]:
        """Return the policy for the first route matching method+path, else defaults."""
        for route in self.routes:
            m = route["match"]
            if "path_exact" in m:
                if path != m["path_exact"]:
                    continue
            elif "path_prefix" in m:
                if not path.startswith(m["path_prefix"]):
                    continue
            if "methods" in m and method.upper() not in {x.upper() for x in m["methods"]}:
                continue
            return route
        return self.defaults

    def redact_headers(self, headers: dict[str, str]) -> dict[str, str]:
        return {k: ("<redacted>" if k.lower() in self._redact_headers else v) for k, v in headers.items()}

    def redact_field(self, name: str) -> bool:
        return name.lower() in self._redact_fields


    def is_allowlisted(self, ip: str) -> bool:
        if not ip or not self._allow:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._allow)


def load(path: str | Path = CONFIG_PATH) -> EngineConfig:
    return EngineConfig(json.loads(Path(path).read_text()))
