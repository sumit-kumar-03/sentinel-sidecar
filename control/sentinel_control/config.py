"""Load, validate and default a sentinel.yaml file.

Validation runs in two passes: the JSON Schema catches structure and type errors,
then semantic checks catch what the schema cannot express (URL parts, CIDRs,
threshold ordering). Every error is collected so a broken file is fixed in one go.
"""

from __future__ import annotations

import copy
import ipaddress
import json
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from jsonschema import Draft202012Validator

DEFAULTS: dict[str, Any] = {
    "upstream": {"timeout_ms": 30000, "connect_timeout_ms": 5000},
    "listen": {
        "port": 8080,
        "metrics_port": 9902,
        "health_path": "/__sentinel/healthz",
        "tls": {"enabled": False},
    },
    "mode": "monitor",
    "profile": "lite",
    "defaults": {
        "on_engine_error": "open",
        "on_timeout": "open",
        "max_inspect_bytes": 65536,
        "crs": {"paranoia": 2, "mode": "score"},
        "thresholds": {"log": 0.4, "challenge": 0.7, "block": 0.85},
        "models": {"m1": 0.4, "m2": 0.2, "m3": 0.2, "m4": 0.0, "crs": 0.2},
    },
    "routes": [],
    "identity": {"client_ip_from": "remote_addr", "trusted_proxies": []},
    "lists": {"allow": [], "deny": []},
    "response_inspection": {"enabled": False, "action": "log"},
    "redaction": {
        "headers": ["authorization", "cookie", "set-cookie", "x-api-key"],
        "body_fields": ["password"],
    },
    "analyst": {
        "enabled": False,
        "auto_actions": {"denylist": True, "threshold_nudge": False, "rules": "propose"},
    },
    "telemetry": {"metrics": "prometheus", "logs": "json"},
}


class ConfigError(Exception):
    """Raised when a config file cannot be loaded; carries every problem found."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("invalid sentinel config:\n" + "\n".join(f"  - {e}" for e in errors))


def _schema() -> dict[str, Any]:
    text = resources.files(__package__).joinpath("schema.json").read_text()
    return json.loads(text)


def _merge(base: Any, override: Any) -> Any:
    """Deep-merge override onto base. Lists and scalars from override replace base."""
    if isinstance(base, dict) and isinstance(override, dict):
        out = dict(base)
        for key, value in override.items():
            out[key] = _merge(base[key], value) if key in base else copy.deepcopy(value)
        return out
    return copy.deepcopy(override)


def _path(parts) -> str:
    return "/".join(str(p) for p in parts) or "<root>"


def _check_network(value: str, where: str, errors: list[str]) -> None:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        errors.append(f"{where}: {value!r} is not a valid IP address or CIDR")


def _semantic_errors(cfg: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    url = urlsplit(cfg["upstream"]["url"])
    if not url.hostname:
        errors.append("upstream/url: missing host")
    try:
        url.port
    except ValueError:
        errors.append("upstream/url: invalid port")
    if url.path not in ("", "/") or url.query or url.fragment:
        errors.append("upstream/url: must be scheme://host[:port] with no path, query or fragment")

    tls = cfg["listen"]["tls"]
    if tls.get("enabled") and not (tls.get("cert") and tls.get("key")):
        errors.append("listen/tls: cert and key are required when tls is enabled")

    for i, cidr in enumerate(cfg["identity"]["trusted_proxies"]):
        _check_network(cidr, f"identity/trusted_proxies/{i}", errors)
    for name in ("allow", "deny"):
        for i, cidr in enumerate(cfg["lists"][name]):
            _check_network(cidr, f"lists/{name}/{i}", errors)

    policies = [("defaults", cfg["defaults"])]
    policies += [(f"routes/{i}", r) for i, r in enumerate(cfg["routes"])]
    for where, policy in policies:
        t = policy.get("thresholds")
        if t and not t["log"] <= t["challenge"] <= t["block"]:
            errors.append(f"{where}/thresholds: must satisfy log <= challenge <= block (got {t})")
        weights = policy.get("models")
        if weights is not None and sum(weights.values()) <= 0:
            errors.append(f"{where}/models: at least one ensemble weight must be > 0")

    for i, route in enumerate(cfg["routes"]):
        match = route["match"]
        if "path_prefix" in match and "path_exact" in match:
            errors.append(f"routes/{i}/match: use either path_prefix or path_exact, not both")
        if not ("path_prefix" in match or "path_exact" in match):
            errors.append(f"routes/{i}/match: path_prefix or path_exact is required")
        if route.get("bypass") and route.get("llm_endpoint"):
            errors.append(f"routes/{i}: a bypass route cannot also be an llm_endpoint")

    if cfg["analyst"]["enabled"] and cfg["profile"] == "full" and "llm" not in cfg["analyst"]:
        errors.append("analyst/llm: required when the analyst is enabled with profile: full")

    return errors


def validate(raw: Any) -> dict[str, Any]:
    """Validate a parsed config document and return it with defaults applied."""
    if not isinstance(raw, dict):
        raise ConfigError(["<root>: config must be a YAML mapping"])

    validator = Draft202012Validator(_schema())
    schema_errors = sorted(validator.iter_errors(raw), key=lambda e: list(e.absolute_path))
    if schema_errors:
        raise ConfigError([f"{_path(e.absolute_path)}: {e.message}" for e in schema_errors])

    cfg = _merge(DEFAULTS, raw)
    # Route policies inherit from defaults; a route only overrides what it names.
    base = {k: v for k, v in cfg["defaults"].items()}
    cfg["routes"] = [_merge(base, route) for route in cfg["routes"]]

    errors = _semantic_errors(cfg)
    if errors:
        raise ConfigError(errors)
    return cfg


def load(path: str | Path) -> dict[str, Any]:
    """Read and validate a sentinel.yaml file."""
    try:
        text = Path(path).read_text()
    except OSError as exc:
        raise ConfigError([f"{path}: {exc.strerror}"]) from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError([f"{path}: YAML parse error: {exc}"]) from exc
    return validate(raw)
