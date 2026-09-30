"""Extract a feature bundle from an ext_authz request.

The bundle is shared by every scorer so decoding and parsing happen once. Phase
2 collects the fields the heuristic scorer needs plus structure the real models
will use later: the decoded values from the path, query and body, and a small
set of request-shape signals.
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any


def _multi_decode(value: str, rounds: int = 2) -> str:
    """URL-decode a couple of times so simple double-encoding is unwrapped."""
    seen = value
    for _ in range(rounds):
        decoded = urllib.parse.unquote_plus(seen)
        if decoded == seen:
            break
        seen = decoded
    return seen


@dataclass
class Features:
    method: str
    path: str                      # path only, no query
    raw_path: str                  # original :path (may include query)
    query_values: list[str] = field(default_factory=list)
    body_values: list[str] = field(default_factory=list)
    param_names: list[str] = field(default_factory=list)
    content_type: str = ""
    user_agent: str = ""
    referer: str = ""
    accept: str = ""
    accept_language: str = ""
    cookie: str = ""
    client_ip: str = ""
    body_len: int = 0
    path_depth: int = 0

    def scan_values(self) -> list[str]:
        """All attacker-controllable strings a scorer should inspect."""
        return [_multi_decode(self.path), *self.query_values, *self.body_values]


def _parse_query(raw_path: str) -> tuple[str, list[str], list[str]]:
    parts = urllib.parse.urlsplit(raw_path)
    names, values = [], []
    for name, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        names.append(name)
        values.append(_multi_decode(value))
    return parts.path, names, values


def _parse_body(body: bytes, content_type: str) -> tuple[list[str], list[str]]:
    names: list[str] = []
    values: list[str] = []
    if not body:
        return names, values
    text = body.decode("utf-8", "replace")
    ctype = content_type.split(";", 1)[0].strip().lower()
    if ctype == "application/json":
        try:
            names, values = _walk_json(json.loads(text))
        except (ValueError, RecursionError):
            values = [text]
    elif ctype == "application/x-www-form-urlencoded":
        for name, value in urllib.parse.parse_qsl(text, keep_blank_values=True):
            names.append(name)
            values.append(_multi_decode(value))
    else:
        values = [text]
    return names, values


def _walk_json(obj: Any, names: list[str] | None = None, values: list[str] | None = None):
    names = names if names is not None else []
    values = values if values is not None else []
    if isinstance(obj, dict):
        for key, val in obj.items():
            names.append(str(key))
            _walk_json(val, names, values)
    elif isinstance(obj, list):
        for item in obj:
            _walk_json(item, names, values)
    elif isinstance(obj, str):
        values.append(obj)
    elif obj is not None:
        values.append(str(obj))
    return names, values


def resolve_client_ip(lower: dict[str, str], identity: dict | None) -> str:
    """Resolve the client IP from Envoy's trusted determination, never from the
    client-controllable X-Forwarded-For chain.

    Envoy (use_remote_address) sets x-envoy-external-address to the trusted client
    address after applying xff_num_trusted_hops, and strips x-envoy-* headers sent
    by external clients, so it cannot be spoofed. XFF[0] can be, so we never use it.
    """
    mode = (identity or {}).get("client_ip_from", "remote_addr")
    if mode == "cf-connecting-ip":
        # Operator asserts Cloudflare is in front; trust its header, else fall back.
        return lower.get("cf-connecting-ip", "") or lower.get("x-envoy-external-address", "")
    # remote_addr and x-forwarded-for both rely on Envoy's computed trusted address;
    # for x-forwarded-for the renderer sets xff_num_trusted_hops so Envoy skips the
    # operator's own proxies when computing it.
    return lower.get("x-envoy-external-address", "")


def extract(method: str, raw_path: str, headers: dict[str, str], body: bytes,
            identity: dict | None = None) -> Features:
    lower = {k.lower(): v for k, v in headers.items()}
    path, q_names, q_values = _parse_query(raw_path)
    content_type = lower.get("content-type", "")
    b_names, b_values = _parse_body(body, content_type)
    client_ip = resolve_client_ip(lower, identity)
    return Features(
        method=method,
        path=path,
        raw_path=raw_path,
        query_values=q_values,
        body_values=b_values,
        param_names=q_names + b_names,
        content_type=content_type,
        user_agent=lower.get("user-agent", ""),
        referer=lower.get("referer", ""),
        accept=lower.get("accept", ""),
        accept_language=lower.get("accept-language", ""),
        cookie=lower.get("cookie", ""),
        client_ip=client_ip,
        body_len=len(body),
        path_depth=path.count("/"),
    )
