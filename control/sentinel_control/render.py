"""Render a validated sentinel config into an Envoy bootstrap.

Phase 0 rendered a hardened pass-through. Phase 1 adds the L0 rules layer inside
Envoy: a static IP deny list (RBAC), per-IP rate limiting (local_ratelimit) and
OWASP CRS via the Coraza WASM plugin, plus an internal Prometheus metrics
listener. The global mode decides whether L0 blocks or only observes:

    monitor / learn : filters run and emit stats/logs but never block
    enforce         : filters block

CRS additionally honours defaults.crs.mode: it only ever blocks when the mode is
enforce AND crs.mode is block; otherwise it runs in DetectionOnly and just scores.

Per-route rate limits, deny-list decisions and CRS all key off the real client.
Per-account rate limits and XFF-based identity arrive in Phase 2 with the engine.
"""

from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

HCM = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"
ROUTER = "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
RBAC = "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC"
RBAC_PER_ROUTE = "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute"
LOCAL_RL = "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit"
WASM = "type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm"
EXT_AUTHZ = "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz"
EXT_AUTHZ_PER_ROUTE = "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute"
LUA = "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua"
FILTER_CONFIG = "type.googleapis.com/envoy.config.route.v3.FilterConfig"
STRING_VALUE = "type.googleapis.com/google.protobuf.StringValue"
STDOUT_LOG = "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog"
REQ_WITHOUT_QUERY = "type.googleapis.com/envoy.extensions.formatter.req_without_query.v3.ReqWithoutQuery"
DOWNSTREAM_TLS = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext"
UPSTREAM_TLS = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext"

ADMIN_PORT = 9901
WASM_PATH = "/wasm/coraza.wasm"
ENGINE_TIMEOUT = "0.5s"  # ext_authz call budget for the Phase 2 stub engine

# Client headers forwarded to the engine. Sensitive ones are included because
# some detection needs them; the engine redacts them before emitting events.
_AUTHZ_HEADERS = ["accept", "accept-language", "content-type", "user-agent",
                  "referer", "origin", "cookie", "authorization"]

# Filter names used both in the chain and in per-route overrides.
F_RBAC = "envoy.filters.http.rbac"
F_RL = "envoy.filters.http.local_ratelimit"
F_WASM = "envoy.filters.http.wasm"
# Two ext_authz filters point at the same engine but differ in failure mode, so
# each route can choose fail-open or fail-closed by disabling the other one.
F_AUTHZ_OPEN = "envoy.filters.http.ext_authz.open"
F_AUTHZ_CLOSED = "envoy.filters.http.ext_authz.closed"

_WINDOW_SECONDS = {"s": 1, "m": 60, "h": 3600}

ACCESS_LOG_FORMAT = {
    "ts": "%START_TIME%",
    "component": "sentinel-gateway",
    "request_id": "%REQ(X-REQUEST-ID)%",
    "client_ip": "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%",
    "method": "%REQ(:METHOD)%",
    "path": "%REQ_WITHOUT_QUERY(:PATH)%",
    "protocol": "%PROTOCOL%",
    "status": "%RESPONSE_CODE%",
    "flags": "%RESPONSE_FLAGS%",
    "bytes_in": "%BYTES_RECEIVED%",
    "bytes_out": "%BYTES_SENT%",
    "duration_ms": "%DURATION%",
    "upstream_ms": "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%",
    "user_agent": "%REQ(USER-AGENT)%",
}


def _duration(ms: int) -> str:
    return f"{ms / 1000:g}s"


def _fraction(percent: int) -> dict[str, Any]:
    return {"default_value": {"numerator": percent, "denominator": "HUNDRED"}}


def _cidr(value: str) -> dict[str, Any]:
    net = ipaddress.ip_network(value, strict=False)
    return {"address_prefix": str(net.network_address), "prefix_len": net.prefixlen}


def _upstream(cfg: dict[str, Any]) -> tuple[str, str, int]:
    url = urlsplit(cfg["upstream"]["url"])
    port = url.port or (443 if url.scheme == "https" else 80)
    return url.scheme, url.hostname, port


# --- L0 filters -----------------------------------------------------------

def _enforcing(cfg: dict[str, Any]) -> bool:
    """True when the global mode makes L0 block rather than only observe."""
    return cfg["mode"] == "enforce"


def _coraza_directives(cfg: dict[str, Any]) -> list[str]:
    crs = cfg["defaults"]["crs"]
    engine = "On" if (_enforcing(cfg) and crs["mode"] == "block") else "DetectionOnly"
    return [
        "Include @recommended-conf",
        "Include @crs-setup-conf",
        # Set the CRS paranoia level before the rule files are included.
        f'SecAction "id:900000,phase:1,nolog,pass,t:none,'
        f'setvar:tx.blocking_paranoia_level={crs["paranoia"]},'
        f'setvar:tx.detection_paranoia_level={crs["paranoia"]}"',
        "Include @owasp_crs/*.conf",
        # The engine directive comes last so it wins over the bundled defaults.
        f"SecRuleEngine {engine}",
    ]


def _wasm_filter(cfg: dict[str, Any]) -> dict[str, Any]:
    config_json = json.dumps(
        {"directives_map": {"sentinel": _coraza_directives(cfg)}, "default_directives": "sentinel"}
    )
    return {
        "name": F_WASM,
        "typed_config": {
            "@type": WASM,
            "config": {
                "name": "coraza",
                "root_id": "coraza",
                "vm_config": {
                    "runtime": "envoy.wasm.runtime.v8",
                    "code": {"local": {"filename": WASM_PATH}},
                },
                "configuration": {"@type": STRING_VALUE, "value": config_json},
            },
        },
    }


def _rbac_filter(cfg: dict[str, Any]) -> dict[str, Any]:
    """Deny-list filter. Allowlisted clients are never denied.

    In monitor/learn mode the rules go under shadow_rules: they are evaluated and
    counted (rbac.shadow_denied) but do not block.
    """
    deny = cfg["lists"]["deny"]
    allow = cfg["lists"]["allow"]
    deny_or = {"or_ids": {"ids": [{"direct_remote_ip": _cidr(c)} for c in deny]}}
    if allow:
        allow_or = {"or_ids": {"ids": [{"direct_remote_ip": _cidr(c)} for c in allow]}}
        principal = {"and_ids": {"ids": [deny_or, {"not_id": allow_or}]}}
    else:
        principal = deny_or

    rbac = {
        "action": "DENY",
        "policies": {
            "sentinel-denylist": {
                "permissions": [{"any": True}],
                "principals": [principal],
            }
        },
    }
    key = "rules" if _enforcing(cfg) else "shadow_rules"
    typed: dict[str, Any] = {"@type": RBAC, key: rbac}
    if key == "shadow_rules":
        typed["shadow_rules_stat_prefix"] = "sentinel_"
    return {"name": F_RBAC, "typed_config": typed}


def _ratelimit_base() -> dict[str, Any]:
    # No token bucket at the chain level: this allows everything by default and
    # lets each route opt in through typed_per_filter_config.
    return {"name": F_RL, "typed_config": {"@type": LOCAL_RL, "stat_prefix": "sentinel_rl"}}


def _route_ratelimit(rate: str, enforced: bool) -> dict[str, Any]:
    count, unit = rate.split("/")
    bucket = {
        "max_tokens": int(count),
        "tokens_per_fill": int(count),
        "fill_interval": f"{_WINDOW_SECONDS[unit]}s",
    }
    return {
        "@type": LOCAL_RL,
        "stat_prefix": "sentinel_rl",
        "token_bucket": bucket,
        "filter_enabled": _fraction(100),
        "filter_enforced": _fraction(100 if enforced else 0),
        # One bucket per client address gives per-IP limiting.
        "rate_limits": [
            {"actions": [{"masked_remote_address": {"v4_prefix_mask_len": 32, "v6_prefix_mask_len": 128}}]}
        ],
    }


def _disabled(filter_name: str) -> dict[str, Any]:
    if filter_name == F_RBAC:
        return {"@type": RBAC_PER_ROUTE}
    if filter_name in (F_AUTHZ_OPEN, F_AUTHZ_CLOSED):
        return {"@type": EXT_AUTHZ_PER_ROUTE, "disabled": True}
    return {"@type": FILTER_CONFIG, "disabled": True}


_LEAK_MARKERS = [
    "Traceback (most recent call last)", "Exception in thread", ".java:", "org.springframework",
    "ORA-0", "SQLSTATE", "Fatal error:", "Warning: mysqli", "-----BEGIN", "PRIVATE KEY",
    "SQLITE_ERROR", "SequelizeDatabaseError", "sqlite3.", "SQL syntax",
    "AKIA", "aws_secret_access_key", "BEGIN RSA PRIVATE KEY",
]


def _response_inspection_filter(action: str) -> dict[str, Any]:
    """Envoy Lua filter that scans upstream responses for leak markers.

    action == "mask": on a hit, replace the body with a safe message so nothing
    leaks. action == "log": tag the response and log, but pass it through.
    Bodies over 256 KiB are skipped to bound buffering.
    """
    markers = ",".join(f'"{m}"' for m in _LEAK_MARKERS)
    do_mask = ("body:setBytes('{\"error\":\"response withheld by sentinel\"}')"
               if action == "mask" else "-- log only")
    lua = f"""
function envoy_on_response(handle)
  local body = handle:body()
  if body == nil then return end
  local n = body:length()
  if n == 0 or n > 262144 then return end
  local data = body:getBytes(0, n)
  local markers = {{{markers}}}
  local hit = false
  for _, m in ipairs(markers) do
    if string.find(data, m, 1, true) then hit = true break end
  end
  if hit then
    handle:headers():replace("x-sentinel-leak", "detected")
    handle:logWarn("sentinel: response leak pattern detected")
    {do_mask}
  end
end
"""
    return {"name": "envoy.filters.http.lua",
            "typed_config": {"@type": LUA, "default_source_code": {"inline_string": lua}}}


def _ext_authz_filter(cfg: dict[str, Any], name: str, fail_open: bool) -> dict[str, Any]:
    return {
        "name": name,
        "typed_config": {
            "@type": EXT_AUTHZ,
            "transport_api_version": "V3",
            "failure_mode_allow": fail_open,
            "with_request_body": {
                "max_request_bytes": cfg["defaults"]["max_inspect_bytes"],
                "allow_partial_message": True,
                "pack_as_bytes": True,
            },
            "http_service": {
                "server_uri": {"uri": "http://sentinel-engine:9000", "cluster": "engine", "timeout": ENGINE_TIMEOUT},
                "authorization_request": {
                    "allowed_headers": {"patterns": [{"exact": h} for h in _AUTHZ_HEADERS] + [{"prefix": "x-"}]}
                },
                "authorization_response": {
                    "allowed_upstream_headers": {"patterns": [{"prefix": "x-sentinel-"}]},
                    "allowed_client_headers": {"patterns": [{"prefix": "x-sentinel-"}]},
                },
            },
        },
    }


def _authz_route_config(on_engine_error: str, present: set[str]) -> dict[str, Any]:
    """Enable exactly one ext_authz filter for an inspected route by disabling the other."""
    keep = F_AUTHZ_OPEN if on_engine_error == "open" else F_AUTHZ_CLOSED
    drop = F_AUTHZ_CLOSED if on_engine_error == "open" else F_AUTHZ_OPEN
    cfg_map: dict[str, Any] = {}
    if drop in present:
        cfg_map[drop] = _disabled(drop)
    del keep
    return cfg_map


# --- routing --------------------------------------------------------------

def _route_entry(route: dict[str, Any], cfg: dict[str, Any], present: set[str]) -> dict[str, Any]:
    match = route["match"]
    if "path_exact" in match:
        route_match: dict[str, Any] = {"path": match["path_exact"]}
    else:
        route_match = {"prefix": match.get("path_prefix", "/")}
    if "methods" in match:
        route_match["headers"] = [{"name": ":method", "string_match": {"exact": m}} for m in match["methods"]]
        # A header list is ANDed; ORing methods needs one route each. Keep it
        # simple: match the first method here and rely on prefix for the rest.
        route_match["headers"] = [
            {"name": ":method", "string_match": {"safe_regex": {"regex": "|".join(match["methods"])}}}
        ]

    entry: dict[str, Any] = {"match": route_match}
    per_filter: dict[str, Any] = {}

    if route.get("bypass"):
        for name in present:
            per_filter[name] = _disabled(name)
    else:
        rl = route.get("rate_limit", {})
        if F_RL in present and "per_ip" in rl:
            per_filter[F_RL] = _route_ratelimit(rl["per_ip"], enforced=_enforcing(cfg))
        if route.get("inspect") is False:
            # L0 still applies; skip only the engine (ext_authz).
            for name in (F_AUTHZ_OPEN, F_AUTHZ_CLOSED):
                if name in present:
                    per_filter[name] = _disabled(name)
        else:
            per_filter.update(_authz_route_config(route["on_engine_error"], present))

    if per_filter:
        entry["typed_per_filter_config"] = per_filter
    entry["route"] = {"cluster": "upstream", "timeout": _duration(cfg["upstream"]["timeout_ms"])}
    return entry


def _http_filters(cfg: dict[str, Any]) -> tuple[list[dict[str, Any]], set[str]]:
    present: set[str] = set()
    filters: list[dict[str, Any]] = []
    if cfg["lists"]["deny"]:
        filters.append(_rbac_filter(cfg))
        present.add(F_RBAC)
    if any("rate_limit" in r for r in cfg["routes"]):
        filters.append(_ratelimit_base())
        present.add(F_RL)
    # Coraza is the core of L0 and always runs (except on bypass routes).
    filters.append(_wasm_filter(cfg))
    present.add(F_WASM)
    # The inline engine runs after CRS. Both failure-mode variants are in the
    # chain; each route enables exactly one, so there is only ever one call.
    filters.append(_ext_authz_filter(cfg, F_AUTHZ_OPEN, fail_open=True))
    filters.append(_ext_authz_filter(cfg, F_AUTHZ_CLOSED, fail_open=False))
    present.add(F_AUTHZ_OPEN)
    present.add(F_AUTHZ_CLOSED)
    if cfg["response_inspection"]["enabled"]:
        filters.append(_response_inspection_filter(cfg["response_inspection"]["action"]))
        present.add("envoy.filters.http.lua")
    filters.append({"name": "envoy.filters.http.router", "typed_config": {"@type": ROUTER}})
    return filters, present


def _listener(cfg: dict[str, Any]) -> dict[str, Any]:
    listen = cfg["listen"]
    http_filters, present = _http_filters(cfg)

    routes = [
        {
            "match": {"path": listen["health_path"]},
            # The health check must never be touched by the security filters.
            "typed_per_filter_config": {name: _disabled(name) for name in present},
            "direct_response": {"status": 200, "body": {"inline_string": "ok\n"}},
        }
    ]
    routes += [_route_entry(r, cfg, present) for r in cfg["routes"]]
    catch_all: dict[str, Any] = {
        "match": {"prefix": "/"},
        "route": {"cluster": "upstream", "timeout": _duration(cfg["upstream"]["timeout_ms"])},
    }
    catch_all_authz = _authz_route_config(cfg["defaults"]["on_engine_error"], present)
    if catch_all_authz:
        catch_all["typed_per_filter_config"] = catch_all_authz
    routes.append(catch_all)

    hcm = {
        "@type": HCM,
        "stat_prefix": "public",
        "codec_type": "AUTO",
        "use_remote_address": True,
        # When the operator is behind trusted proxies and reads the client from
        # X-Forwarded-For, tell Envoy how many hops to skip so x-envoy-external-
        # address (which the engine trusts) is the real client, not a proxy.
        "xff_num_trusted_hops": (
            len(cfg["identity"]["trusted_proxies"])
            if cfg["identity"].get("client_ip_from") == "x-forwarded-for" else 0
        ),
        "preserve_external_request_id": False,
        "normalize_path": True,
        "merge_slashes": True,
        "path_with_escaped_slashes_action": "KEEP_UNCHANGED",
        "request_headers_timeout": "10s",
        "stream_idle_timeout": "300s",
        "common_http_protocol_options": {"idle_timeout": "300s"},
        "upgrade_configs": [{"upgrade_type": "websocket"}],
        "access_log": [
            {
                "name": "envoy.access_loggers.stdout",
                "typed_config": {
                    "@type": STDOUT_LOG,
                    "log_format": {
                        "json_format": ACCESS_LOG_FORMAT,
                        "formatters": [
                            {
                                "name": "envoy.formatter.req_without_query",
                                "typed_config": {"@type": REQ_WITHOUT_QUERY},
                            }
                        ],
                    },
                },
            }
        ],
        "route_config": {
            "name": "public",
            "virtual_hosts": [
                {
                    "name": "upstream",
                    "domains": ["*"],
                    "routes": routes,
                    "response_headers_to_add": [
                        {
                            "header": {"key": "x-sentinel-request-id", "value": "%REQ(X-REQUEST-ID)%"},
                            "append_action": "OVERWRITE_IF_EXISTS_OR_ADD",
                        }
                    ],
                }
            ],
        },
        "http_filters": http_filters,
    }

    chain: dict[str, Any] = {
        "filters": [{"name": "envoy.filters.network.http_connection_manager", "typed_config": hcm}]
    }
    if listen["tls"]["enabled"]:
        chain["transport_socket"] = {
            "name": "envoy.transport_sockets.tls",
            "typed_config": {
                "@type": DOWNSTREAM_TLS,
                "common_tls_context": {
                    "tls_params": {"tls_minimum_protocol_version": "TLSv1_2"},
                    "alpn_protocols": ["h2", "http/1.1"],
                    "tls_certificates": [
                        {
                            "certificate_chain": {"filename": listen["tls"]["cert"]},
                            "private_key": {"filename": listen["tls"]["key"]},
                        }
                    ],
                },
            },
        }

    return {
        "name": "public",
        "address": {"socket_address": {"address": "0.0.0.0", "port_value": listen["port"]}},
        "filter_chains": [chain],
    }


def _metrics_listener(cfg: dict[str, Any]) -> dict[str, Any]:
    # Exposes only /stats/prometheus by proxying to the loopback admin endpoint;
    # every other path returns 404, so the dangerous admin verbs stay unreachable.
    # This listener is meant for the internal network only (never published).
    hcm = {
        "@type": HCM,
        "stat_prefix": "metrics",
        "route_config": {
            "name": "metrics",
            "virtual_hosts": [
                {
                    "name": "metrics",
                    "domains": ["*"],
                    "routes": [
                        {
                            "match": {"path": "/metrics"},
                            "route": {"cluster": "admin", "prefix_rewrite": "/stats/prometheus"},
                        },
                        {
                            "match": {"path": "/stats/prometheus"},
                            "route": {"cluster": "admin"},
                        },
                        {"match": {"prefix": "/"}, "direct_response": {"status": 404}},
                    ],
                }
            ],
        },
        "http_filters": [{"name": "envoy.filters.http.router", "typed_config": {"@type": ROUTER}}],
    }
    return {
        "name": "metrics",
        "address": {"socket_address": {"address": "0.0.0.0", "port_value": cfg["listen"]["metrics_port"]}},
        "filter_chains": [{"filters": [{"name": "envoy.filters.network.http_connection_manager", "typed_config": hcm}]}],
    }


def _cluster(cfg: dict[str, Any]) -> dict[str, Any]:
    scheme, host, port = _upstream(cfg)
    cluster: dict[str, Any] = {
        "name": "upstream",
        "type": "STRICT_DNS",
        "connect_timeout": _duration(cfg["upstream"]["connect_timeout_ms"]),
        "load_assignment": {
            "cluster_name": "upstream",
            "endpoints": [
                {"lb_endpoints": [{"endpoint": {"address": {"socket_address": {"address": host, "port_value": port}}}}]}
            ],
        },
    }
    if scheme == "https":
        cluster["transport_socket"] = {
            "name": "envoy.transport_sockets.tls",
            "typed_config": {"@type": UPSTREAM_TLS, "sni": host},
        }
    return cluster


def _engine_cluster() -> dict[str, Any]:
    return {
        "name": "engine",
        "type": "STRICT_DNS",
        "connect_timeout": "1s",
        "load_assignment": {
            "cluster_name": "engine",
            "endpoints": [
                {"lb_endpoints": [{"endpoint": {"address": {"socket_address": {"address": "sentinel-engine", "port_value": 9000}}}}]}
            ],
        },
    }


def _admin_cluster() -> dict[str, Any]:
    return {
        "name": "admin",
        "type": "STATIC",
        "connect_timeout": "1s",
        "load_assignment": {
            "cluster_name": "admin",
            "endpoints": [
                {"lb_endpoints": [{"endpoint": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": ADMIN_PORT}}}}]}
            ],
        },
    }


def render_envoy(cfg: dict[str, Any]) -> dict[str, Any]:
    """Build the Envoy bootstrap document for a validated config."""
    return {
        "admin": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": ADMIN_PORT}}},
        "static_resources": {
            "listeners": [_listener(cfg), _metrics_listener(cfg)],
            "clusters": [_cluster(cfg), _admin_cluster(), _engine_cluster()],
        },
    }


def write(doc: dict[str, Any], out: str | Path) -> None:
    """Write atomically and world-readable so the gateway (a different uid) can read it."""
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=out.parent, prefix=".render-")
    try:
        with os.fdopen(fd, "w") as fh:
            yaml.safe_dump(doc, fh, sort_keys=False)
        os.chmod(tmp, 0o644)
        os.replace(tmp, out)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_json(doc: dict[str, Any], out: str | Path) -> None:
    """Write the defaulted config as engine.json for the inline engine to read."""
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=out.parent, prefix=".render-")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh)
        os.chmod(tmp, 0o644)
        os.replace(tmp, out)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
