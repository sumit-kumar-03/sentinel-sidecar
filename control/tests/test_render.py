import tempfile
import unittest
from pathlib import Path

import yaml

from sentinel_control import config, render


def rendered(**doc):
    doc.setdefault("upstream", {"url": "http://app:3000"})
    return render.render_envoy(config.validate(doc))


def hcm(bootstrap):
    return bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]


class RenderTests(unittest.TestCase):
    def test_cluster_points_at_upstream(self):
        cluster = rendered()["static_resources"]["clusters"][0]
        addr = cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["socket_address"]
        self.assertEqual((addr["address"], addr["port_value"]), ("app", 3000))
        self.assertNotIn("transport_socket", cluster)

    def test_https_upstream_uses_tls_with_sni(self):
        cluster = rendered(upstream={"url": "https://api.example.com"})["static_resources"]["clusters"][0]
        addr = cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["socket_address"]
        self.assertEqual(addr["port_value"], 443)
        self.assertEqual(cluster["transport_socket"]["typed_config"]["sni"], "api.example.com")

    def test_listener_port_and_timeouts(self):
        doc = rendered(listen={"port": 9000}, upstream={"url": "http://app:3000", "timeout_ms": 1500})
        listener = doc["static_resources"]["listeners"][0]
        self.assertEqual(listener["address"]["socket_address"]["port_value"], 9000)
        routes = hcm(doc)["route_config"]["virtual_hosts"][0]["routes"]
        self.assertEqual(routes[-1]["route"]["timeout"], "1.5s")

    def test_health_route_comes_first_and_is_local(self):
        routes = hcm(rendered())["route_config"]["virtual_hosts"][0]["routes"]
        self.assertEqual(routes[0]["match"], {"path": "/__sentinel/healthz"})
        self.assertIn("direct_response", routes[0])

    def test_admin_is_loopback_only(self):
        self.assertEqual(rendered()["admin"]["address"]["socket_address"]["address"], "127.0.0.1")

    def test_access_log_drops_query_string(self):
        fmt = hcm(rendered())["access_log"][0]["typed_config"]["log_format"]["json_format"]
        self.assertEqual(fmt["path"], "%REQ_WITHOUT_QUERY(:PATH)%")

    def test_tls_listener(self):
        doc = rendered(listen={"tls": {"enabled": True, "cert": "/c.crt", "key": "/c.key"}})
        chain = doc["static_resources"]["listeners"][0]["filter_chains"][0]
        certs = chain["transport_socket"]["typed_config"]["common_tls_context"]["tls_certificates"][0]
        self.assertEqual(certs["certificate_chain"]["filename"], "/c.crt")

    def test_write_is_readable_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "sub" / "envoy.yaml"
            render.write(rendered(), out)
            self.assertEqual(out.stat().st_mode & 0o777, 0o644)
            self.assertIn("static_resources", yaml.safe_load(out.read_text()))


if __name__ == "__main__":
    unittest.main()


def http_filter_names(bootstrap):
    return [f["name"] for f in hcm(bootstrap)["http_filters"]]


def public_routes(bootstrap):
    return hcm(bootstrap)["route_config"]["virtual_hosts"][0]["routes"]


def coraza_value(bootstrap):
    import json
    for f in hcm(bootstrap)["http_filters"]:
        if f["name"] == "envoy.filters.http.wasm":
            return json.loads(f["typed_config"]["config"]["configuration"]["value"])
    return None


class Phase1FilterTests(unittest.TestCase):
    def test_filter_chain_order(self):
        names = http_filter_names(rendered())
        # CRS runs before the engine, and the engine (both fail modes) runs last
        # before the router.
        self.assertIn("envoy.filters.http.wasm", names)
        self.assertLess(names.index("envoy.filters.http.wasm"), names.index("envoy.filters.http.ext_authz.open"))
        self.assertEqual(names[-1], "envoy.filters.http.router")

    def test_coraza_config_is_valid_json_with_engine_off_by_default(self):
        # Default mode is monitor -> DetectionOnly (never blocks).
        directives = coraza_value(rendered())["directives_map"]["sentinel"]
        self.assertIn("SecRuleEngine DetectionOnly", directives)
        self.assertTrue(any("blocking_paranoia_level=2" in d for d in directives))

    def test_coraza_blocks_only_in_enforce_plus_block(self):
        on = coraza_value(rendered(mode="enforce", defaults={"crs": {"mode": "block"}}))
        self.assertIn("SecRuleEngine On", on["directives_map"]["sentinel"])
        # enforce but crs score -> still DetectionOnly
        score = coraza_value(rendered(mode="enforce", defaults={"crs": {"mode": "score"}}))
        self.assertIn("SecRuleEngine DetectionOnly", score["directives_map"]["sentinel"])

    def test_paranoia_level_flows_into_directives(self):
        directives = coraza_value(rendered(defaults={"crs": {"paranoia": 4}}))["directives_map"]["sentinel"]
        self.assertTrue(any("blocking_paranoia_level=4" in d for d in directives))

    def test_rbac_present_only_with_deny_list(self):
        self.assertNotIn("envoy.filters.http.rbac", http_filter_names(rendered()))
        self.assertIn("envoy.filters.http.rbac", http_filter_names(rendered(lists={"deny": ["1.2.3.0/24"]})))

    def test_rbac_enforced_vs_shadow_by_mode(self):
        enf = rendered(mode="enforce", lists={"deny": ["1.2.3.0/24"]})
        mon = rendered(mode="monitor", lists={"deny": ["1.2.3.0/24"]})
        rbac_enf = next(f for f in hcm(enf)["http_filters"] if f["name"] == "envoy.filters.http.rbac")
        rbac_mon = next(f for f in hcm(mon)["http_filters"] if f["name"] == "envoy.filters.http.rbac")
        self.assertIn("rules", rbac_enf["typed_config"])
        self.assertIn("shadow_rules", rbac_mon["typed_config"])

    def test_allowlist_exempts_from_deny(self):
        rbac = next(f for f in hcm(rendered(mode="enforce", lists={"deny": ["1.2.3.0/24"], "allow": ["1.2.3.4/32"]}))["http_filters"]
                    if f["name"] == "envoy.filters.http.rbac")
        principal = rbac["typed_config"]["rules"]["policies"]["sentinel-denylist"]["principals"][0]
        self.assertIn("and_ids", principal)  # deny AND not-allow

    def test_ratelimit_filter_present_only_when_a_route_uses_it(self):
        self.assertNotIn("envoy.filters.http.local_ratelimit", http_filter_names(rendered()))
        doc = rendered(routes=[{"match": {"path_prefix": "/api"}, "rate_limit": {"per_ip": "10/m"}}])
        self.assertIn("envoy.filters.http.local_ratelimit", http_filter_names(doc))

    def test_route_ratelimit_bucket_and_per_ip_action(self):
        doc = rendered(routes=[{"match": {"path_prefix": "/api"}, "rate_limit": {"per_ip": "10/m"}}])
        route = next(r for r in public_routes(doc) if r["match"].get("prefix") == "/api")
        rl = route["typed_per_filter_config"]["envoy.filters.http.local_ratelimit"]
        self.assertEqual(rl["token_bucket"], {"max_tokens": 10, "tokens_per_fill": 10, "fill_interval": "60s"})
        self.assertEqual(rl["rate_limits"][0]["actions"][0]["masked_remote_address"]["v4_prefix_mask_len"], 32)

    def test_ratelimit_shadow_in_monitor(self):
        doc = rendered(mode="monitor", routes=[{"match": {"path_prefix": "/api"}, "rate_limit": {"per_ip": "10/m"}}])
        route = next(r for r in public_routes(doc) if r["match"].get("prefix") == "/api")
        rl = route["typed_per_filter_config"]["envoy.filters.http.local_ratelimit"]
        self.assertEqual(rl["filter_enforced"]["default_value"]["numerator"], 0)

    def test_bypass_route_disables_all_sentinel_filters(self):
        doc = rendered(lists={"deny": ["1.2.3.0/24"]},
                       routes=[{"match": {"path_prefix": "/pub"}, "bypass": True}])
        route = next(r for r in public_routes(doc) if r["match"].get("prefix") == "/pub")
        disabled = route["typed_per_filter_config"]
        self.assertIn("envoy.filters.http.wasm", disabled)
        self.assertIn("envoy.filters.http.rbac", disabled)

    def test_health_route_disables_sentinel_filters(self):
        doc = rendered(lists={"deny": ["1.2.3.0/24"]})
        health = public_routes(doc)[0]
        self.assertEqual(health["match"], {"path": "/__sentinel/healthz"})
        self.assertIn("envoy.filters.http.wasm", health["typed_per_filter_config"])


class MetricsListenerTests(unittest.TestCase):
    def test_metrics_listener_on_configured_port(self):
        listeners = rendered(listen={"metrics_port": 9902})["static_resources"]["listeners"]
        metrics = next(l for l in listeners if l["name"] == "metrics")
        self.assertEqual(metrics["address"]["socket_address"]["port_value"], 9902)

    def test_metrics_only_exposes_prometheus(self):
        listeners = rendered()["static_resources"]["listeners"]
        metrics = next(l for l in listeners if l["name"] == "metrics")
        routes = metrics["filter_chains"][0]["filters"][0]["typed_config"]["route_config"]["virtual_hosts"][0]["routes"]
        paths = {r["match"].get("path", r["match"].get("prefix")) for r in routes}
        self.assertIn("/stats/prometheus", paths)
        catch_all = next(r for r in routes if r["match"].get("prefix") == "/")
        self.assertEqual(catch_all["direct_response"]["status"], 404)

    def test_admin_cluster_is_loopback(self):
        admin = next(c for c in rendered()["static_resources"]["clusters"] if c["name"] == "admin")
        sock = admin["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["socket_address"]
        self.assertEqual((sock["address"], sock["port_value"]), ("127.0.0.1", 9901))


class Phase2EngineTests(unittest.TestCase):
    def test_both_ext_authz_filters_present(self):
        names = http_filter_names(rendered())
        self.assertIn("envoy.filters.http.ext_authz.open", names)
        self.assertIn("envoy.filters.http.ext_authz.closed", names)

    def test_open_filter_fails_open_closed_fails_closed(self):
        by_name = {f["name"]: f for f in hcm(rendered())["http_filters"]}
        self.assertTrue(by_name["envoy.filters.http.ext_authz.open"]["typed_config"]["failure_mode_allow"])
        self.assertFalse(by_name["envoy.filters.http.ext_authz.closed"]["typed_config"]["failure_mode_allow"])

    def test_engine_cluster_present(self):
        engine = next(c for c in rendered()["static_resources"]["clusters"] if c["name"] == "engine")
        sock = engine["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["socket_address"]
        self.assertEqual((sock["address"], sock["port_value"]), ("sentinel-engine", 9000))

    def test_default_route_open_disables_closed(self):
        # defaults.on_engine_error is open -> catch-all keeps open, disables closed.
        catch_all = public_routes(rendered())[-1]
        pf = catch_all["typed_per_filter_config"]
        self.assertIn("envoy.filters.http.ext_authz.closed", pf)
        self.assertNotIn("envoy.filters.http.ext_authz.open", pf)

    def test_route_closed_disables_open(self):
        doc = rendered(routes=[{"match": {"path_prefix": "/login"}, "on_engine_error": "closed"}])
        route = next(r for r in public_routes(doc) if r["match"].get("prefix") == "/login")
        pf = route["typed_per_filter_config"]
        self.assertIn("envoy.filters.http.ext_authz.open", pf)
        self.assertNotIn("envoy.filters.http.ext_authz.closed", pf)

    def test_inspect_false_disables_both_engine_filters(self):
        doc = rendered(routes=[{"match": {"path_prefix": "/static"}, "inspect": False}])
        route = next(r for r in public_routes(doc) if r["match"].get("prefix") == "/static")
        pf = route["typed_per_filter_config"]
        self.assertIn("envoy.filters.http.ext_authz.open", pf)
        self.assertIn("envoy.filters.http.ext_authz.closed", pf)

    def test_with_request_body_uses_max_inspect_bytes(self):
        doc = rendered(defaults={"max_inspect_bytes": 4096})
        f = next(f for f in hcm(doc)["http_filters"] if f["name"] == "envoy.filters.http.ext_authz.open")
        self.assertEqual(f["typed_config"]["with_request_body"]["max_request_bytes"], 4096)


class Phase7ResponseInspectionTests(unittest.TestCase):
    def test_no_lua_by_default(self):
        self.assertNotIn("envoy.filters.http.lua", http_filter_names(rendered()))

    def test_lua_present_when_enabled(self):
        doc = rendered(response_inspection={"enabled": True, "action": "mask"})
        self.assertIn("envoy.filters.http.lua", http_filter_names(doc))

    def test_mask_action_replaces_body(self):
        doc = rendered(response_inspection={"enabled": True, "action": "mask"})
        lua = next(f for f in hcm(doc)["http_filters"] if f["name"] == "envoy.filters.http.lua")
        code = lua["typed_config"]["default_source_code"]["inline_string"]
        self.assertIn("setBytes", code)
        self.assertIn("x-sentinel-leak", code)

    def test_log_action_does_not_replace_body(self):
        doc = rendered(response_inspection={"enabled": True, "action": "log"})
        lua = next(f for f in hcm(doc)["http_filters"] if f["name"] == "envoy.filters.http.lua")
        code = lua["typed_config"]["default_source_code"]["inline_string"]
        self.assertNotIn("setBytes", code)
        self.assertIn("x-sentinel-leak", code)
