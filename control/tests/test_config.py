import unittest
from pathlib import Path

from sentinel_control import config

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"


def minimal(**extra):
    doc = {"upstream": {"url": "http://app:3000"}}
    doc.update(extra)
    return doc


class LoadTests(unittest.TestCase):
    def test_example_config_is_valid(self):
        cfg = config.load(ROOT / "sentinel.example.yaml")
        self.assertEqual(cfg["mode"], "monitor")
        self.assertEqual(len(cfg["routes"]), 3)  # upstream+login+chat(llm_endpoint)+assets -> 3 route entries

    def test_demo_config_is_valid(self):
        config.load(ROOT / "deploy/compose/demo/sentinel.yaml")

    def test_minimal_config_gets_defaults(self):
        cfg = config.validate(minimal())
        self.assertEqual(cfg["listen"]["port"], 8080)
        self.assertEqual(cfg["mode"], "monitor")
        self.assertEqual(cfg["defaults"]["on_engine_error"], "open")
        self.assertEqual(cfg["upstream"]["timeout_ms"], 30000)

    def test_route_inherits_defaults_and_overrides_selectively(self):
        cfg = config.validate(minimal(routes=[
            {"match": {"path_prefix": "/login"}, "on_engine_error": "closed",
             "thresholds": {"log": 0.1, "challenge": 0.2, "block": 0.3}},
        ]))
        route = cfg["routes"][0]
        self.assertEqual(route["on_engine_error"], "closed")
        self.assertEqual(route["on_timeout"], "open")
        self.assertEqual(route["thresholds"]["block"], 0.3)
        self.assertEqual(route["crs"]["paranoia"], 2)

    def test_partial_thresholds_merge_before_ordering_check(self):
        cfg = config.validate(minimal(defaults={"thresholds": {"block": 0.95}}))
        self.assertEqual(cfg["defaults"]["thresholds"], {"log": 0.4, "challenge": 0.7, "block": 0.95})

    def test_missing_file(self):
        with self.assertRaises(config.ConfigError):
            config.load("/nonexistent/sentinel.yaml")


class RejectionTests(unittest.TestCase):
    def assertRejected(self, doc, fragment):
        with self.assertRaises(config.ConfigError) as ctx:
            config.validate(doc)
        joined = "\n".join(ctx.exception.errors)
        self.assertIn(fragment, joined)

    def test_upstream_required(self):
        self.assertRejected({}, "'upstream' is a required property")

    def test_unknown_top_level_key(self):
        self.assertRejected(minimal(surprise=1), "surprise")

    def test_unknown_route_key(self):
        self.assertRejected(minimal(routes=[{"match": {"path_prefix": "/"}, "typo": 1}]), "typo")

    def test_bad_mode(self):
        self.assertRejected(minimal(mode="panic"), "mode")

    def test_upstream_path_rejected(self):
        self.assertRejected({"upstream": {"url": "http://app:3000/api"}}, "no path")

    def test_threshold_ordering(self):
        self.assertRejected(
            minimal(defaults={"thresholds": {"log": 0.9, "challenge": 0.5, "block": 0.8}}),
            "log <= challenge <= block",
        )

    def test_route_needs_path(self):
        self.assertRejected(minimal(routes=[{"match": {"methods": ["GET"]}}]), "path_prefix or path_exact")

    def test_bad_cidr(self):
        self.assertRejected(minimal(lists={"deny": ["not-an-ip"]}), "not a valid IP")

    def test_tls_needs_cert(self):
        self.assertRejected(minimal(listen={"tls": {"enabled": True}}), "cert and key")

    def test_bad_rate(self):
        self.assertRejected(
            minimal(routes=[{"match": {"path_prefix": "/"}, "rate_limit": {"per_ip": "10/day"}}]),
            "per_ip",
        )

    def test_full_profile_analyst_needs_llm(self):
        self.assertRejected(minimal(profile="full", analyst={"enabled": True}), "analyst/llm")

    def test_invalid_fixture_reports_all_schema_errors(self):
        with self.assertRaises(config.ConfigError) as ctx:
            config.load(FIXTURES / "invalid.yaml")
        self.assertGreaterEqual(len(ctx.exception.errors), 4)


if __name__ == "__main__":
    unittest.main()
