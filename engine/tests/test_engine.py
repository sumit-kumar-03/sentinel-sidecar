import time
import unittest

from sentinel_engine import appconfig, challenge, ensemble, features
from sentinel_engine.scorers import BehaviorM2, BotM3, Context, HeuristicM1, default_scorers


DEFAULT_POLICY = {
    "thresholds": {"log": 0.4, "challenge": 0.7, "block": 0.85},
    "models": {"m1": 0.4, "m2": 0.2, "m3": 0.2, "m4": 0.0, "crs": 0.2},
}


def ctx(raw_path="/x", method="GET", headers=None, body=b"", state=None):
    f = features.extract(method, raw_path, headers or {}, body)
    return Context(features=f, state=state)


def cfg(mode="enforce", routes=None):
    doc = {"mode": mode, "defaults": {**DEFAULT_POLICY}, "routes": routes or [],
           "redaction": {"headers": ["authorization", "cookie"], "body_fields": ["password"]}}
    return appconfig.EngineConfig(doc)


class FeatureTests(unittest.TestCase):
    def test_query_and_path_split(self):
        f = features.extract("GET", "/rest/search?q=apple&n=2", {}, b"")
        self.assertEqual(f.path, "/rest/search")
        self.assertIn("apple", f.query_values)

    def test_double_url_decoding(self):
        f = features.extract("GET", "/x?q=%2527%20OR%25201=1", {}, b"")
        self.assertTrue(any("' OR 1=1" in v for v in f.query_values))

    def test_json_body_values(self):
        f = features.extract("POST", "/api", {"content-type": "application/json"},
                             b'{"user":"a","nested":{"q":"<script>"}}')
        self.assertIn("<script>", f.body_values)

    def test_headers_captured(self):
        f = features.extract("GET", "/", {"user-agent": "curl/8", "accept": "*/*",
                                          "cookie": "a=1"}, b"")
        self.assertEqual(f.user_agent, "curl/8")
        self.assertEqual(f.accept, "*/*")
        self.assertEqual(f.cookie, "a=1")


class HeuristicScorerTests(unittest.TestCase):
    def setUp(self):
        self.m1 = HeuristicM1()

    def test_benign_low(self):
        self.assertEqual(self.m1.score(ctx("/rest/search?q=apple")), 0.0)

    def test_sqli_hard_block(self):
        c = ctx("/rest/search?q=1' OR 1=1")
        sc = self.m1.score(c)
        self.assertGreaterEqual(sc, 0.9)
        self.assertEqual(self.m1.hard(c, sc), "block")


class BotM3Tests(unittest.TestCase):
    def setUp(self):
        self.m3 = BotM3()

    def test_scanner_ua_hard_block(self):
        c = ctx(headers={"user-agent": "Fuzz Faster U Fool v2.1.0-dev"})  # ffuf real UA, no literal ffuf
        self.assertEqual(self.m3.hard(c, self.m3.score(c)), "block")

    def test_sqlmap_ua_hard_block(self):
        c = ctx(headers={"user-agent": "sqlmap/1.8"})
        self.assertEqual(self.m3.hard(c, self.m3.score(c)), "block")

    def test_generic_bot_soft_not_hard(self):
        c = ctx(headers={"user-agent": "python-requests/2.31"})
        self.assertGreater(self.m3.score(c), 0.4)
        self.assertIsNone(self.m3.hard(c, self.m3.score(c)))

    def test_browser_low(self):
        c = ctx(headers={"user-agent": "Mozilla/5.0 (X11) Firefox/120", "accept": "text/html",
                         "accept-language": "en-US"})
        self.assertLess(self.m3.score(c), 0.3)
        self.assertIsNone(self.m3.hard(c, self.m3.score(c)))

    def test_missing_ua(self):
        self.assertGreater(self.m3.score(ctx(headers={})), 0.5)


class BehaviorM2Tests(unittest.TestCase):
    def setUp(self):
        self.m2 = BehaviorM2()

    def test_abstains_without_state(self):
        self.assertEqual(self.m2.score(ctx()), 0.0)
        self.assertIsNone(self.m2.hard(ctx(), 0.0))

    def test_high_fanout_hard_challenge(self):
        c = ctx(state={"rate": 50, "fanout": 45, "novelty": 0.0})
        self.assertEqual(self.m2.hard(c, self.m2.score(c)), "challenge")

    def test_normal_window_low(self):
        c = ctx(state={"rate": 3, "fanout": 2, "novelty": 0.0})
        self.assertLess(self.m2.score(c), 0.2)
        self.assertIsNone(self.m2.hard(c, self.m2.score(c)))


class EnsembleTests(unittest.TestCase):
    def combine(self, c, mode="enforce", cleared=False):
        return ensemble.combine(c, default_scorers(), DEFAULT_POLICY, mode, cleared=cleared)

    def test_benign_allow(self):
        d = self.combine(ctx("/rest/search?q=apple",
                             headers={"user-agent": "Mozilla/5.0", "accept": "text/html", "accept-language": "en"}))
        self.assertEqual(d.effective, "allow")

    def test_confident_payload_blocks_despite_other_models_silent(self):
        # Regression guard: adding M2/M3 must not dilute a confident M1.
        d = self.combine(ctx("/rest/search?q=1' OR 1=1",
                             headers={"user-agent": "Mozilla/5.0", "accept": "text/html"}))
        self.assertEqual(d.effective, "block")

    def test_scanner_ua_blocks(self):
        d = self.combine(ctx("/x?q=hello", headers={"user-agent": "ffuf/2.0"}))
        self.assertEqual(d.effective, "block")

    def test_scan_rate_challenges(self):
        d = self.combine(ctx("/x?q=hello", headers={"user-agent": "Mozilla/5.0", "accept": "text/html"},
                             state={"rate": 80, "fanout": 60, "novelty": 0.0}))
        self.assertEqual(d.effective, "challenge")

    def test_monitor_downgrades_block_to_log(self):
        d = self.combine(ctx("/x?q=1' OR 1=1"), mode="monitor")
        self.assertEqual(d.intended, "block")
        self.assertEqual(d.effective, "log")

    def test_cleared_relaxes_challenge_not_block(self):
        chal = ctx("/x", headers={"user-agent": "Mozilla/5.0", "accept": "text/html"},
                   state={"rate": 80, "fanout": 60, "novelty": 0.0})
        self.assertEqual(self.combine(chal, cleared=True).effective, "log")
        blk = ctx("/x?q=1' OR 1=1", headers={"user-agent": "Mozilla/5.0"})
        self.assertEqual(self.combine(blk, cleared=True).effective, "block")


class ChallengeTests(unittest.TestCase):
    def test_no_cookie_not_cleared(self):
        self.assertFalse(challenge.is_cleared(""))
        self.assertFalse(challenge.is_cleared("other=1"))

    def test_forged_cookie_rejected(self):
        self.assertFalse(challenge.is_cleared(f"{challenge.COOKIE}=123.45.deadbeef"))

    def test_valid_clearance_roundtrip(self):
        # Reproduce what the browser JS does: sign(ts) is engine-side; find a nonce.
        import hashlib
        ts = str(int(time.time()))
        sig = challenge._sign(ts)
        nonce = 0
        while True:
            d = hashlib.sha256(f"{ts}:{nonce}".encode()).digest()
            if challenge._leading_zero_bits(d) >= challenge.DIFFICULTY_BITS:
                break
            nonce += 1
        cookie = f"{challenge.COOKIE}={ts}.{nonce}.{sig}"
        self.assertTrue(challenge.is_cleared(cookie))

    def test_expired_clearance_rejected(self):
        old = str(int(time.time()) - challenge.TTL_SECONDS - 10)
        self.assertFalse(challenge.is_cleared(f"{challenge.COOKIE}={old}.0.{challenge._sign(old)}"))

    def test_page_renders(self):
        html = challenge.page("rid-1")
        self.assertIn(b"Checking your browser", html)
        self.assertIn(b"sentinel-clearance", html)


class RouteMatchTests(unittest.TestCase):
    def test_first_match_and_default(self):
        c = cfg(routes=[{"match": {"path_prefix": "/api/login", "methods": ["POST"]},
                         "thresholds": {"log": 0.1, "challenge": 0.2, "block": 0.3},
                         "models": DEFAULT_POLICY["models"]}])
        self.assertEqual(c.match("POST", "/api/login")["thresholds"]["block"], 0.3)
        self.assertIs(c.match("GET", "/api/login"), c.defaults)

    def test_redaction(self):
        c = cfg()
        red = c.redact_headers({"authorization": "Bearer x", "user-agent": "curl"})
        self.assertEqual(red["authorization"], "<redacted>")
        self.assertEqual(red["user-agent"], "curl")


if __name__ == "__main__":
    unittest.main()


class ClientIpResolutionTests(unittest.TestCase):
    def test_ignores_client_xff_uses_envoy_address(self):
        # A client sets X-Forwarded-For to spoof; the engine must ignore it.
        f = features.extract("GET", "/", {"x-forwarded-for": "1.2.3.4",
                                          "x-envoy-external-address": "203.0.113.9"}, b"",
                             {"client_ip_from": "remote_addr"})
        self.assertEqual(f.client_ip, "203.0.113.9")

    def test_xff_mode_still_uses_envoy_computed_address(self):
        f = features.extract("GET", "/", {"x-forwarded-for": "1.2.3.4, 10.0.0.1",
                                          "x-envoy-external-address": "198.51.100.2"}, b"",
                             {"client_ip_from": "x-forwarded-for"})
        self.assertEqual(f.client_ip, "198.51.100.2")

    def test_cf_mode_uses_cf_header(self):
        f = features.extract("GET", "/", {"cf-connecting-ip": "9.9.9.9",
                                          "x-envoy-external-address": "10.0.0.1"}, b"",
                             {"client_ip_from": "cf-connecting-ip"})
        self.assertEqual(f.client_ip, "9.9.9.9")


class LlmEndpointContextTests(unittest.TestCase):
    def test_llm_endpoint_defaults_false(self):
        self.assertFalse(ctx().llm_endpoint)

    def test_llm_endpoint_can_be_set(self):
        c = Context(features=features.extract("GET", "/x", {}, b""), llm_endpoint=True)
        self.assertTrue(c.llm_endpoint)
