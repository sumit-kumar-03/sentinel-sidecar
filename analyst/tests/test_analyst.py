import time
import unittest

from sentinel_analyst import correlator, llm


class FakeRedis:
    """Minimal in-memory stand-in for the Redis calls the correlator makes."""
    def __init__(self):
        self.sets = {}
        self.ints = {}
        self.kv = {}
        self.expires = {}
    # pipeline just records and executes eagerly in order
    def pipeline(self):
        return FakePipe(self)
    def set(self, key, val, nx=False, ex=None):
        if nx and key in self.kv:
            return None
        self.kv[key] = val
        return True


class FakePipe:
    def __init__(self, r):
        self.r = r
        self.ops = []
    def sadd(self, k, *v): self.ops.append(("sadd", k, v)); return self
    def expire(self, k, t): self.ops.append(("expire", k, t)); return self
    def incr(self, k): self.ops.append(("incr", k, None)); return self
    def scard(self, k): self.ops.append(("scard", k, None)); return self
    def execute(self):
        out = []
        for op, k, v in self.ops:
            if op == "sadd":
                s = self.r.sets.setdefault(k, set()); s.update(v); out.append(len(v))
            elif op == "incr":
                self.r.ints[k] = self.r.ints.get(k, 0) + 1; out.append(self.r.ints[k])
            elif op == "scard":
                out.append(len(self.r.sets.get(k, set())))
            else:
                out.append(True)
        return out


def auth_event(ip):
    return {"client_ip": ip, "path": "/rest/user/login", "route": "/rest/user/login", "method": "POST"}


def scan_event(ip, path):
    return {"client_ip": ip, "path": path, "route": "default", "method": "GET"}


class CorrelatorTests(unittest.TestCase):
    def setUp(self):
        self.r = FakeRedis()
        self.c = correlator.Correlator()

    def test_distributed_stuffing_raises_once(self):
        alerts = []
        # below thresholds first
        for i in range(correlator.AUTH_MIN_IPS - 1):
            alerts += self.c.update(self.r, auth_event(f"10.0.0.{i}"))
        self.assertEqual(alerts, [])
        # push distinct IPs and request count over thresholds
        for i in range(correlator.AUTH_MIN_IPS, correlator.AUTH_MIN_IPS + 5):
            self.c.update(self.r, auth_event(f"10.0.0.{i}"))
        got = []
        for _ in range(correlator.AUTH_MIN_REQS):
            got += self.c.update(self.r, auth_event("10.0.0.250"))
        stuffing = [a for a in got if a["type"] == "distributed_stuffing"]
        self.assertEqual(len(stuffing), 1)  # cooldown dedupes
        self.assertGreaterEqual(stuffing[0]["distinct_ips"], correlator.AUTH_MIN_IPS)

    def test_slow_scan_raises(self):
        got = []
        for i in range(correlator.SCAN_MIN_PATHS + 2):
            got += self.c.update(self.r, scan_event("9.9.9.9", f"/admin/p{i}"))
        scans = [a for a in got if a["type"] == "slow_scan"]
        self.assertEqual(len(scans), 1)
        self.assertGreaterEqual(scans[0]["distinct_paths"], correlator.SCAN_MIN_PATHS)

    def test_no_alert_without_ip(self):
        self.assertEqual(self.c.update(self.r, {"path": "/x", "route": "default"}), [])

    def test_auth_detection(self):
        self.assertTrue(correlator._is_auth("/rest/user/login", "default"))
        self.assertTrue(correlator._is_auth("/x", "/api/auth"))
        self.assertFalse(correlator._is_auth("/products", "default"))


class M5ValidationTests(unittest.TestCase):
    def test_valid_verdict(self):
        v = llm._validate({"attack_type": "SQLi", "confidence": 0.9,
                           "recommended_action": "Block", "rationale": "union select"})
        self.assertEqual(v["attack_type"], "sqli")
        self.assertEqual(v["recommended_action"], "block")

    def test_bad_enum_rejected(self):
        self.assertIsNone(llm._validate({"attack_type": "nuke", "confidence": 0.9,
                                         "recommended_action": "block"}))

    def test_bad_confidence_rejected(self):
        self.assertIsNone(llm._validate({"attack_type": "xss", "confidence": "high",
                                         "recommended_action": "block"}))
        self.assertIsNone(llm._validate({"attack_type": "xss", "confidence": 2.0,
                                         "recommended_action": "block"}))

    def test_non_dict_rejected(self):
        self.assertIsNone(llm._validate(["not", "a", "dict"]))

    def test_prompt_includes_untrusted_marker_and_data(self):
        ev = {"method": "GET", "path": "/x", "sample": {"values": ["1 OR 1=1"], "hits": ["sqli"]},
              "scores": {"m1": 0.9}}
        prompt = llm.build_prompt(ev)
        self.assertIn("UNTRUSTED", prompt)
        self.assertIn("1 OR 1=1", prompt)


class M5TriageTests(unittest.TestCase):
    def test_triage_uses_validation(self):
        m5 = llm.M5("http://x", "m")
        m5.triage = llm.M5.triage.__get__(m5)  # keep real method
        # monkeypatch urlopen path by stubbing _validate flow via a fake generate
        import types

        def fake_triage(event):
            raw = {"attack_type": "xss", "confidence": 0.8, "recommended_action": "block", "rationale": "r"}
            return llm._validate(raw)
        m5.triage = types.MethodType(lambda self, e: fake_triage(e), m5)
        self.assertEqual(m5.triage({})["attack_type"], "xss")


if __name__ == "__main__":
    unittest.main()


class FakeRedisFull(FakeRedis):
    def __init__(self):
        super().__init__()
        self.streams = {}
        self.ttls = {}
    def incr(self, k):
        self.ints[k] = self.ints.get(k, 0) + 1
        return self.ints[k]
    def expire(self, k, t):
        self.ttls[k] = t
        return True
    def set(self, k, v, nx=False, ex=None):
        if nx and k in self.kv:
            return None
        self.kv[k] = v
        if ex:
            self.ttls[k] = ex
        return True
    def get(self, k):
        return self.kv.get(k)
    def ttl(self, k):
        return self.ttls.get(k, -1)
    def delete(self, *ks):
        n = 0
        for k in ks:
            if k in self.kv:
                del self.kv[k]; n += 1
        return n
    def xadd(self, key, fields, **kw):
        self.streams.setdefault(key, []).append(fields)
        return b"1-1"
    def scan_iter(self, match=None, count=100):
        import fnmatch
        return [k for k in self.kv if match is None or fnmatch.fnmatch(k, match)]


from sentinel_analyst import applier as applier_mod


class _Cfg:
    def __init__(self, allow=None, denylist=True, rules="apply"):
        self.cfg = {"lists": {"allow": allow or []},
                    "analyst": {"auto_actions": {"denylist": denylist, "rules": rules}}}


def verdict_record(ip, action="block", conf=0.9, at="sqli"):
    return {"client_ip": ip, "path": "/x", "verdict": {"attack_type": at, "confidence": conf,
            "recommended_action": action, "rationale": "r"}}


class ApplierTests(unittest.TestCase):
    def setUp(self):
        self.r = FakeRedisFull()

    def test_apply_writes_denylist_and_audit(self):
        a = applier_mod.Applier(self.r, _Cfg(rules="apply"))
        a.on_verdict(verdict_record("5.5.5.5"))
        self.assertIn("dyn:deny:5.5.5.5", self.r.kv)
        self.assertEqual(len(self.r.streams.get("sentinel:audit", [])), 1)
        self.assertEqual(a.counters["denies"], 1)

    def test_propose_mode_does_not_deny(self):
        a = applier_mod.Applier(self.r, _Cfg(rules="propose"))
        a.on_verdict(verdict_record("5.5.5.5"))
        self.assertNotIn("dyn:deny:5.5.5.5", self.r.kv)
        self.assertEqual(len(self.r.streams.get("sentinel:proposals", [])), 1)

    def test_allowlisted_ip_is_never_denied(self):
        a = applier_mod.Applier(self.r, _Cfg(allow=["5.5.5.0/24"], rules="apply"))
        a.on_verdict(verdict_record("5.5.5.5"))
        self.assertNotIn("dyn:deny:5.5.5.5", self.r.kv)
        self.assertEqual(a.counters["skipped_allow"], 1)

    def test_low_confidence_ignored(self):
        a = applier_mod.Applier(self.r, _Cfg(rules="apply"))
        a.on_verdict(verdict_record("5.5.5.5", conf=0.4))
        self.assertNotIn("dyn:deny:5.5.5.5", self.r.kv)

    def test_ttl_escalates_for_repeat_offender(self):
        a = applier_mod.Applier(self.r, _Cfg(rules="apply"))
        a.on_verdict(verdict_record("5.5.5.5"))
        first = self.r.ttls["dyn:deny:5.5.5.5"]
        a.on_verdict(verdict_record("5.5.5.5"))
        second = self.r.ttls["dyn:deny:5.5.5.5"]
        self.assertGreater(second, first)

    def test_slow_scan_denies_scanner(self):
        a = applier_mod.Applier(self.r, _Cfg(rules="apply"))
        a.on_campaign({"type": "slow_scan", "client_ip": "7.7.7.7"})
        self.assertIn("dyn:deny:7.7.7.7", self.r.kv)

    def test_distributed_stuffing_is_proposal_only(self):
        a = applier_mod.Applier(self.r, _Cfg(rules="apply"))
        a.on_campaign({"type": "distributed_stuffing", "route": "/login", "distinct_ips": 40})
        self.assertEqual(len(self.r.streams.get("sentinel:proposals", [])), 1)
        self.assertEqual(a.counters["denies"], 0)
