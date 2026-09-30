"""Release-gate evaluator: measure the live sidecar against docs/ARCHITECTURE.md 9.

Gates: detection >= 95%, FPR <= 0.1%, added latency p95 < 25ms / p99 < 50ms.
Detection/FPR are measured end-to-end through the sidecar in enforce mode; latency
is the delta between the sidecar path and a direct-to-app baseline. Writes a
report (md + json) and exits non-zero if any gate fails.

Usage: python3 gate.py <sidecar_url> <app_direct_url> [out_dir]
"""

from __future__ import annotations

import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import corpus
import run  # reuse probe(), caught(), layer()

GATE_DETECTION = 0.95
GATE_FPR = 0.001
GATE_P95_ADDED = 25.0
GATE_P99_ADDED = 50.0
LAT_N = 400

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"


def _pct(xs, p):
    xs = sorted(xs)
    return xs[max(0, min(len(xs) - 1, int(round((p / 100) * (len(xs) - 1)))))]


def _latency(base):
    times = []
    for i in range(LAT_N):
        url = base.rstrip("/") + "/rest/products/search?q=" + urllib.parse.quote(f"benign {i}")
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html",
                                                   "X-Forwarded-For": f"198.19.{(i//250)%250}.{i%250}"})
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                r.read()
        except Exception:
            continue
        times.append((time.perf_counter() - t0) * 1000)
    times = times[5:]
    return {"p50": _pct(times, 50), "p95": _pct(times, 95), "p99": _pct(times, 99)}


def main():
    sidecar, app = sys.argv[1], sys.argv[2]
    out = Path(sys.argv[3]) if len(sys.argv) > 3 else Path(".")

    caught = fam_c = 0
    fam_total = {}
    fam_caught = {}
    for family, payload in corpus.ATTACKS:
        st, v = run.probe(sidecar, payload)
        fam_total[family] = fam_total.get(family, 0) + 1
        if run.caught(st):
            caught += 1
            fam_caught[family] = fam_caught.get(family, 0) + 1
    n_attack = len(corpus.ATTACKS)
    detection = caught / n_attack

    benign = corpus.benign()
    fp = sum(1 for val in benign if run.caught(run.probe(sidecar, val)[0]))
    fpr = fp / len(benign)

    lat_s = _latency(sidecar)
    lat_a = _latency(app)
    added = {k: round(lat_s[k] - lat_a[k], 2) for k in lat_s}

    gates = {
        "detection>=95%": (detection >= GATE_DETECTION, f"{detection*100:.1f}%"),
        "fpr<=0.1%": (fpr <= GATE_FPR, f"{fpr*100:.3f}%"),
        "added_p95<25ms": (added["p95"] < GATE_P95_ADDED, f"{added['p95']:.2f}ms"),
        "added_p99<50ms": (added["p99"] < GATE_P99_ADDED, f"{added['p99']:.2f}ms"),
    }
    all_pass = all(ok for ok, _ in gates.values())

    result = {"detection": round(detection, 4), "fpr": round(fpr, 5),
              "by_family": {f: f"{fam_caught.get(f,0)}/{fam_total[f]}" for f in sorted(fam_total)},
              "latency_sidecar": {k: round(v, 2) for k, v in lat_s.items()},
              "latency_app": {k: round(v, 2) for k, v in lat_a.items()},
              "latency_added": added, "gates": {k: v[0] for k, v in gates.items()},
              "pass": all_pass}
    out.mkdir(parents=True, exist_ok=True)
    (out / "gate_report.json").write_text(json.dumps(result, indent=2))

    lines = ["# Release-gate report", "",
             f"Overall: {'PASS' if all_pass else 'FAIL'}", "",
             "| Gate | Result | Value |", "|---|---|---|"]
    for name, (ok, val) in gates.items():
        lines.append(f"| {name} | {'PASS' if ok else 'FAIL'} | {val} |")
    lines += ["", "Per-family detection: " + ", ".join(f"{f} {result['by_family'][f]}" for f in result['by_family']),
              "", f"Latency sidecar/app/added p95: {lat_s['p95']:.2f} / {lat_a['p95']:.2f} / {added['p95']:.2f} ms"]
    (out / "gate_report.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
