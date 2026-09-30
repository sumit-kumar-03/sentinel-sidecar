"""Per-request latency of a benign GET, as percentiles.

Run twice -- once against the sidecar and once against the app directly -- to
isolate the latency the sidecar adds (CRS + ext_authz to the engine). Sequential
by design: this measures per-request added latency, not throughput. A distinct
client IP per request avoids the behaviour scorer flagging the run's volume.

Usage: python3 latency.py http://127.0.0.1:8090 [n]
"""

from __future__ import annotations

import sys
import time
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"


def pct(xs, p):
    xs = sorted(xs)
    k = max(0, min(len(xs) - 1, int(round((p / 100) * (len(xs) - 1)))))
    return xs[k]


def main() -> int:
    base = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 500
    times = []
    for i in range(n):
        url = base.rstrip("/") + "/rest/products/search?q=" + urllib.parse.quote(f"benign query {i}")
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html",
                                                   "X-Forwarded-For": f"198.19.{(i//250)%250}.{i%250}"})
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                r.read()
        except Exception:
            continue
        times.append((time.perf_counter() - t0) * 1000)
    times = times[5:]  # drop warmup
    print(f"target={base} n={len(times)} "
          f"p50={pct(times,50):.2f}ms p95={pct(times,95):.2f}ms p99={pct(times,99):.2f}ms "
          f"mean={sum(times)/len(times):.2f}ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
