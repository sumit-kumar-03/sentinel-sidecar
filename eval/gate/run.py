"""End-to-end detection & false-positive measurement through the live sidecar.

Replays the labeled corpus as query values against the running sidecar with a
browser-like user-agent (so the M3 bot signal does not shortcut the result and we
measure payload detection). A response of 403/429 counts as caught. Attribution:
a 403 carrying an x-sentinel-verdict header came from the engine; a 403 without it
came from CRS in the gateway; a 429 is the challenge tier.

Usage: python3 run.py http://127.0.0.1:8090
"""

from __future__ import annotations

import json
import sys
import urllib.parse
import urllib.request
from collections import defaultdict

import corpus

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
HEADERS = {"User-Agent": UA, "Accept": "text/html,application/xhtml+xml",
           "Accept-Language": "en-US,en;q=0.9"}


_seq = [0]

def probe(base: str, value: str) -> tuple[int, str]:
    url = base.rstrip("/") + "/rest/products/search?q=" + urllib.parse.quote(value)
    # A distinct client IP per request isolates payload detection/FPR from the
    # per-client behaviour scorer (rate/fan-out), which would otherwise flag the
    # replay's own volume. (The engine currently trusts client XFF -- see report.)
    _seq[0] += 1
    n = _seq[0]
    xff = f"198.18.{(n // 250) % 250}.{n % 250}"
    req = urllib.request.Request(url, headers={**HEADERS, "X-Forwarded-For": xff})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers.get("x-sentinel-verdict", "")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("x-sentinel-verdict", "")
    except Exception:
        return 0, ""


def caught(status: int) -> bool:
    return status in (403, 429)


def layer(status: int, verdict: str) -> str:
    if status == 429:
        return "engine(challenge)"
    if status == 403:
        return "engine" if verdict else "crs"
    return "-"


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8090"
    fam_total: dict[str, int] = defaultdict(int)
    fam_caught: dict[str, int] = defaultdict(int)
    by_layer: dict[str, int] = defaultdict(int)

    for family, payload in corpus.ATTACKS:
        st, v = probe(base, payload)
        fam_total[family] += 1
        if caught(st):
            fam_caught[family] += 1
            by_layer[layer(st, v)] += 1

    n_attack = sum(fam_total.values())
    n_caught = sum(fam_caught.values())

    benign = corpus.benign()
    fp = 0
    fp_examples = []
    fp_layer = defaultdict(int)
    for value in benign:
        st, v = probe(base, value)
        if caught(st):
            fp += 1
            fp_layer[layer(st, v)] += 1
            if len(fp_examples) < 15:
                fp_examples.append(value)

    result = {
        "target": base,
        "attacks": {"total": n_attack, "caught": n_caught,
                    "detection_rate": round(n_caught / n_attack, 4) if n_attack else 0.0},
        "by_family": {f: {"total": fam_total[f], "caught": fam_caught[f]} for f in sorted(fam_total)},
        "by_layer": dict(by_layer),
        "benign": {"total": len(benign), "false_blocks": fp,
                   "fpr": round(fp / len(benign), 5) if benign else 0.0,
                   "by_layer": dict(fp_layer)},
        "fp_examples": fp_examples,
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
