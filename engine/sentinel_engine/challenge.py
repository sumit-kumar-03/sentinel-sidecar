"""JS + proof-of-work challenge for the 'challenge' verdict tier.

A challenged client receives an interstitial page that (1) runs JavaScript and
(2) spends a little CPU finding a nonce whose SHA-256 has DIFFICULTY leading zero
bits. The page then stores a clearance cookie and reloads. The engine verifies
the cookie: the timestamp is HMAC-signed by the engine (so it cannot be forged),
it is still fresh, and the submitted nonce genuinely meets the difficulty.

This defeats non-JS automation (ffuf, curl, sqlmap, most scanners) without a
CAPTCHA. It is a friction gate, not proof of humanity. A self-contained SHA-256
is embedded so it works over plain HTTP where window.crypto.subtle is absent.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time

SECRET = os.environ.get("SENTINEL_CHALLENGE_SECRET", "").encode() or os.urandom(32)
DIFFICULTY_BITS = int(os.environ.get("SENTINEL_CHALLENGE_BITS", "16"))
TTL_SECONDS = int(os.environ.get("SENTINEL_CLEARANCE_TTL", "3600"))
COOKIE = "sentinel-clearance"


def _sign(ts: str) -> str:
    return hmac.new(SECRET, ts.encode(), hashlib.sha256).hexdigest()[:32]


def _leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        for i in range(7, -1, -1):
            if byte & (1 << i):
                return bits
            bits += 1
        break
    return bits


def _cookie_value(cookie_header: str) -> str | None:
    for part in cookie_header.split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE:
            return value
    return None


def is_cleared(cookie_header: str) -> bool:
    """True if the request carries a valid, fresh, PoW-backed clearance cookie."""
    raw = _cookie_value(cookie_header or "")
    if not raw:
        return False
    try:
        ts_s, nonce, sig = raw.split(".", 2)
    except ValueError:
        return False
    if not hmac.compare_digest(sig, _sign(ts_s)):
        return False
    try:
        ts = int(ts_s)
    except ValueError:
        return False
    if abs(time.time() - ts) > TTL_SECONDS:
        return False
    digest = hashlib.sha256(f"{ts_s}:{nonce}".encode()).digest()
    return _leading_zero_bits(digest) >= DIFFICULTY_BITS


def page(request_id: str = "") -> bytes:
    ts = str(int(time.time()))
    sig = _sign(ts)
    html = _TEMPLATE.replace("__TS__", ts).replace("__SIG__", sig) \
        .replace("__BITS__", str(DIFFICULTY_BITS)).replace("__RID__", request_id).replace("__COOKIE__", COOKIE)
    return html.encode()


# Minimal SHA-256 in JS so the PoW works without window.crypto.subtle (plain HTTP).
_TEMPLATE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Checking your browser</title>
<style>body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;
display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{max-width:26rem;padding:2rem;text-align:center}.spin{width:2rem;height:2rem;
border:3px solid #333;border-top-color:#5b8def;border-radius:50%;margin:1rem auto;
animation:s 1s linear infinite}@keyframes s{to{transform:rotate(360deg)}}
small{color:#8a8f98}</style></head><body><div class=card>
<h2>Checking your browser</h2><div class=spin></div>
<p>Verifying you are not an automated client. This runs once.</p>
<small>request __RID__</small></div>
<script>
function sha256(a){function r(a,b){return a>>>b|a<<32-b}var b,c,d,e,f,g,h,i,j,
k=[],l=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,
2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,
2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,
770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,
3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,
1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,
2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,
430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,
1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,
3204031479,3329325298];b=[1779033703,3144134277,1013904242,2773480762,
1359893119,2600822924,528734635,1541459225];c=unescape(encodeURIComponent(a));
d=[];for(e=0;e<c.length;e++)d.push(c.charCodeAt(e));d.push(128);while(d.length%64-56)
d.push(0);f=8*c.length;var m=[];for(e=0;e<8;e++){m.unshift(f&255);f=Math.floor(f/256)}
d=d.concat(m);for(e=0;e<d.length;e+=64){var n=b.slice(0);for(g=0;g<64;g++){if(g<16)
k[g]=d[e+4*g]<<24|d[e+4*g+1]<<16|d[e+4*g+2]<<8|d[e+4*g+3];else{h=k[g-15];i=k[g-2];
k[g]=(r(h,7)^r(h,18)^h>>>3)+k[g-7]+(r(i,17)^r(i,19)^i>>>10)+k[g-16]|0}var o=(r(n[0],
2)^r(n[0],13)^r(n[0],22))+((n[0]&n[1])^(n[0]&n[2])^(n[1]&n[2]))|0,p=(r(n[4],6)^
r(n[4],11)^r(n[4],25))+((n[4]&n[5])^(~n[4]&n[6]))+n[7]+l[g]+k[g]|0;n=[p+o|0,n[0],
n[1],n[2],n[3]+p|0,n[4],n[5],n[6]]}for(g=0;g<8;g++)b[g]=b[g]+n[g]|0}var q="";
for(e=0;e<8;e++)for(g=28;g>=0;g-=4)q+=(b[e]>>>g&15).toString(16);return q}
function lz(hex){var n=0;for(var i=0;i<hex.length;i++){var v=parseInt(hex[i],16);
if(v===0){n+=4;continue}if(v>=8)return n;if(v>=4)return n+1;if(v>=2)return n+2;
return n+3}return n}
var ts="__TS__",sig="__SIG__",bits=__BITS__,n=0;
function solve(){for(var i=0;i<200000;i++){if(lz(sha256(ts+":"+n))>=bits){
document.cookie="__COOKIE__="+ts+"."+n+"."+sig+";path=/;max-age=3600;samesite=lax";
location.reload();return}n++}setTimeout(solve,0)}
setTimeout(solve,50);
</script></body></html>"""
