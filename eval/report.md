# sentinel-sidecar — Validation Report

Date: 2026-09-29 · Scope: Phases 0–5, single-host Docker Compose test stack

Validated the running sidecar across four layers: automated checks, release-gate
detection/FPR/latency, adversarial real-tool replay, and this report. All numbers
are reproducible via the `eval/` harness against a live enforce-mode stack.

## Verdict

- **Detection & false positives:** in the recommended posture (CRS in score mode,
  the engine decides) the sidecar caught **96.4%** of attack payloads with a
  **0.0%** false-positive rate on 2000 benign inputs — **meets** the release gate
  (≥95% detection, ≤0.1% FPR) on this corpus.
- **Latency:** the sidecar adds **~1.4 ms at p95 / ~1.6 ms at p99** — far under the
  25 ms / 50 ms budget.
- **Adversarial:** ffuf is fully blocked (after a fix this validation found) and
  sqlmap is neutralised (403s; reports the parameter not injectable).
- **Caveat:** CRS in *block* mode is unusable at paranoia 2 (25.9% FPR); use score
  mode. The 96.4%/0% figure is on a 56-payload curated corpus of relatively clean
  payloads — heavily evasive payloads drop M1 to ~78–83% (see Findings).

## Layer 1 — Automated checks

| Check | Result |
|---|---|
| `make test` (unit) | 85 passed (control 48, engine 27, analyst 10) |
| `make smoke` (end-to-end, 23 checks) | 23 passed |
| `make replay` (M1 ensemble, offline, evasive set) | 77.8% detection / 0% FPR |

## Layer 2 — Release-gate validation (live enforce stack, browser UA, unique IP/req)

Detection on 56 curated real payloads (5 families); FPR on 2000 benign values.

| Posture | Detection | FPR | Notes |
|---|---|---|---|
| CRS **block** mode | 100% (56/56) | **25.9%** (518/2000) | every false block is CRS; unusable for APIs at PL2 |
| CRS **score** mode (engine decides) | **96.4%** (54/56) | **0.0%** (0/2000) | recommended posture; **meets gate** |

Per-family detection (score mode): sqli 15/15, xss 15/15, traversal 8/8, cmdi 10/10,
ssti 8/8 caught by CRS in block mode; in score mode the engine (M1) caught 54/56,
missing 2. Engine caused **0** false positives in either posture.

**Latency** (500 benign GETs, sequential):

| Path | p50 | p95 | p99 |
|---|---|---|---|
| via sidecar | 9.02 ms | 11.40 ms | 13.32 ms |
| direct to app | 8.40 ms | 10.05 ms | 11.72 ms |
| **added by sidecar** | **~0.6 ms** | **~1.4 ms** | **~1.6 ms** |

**Operational invariants:** fail-open confirmed (engine down → open route still 200);
fail-closed, JS/PoW challenge + clearance, and learn-mode baselines verified in
earlier phase testing; invalid config refuses to start (smoke).

## Layer 3 — Adversarial real-tool replay (Trident scanner image, thermal-capped)

| Tool | Through sidecar | Direct to app |
|---|---|---|
| ffuf (60 paths) — before fix | 0 blocked (bypassed via UA) | n/a |
| ffuf (60 paths) — after fix | **60/60 blocked (403)** | 200/404s |
| sqlmap (boolean, level 1) | **blocked (403); "not injectable"** | probes reach app |

## Findings

1. **ffuf evasion (FIXED during validation).** ffuf's default user-agent is
   "Fuzz Faster U Fool", not the literal "ffuf" the M3 signature matched, so 20
   discovery requests passed. Added the real UA to the scanner list; ffuf now
   blocks 60/60. Locked with a unit test using the real UA.
2. **The engine trusts a client-supplied `X-Forwarded-For` (open issue).** Proper
   trusted-proxy / XFF handling was deferred in Phase 2. A client can currently
   set its own perceived IP, which would let an attacker dodge the per-IP
   behaviour scorer by rotating XFF. Must be fixed before enforce in production.
   (This validation used it deliberately to isolate payload detection from
   behaviour.)
3. **CRS block mode is too false-positive-prone at PL2** for API traffic (flags
   benign URLs and JSON in parameter values). Run CRS in score mode and let the
   engine decide; the deferred CRS-score→engine feed would let CRS contribute its
   recall (the 2 payloads the engine missed) without its false positives.
4. **M1 accuracy is payload-dependent.** 96.4% on clean canonical payloads, ~78–83%
   on heavily evasive ones. M1 is trained on a synthetic corpus; reaching the gate
   robustly needs real corpora (SecLists, CSIC, live traffic).

## How to reproduce

```
make test && make demo-up && make smoke && make replay      # Layer 1
# Layer 2 (enforce stack on :8090):
python3 eval/gate/run.py http://127.0.0.1:8090              # detection + FPR
python3 eval/gate/latency.py http://127.0.0.1:8090 500      # latency
# Layer 3: eval/adversarial via the Trident scanner image (see report)
```
