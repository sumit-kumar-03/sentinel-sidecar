# sentinel-sidecar: Architecture and Build Plan

## 1. Context

A self-contained security service that runs as an adjacent container in front of any HTTP application. It combines deterministic rules with several specialist models: fast models make blocking decisions inline, and heavier LLM analysis runs out-of-band and feeds back into the inline tier. Each deployment is configured through one YAML file, so the same image protects any upstream app or endpoint from internet traffic.

Design goals:

- **Drop-in**: add one container, point `upstream` at the app, and route public traffic to the sidecar. The app needs no code changes.
- **Hybrid decisioning**: every request gets a verdict inline within a strict latency budget. Gray-zone and aggregate behavior go to an async analysis tier that can tighten the inline policy.
- **Safe by default**: the service starts in `monitor` mode. Fail-open or fail-closed is set per route, and the sidecar container itself is hardened.
- **Portable**: a CPU-only `lite` profile runs anywhere. A `full` profile adds a GPU LLM analyst.

### Scope, stated honestly

| In scope (L7, HTTP/HTTPS/WebSocket/gRPC-web) | Out of scope (needs other layers) |
|---|---|
| Injection (SQLi, XSS, command, template, LDAP, XXE), path traversal, SSRF, RCE payloads | Volumetric L3/L4 DDoS (needs upstream scrubbing or a CDN) |
| Credential stuffing, brute force, account enumeration | Compromise of the host, the kernel or the app runtime |
| Bot and automation abuse, scraping, scanner fingerprints | Zero-days with no observable anomaly in the request or response |
| Protocol abuse (request smuggling, oversized or malformed bodies, header injection) | Supply-chain attacks against the protected app |
| Prompt injection against LLM-backed endpoints | |
| Response-side data leakage (stack traces, secrets, PII egress) | |
| Slow, distributed attacks correlated over time (out-of-band) | |

## 2. Topology

```
             internet
                |
        :443 / :8080 (public)
                |
  +-------------v------------------------------------------+
  |  sentinel-sidecar (pod / compose group)                  |
  |                                                        |
  |  [gateway]  Envoy                                      |
  |    - TLS termination, HTTP normalization               |
  |    - L0: coraza-proxy-wasm (OWASP CRS), local rate     |
  |          limit, IP/ASN/JA4 reputation lookup           |
  |    - ext_authz (gRPC) ------------+                    |
  |    - response inspection filter   |                    |
  |          |                         v                   |
  |          |              [inline-engine]  (CPU, ONNX)   |
  |          |               M1 payload classifier         |
  |          |               M2 behavior/anomaly           |
  |          |               M3 bot/automation             |
  |          |               M4 prompt-injection (opt.)    |
  |          |               ensemble -> allow/challenge/  |
  |          |                          block/log          |
  |          |                         |  events           |
  |          |                         v                   |
  |          |              [state]  Redis                 |
  |          |               - per-client counters/sessions|
  |          |               - reputation + dynamic rules  |
  |          |               - event stream (Streams)      |
  |          |                         |                   |
  |          |                         v                   |
  |          |              [analyst]  (async, GPU opt.)   |
  |          |               M5 LLM triage (Ollama/vLLM)   |
  |          |               correlator (time-window jobs) |
  |          |               -> writes reputation, TTL     |
  |          |                  blocks, rule proposals     |
  |          v                                             |
  |     upstream app  (http://app:3000, unchanged)         |
  |                                                        |
  |  [control]  admin API + Prometheus /metrics (internal) |
  +--------------------------------------------------------+
```

Why Envoy with ext_authz rather than a custom proxy: Envoy is a mature, fast data plane. TLS, HTTP/2 and 3, WebSockets, body buffering limits and smuggling-resistant parsing come with it. Coraza runs inside Envoy as WASM, so CRS rules add no network hop. All ML stays in one service, `inline-engine`, behind a single gRPC contract that can be tested and swapped independently.

## 3. Request flow (inline path)

Latency budget: **p95 under 25 ms added**, with a hard timeout of 50 ms. After the timeout, the route's `on_timeout` policy applies.

1. **Normalize** (Envoy): reject malformed or ambiguous requests up front, including conflicting `Content-Length`/`Transfer-Encoding`, oversized headers, and bad encodings.
2. **L0 fast rules** (under 1 ms):
   - Static and dynamic denylist check by IP, CIDR, ASN, JA4 fingerprint or API key. Dynamic entries come from the analyst, stored in Redis with a TTL and cached locally.
   - Local rate limits and per-route quotas.
   - Coraza with OWASP CRS at the configured paranoia level. CRS contributes an **anomaly score** (a feature for the models), not a hard block, unless the route sets `crs_mode: block`.
3. **ext_authz to inline-engine** (5 to 20 ms). The request carries method, path, query, headers, the body up to `max_inspect_bytes`, TLS/JA4 metadata, the CRS score and client identity.
   - Feature extraction runs once and is shared by every model.
   - Models run in parallel with per-model timeouts. A model that fails or times out contributes "no opinion", and the ensemble renormalizes.
   - **Ensemble**: `risk = max(hard_signals) OR weighted_sum(model_scores)`. Per-route thresholds map risk to `allow | log | challenge | block`.
4. **Act**: Envoy forwards, returns 403 with a request ID, or returns a challenge (429 with Retry-After, or a JS/PoW challenge page for browser routes).
5. **Emit an event** asynchronously (never on the request's critical path) to a Redis Stream: the verdict, scores and features, plus a redacted request sample when risk falls in the gray zone or the request was blocked.
6. **Response inspection** (optional per route): scan the upstream response for leakage patterns (stack traces, secrets, bulk PII). The sidecar either masks the match or logs it and alerts.

## 4. Model roster

| ID | Specialty | Tier | Model type | Input | Output |
|---|---|---|---|---|---|
| L0 | Known-bad signatures | inline | OWASP CRS via Coraza + reputation lists | raw request | anomaly score, rule IDs |
| M1 | Payload attack classifier | inline | Small transformer (ModernBERT-small class, ~30-60M params), INT8 ONNX, CPU. A char-CNN fallback runs in `lite` mode | decoded params, body fields, path, selected headers | per-class probabilities: sqli, xss, cmdi, traversal, ssrf, ssti, xxe, benign |
| M2 | Behavior / anomaly | inline | Gradient-boosted trees plus a per-route baseline (isolation forest), trained on this deployment's own traffic during `learn` mode | per-client sliding-window features: rate, path entropy, error ratio, param novelty, auth failures | anomaly score |
| M3 | Bot / automation | inline | Gradient-boosted trees | JA4/TLS, header order, UA consistency, timing jitter, cookie/JS challenge state | bot probability, class (scanner, scraper, stuffing, benign bot) |
| M4 | Prompt injection (routes marked `llm_endpoint`) | inline | Small classifier (DeBERTa-small class), ONNX | user-controlled text fields | injection probability |
| M5 | LLM analyst | out-of-band | 7-8B instruct model, Q4 (Qwen2.5-7B / Llama-3.1-8B class) via Ollama, or vLLM on larger GPUs | gray-zone samples, correlated incident bundles | structured verdict (JSON schema): attack type, confidence, rationale, recommended action |
| C1 | Correlator | out-of-band | Deterministic jobs plus M2 aggregates | event stream windows (1m / 15m / 24h) | campaign detection: distributed stuffing, slow scans, enumeration |

Why several specialists instead of one big model: each specialist is small, fast and can be tested alone against its own dataset. Their errors are partly independent, so the ensemble beats any single model. The expensive generalist (M5) only sees the roughly 1% of traffic that is ambiguous.

## 5. Out-of-band loop (analyst service)

```
Redis Stream "events" --> consumer group "analyst"
   |-- gray-zone sample --> M5 triage --> verdict
   |-- window aggregates --> C1 correlator --> campaign
                                   |
           +-----------------------+-----------------------+
           v                       v                       v
  dynamic denylist (TTL)   route threshold nudge     rule proposal
  (auto, bounded)          (auto, bounded, logged)   (needs approval via admin API,
                                                       or auto-apply if configured)
```

Guardrails on automated feedback:

- Auto-blocks always carry a TTL (default 1 h, escalating on repeat offenses). They never apply to `allowlist` identities.
- Threshold nudges are bounded, for example to ±0.1 of the configured value, and revert when they expire.
- M5 output is schema-validated. An invalid or low-confidence verdict produces no action.
- M5 only ever sees redacted samples. Secrets, auth headers, cookies and configured PII fields are stripped before enqueueing, and request content is treated as untrusted data inside the prompt.
- Every automated action is written to an audit stream and exposed at `GET /admin/actions`.

## 6. Configuration (single file, per deployment)

```yaml
# sentinel.yaml
upstream:
  url: http://app:3000
  timeout_ms: 30000

listen:
  port: 8080
  tls: { enabled: false, cert: /certs/tls.crt, key: /certs/tls.key }

mode: monitor            # learn | monitor | enforce
profile: lite            # lite (CPU only) | full (enables M5 via analyst.llm)

defaults:
  on_engine_error: open  # open | closed
  on_timeout: open
  max_inspect_bytes: 65536
  crs: { paranoia: 2, mode: score }   # score | block
  thresholds: { log: 0.4, challenge: 0.7, block: 0.85 }
  models: { m1: 0.40, m2: 0.20, m3: 0.20, crs: 0.20 }  # ensemble weights

routes:
  - match: { path_prefix: /api/login, methods: [POST] }
    on_engine_error: closed
    rate_limit: { per_ip: 10/m, per_account: 5/m }
    thresholds: { challenge: 0.5, block: 0.75 }
  - match: { path_prefix: /api/chat }
    llm_endpoint: true           # enables M4
  - match: { path_prefix: /static }
    inspect: false               # L0 only
  - match: { path_prefix: /healthz }
    bypass: true

identity:
  client_ip_from: x-forwarded-for   # remote_addr | x-forwarded-for | cf-connecting-ip
  trusted_proxies: [10.0.0.0/8]
  account_from: { jwt_claim: sub }

lists:
  allow: [ 10.0.0.0/8 ]
  deny: []

response_inspection:
  enabled: true
  action: mask            # mask | log

redaction:
  headers: [authorization, cookie, x-api-key]
  body_fields: [password, card_number, ssn]

analyst:
  enabled: true
  llm: { provider: ollama, url: http://ollama:11434, model: qwen2.5:7b-instruct-q4_K_M }
  auto_actions: { denylist: true, threshold_nudge: true, rules: propose }  # rules: propose | apply | off

telemetry:
  metrics: prometheus
  logs: json              # ECS-compatible; ship with any collector
```

The config is validated at startup against a JSON Schema, and the service refuses to start if it is invalid. It hot-reloads on SIGHUP or file change.

## 7. Repo layout

```
sentinel-sidecar/
  gateway/            envoy.yaml template, coraza WASM + CRS bundle, render script
  engine/             inline-engine (Python 3.12, gRPC ext_authz, onnxruntime)
    features/         shared feature extraction
    models/           M1-M4 wrappers + ensemble
  analyst/            OOB worker (Redis Streams consumer, M5 client, correlator)
  control/            admin API, config schema + loader
  training/           datasets, training + ONNX export scripts, model cards
  eval/               attack replay harness, latency benchmark, reports
  deploy/
    compose/          sidecar compose fragment + demo stack (Juice Shop / DVWA upstream)
    k8s/              sidecar pod spec example (later)
  docs/
```

Language choice: Python for engine, analyst and control, because the ML ecosystem and ONNX Runtime are there, and gRPC with an async server and in-process models meets the budget. If profiling shows Python overhead dominating, the ext_authz server is the component to port to Go. Its contract stays the same.

## 8. Deployment

Adding the sidecar to an existing compose app:

```yaml
services:
  app:                      # existing service, no longer publishes ports
    image: my-app
  sentinel:
    image: sentinel-sidecar/gateway
    ports: ["443:8080"]
    volumes: ["./sentinel.yaml:/etc/sentinel/sentinel.yaml:ro"]
    depends_on: [sentinel-engine]
  sentinel-engine:
    image: sentinel-sidecar/engine
  sentinel-redis:
    image: redis:7-alpine
  sentinel-analyst:          # optional (profile: full)
    image: sentinel-sidecar/analyst
```

One `include:`-able compose fragment ships these, so an adopting service adds about four lines. In Kubernetes, the same containers run as sidecars in the app pod.

Container hardening: non-root, read-only rootfs, dropped capabilities, no admin port on the public interface, and pinned image digests.

Reference sizing: a 12 GB consumer GPU runs M5 at Q4 with room to spare, and inline models run on CPU. For sustained load tests, cap the GPU power limit (`nvidia-smi -pl`) and the analyst's concurrency.

## 9. Training data and evaluation

- **M1**: public payload corpora (SecLists fuzzing sets, PayloadsAllTheThings, CSIC 2010 HTTP dataset, SQLi/XSS Kaggle sets). Benign traffic comes from crawled legitimate requests and synthetic API traffic. Evaluate on a held-out split and on obfuscated variants (encoding, case, comments).
- **M2/M3**: bootstrap from synthetic and replayed traffic, then per-deployment `learn` mode builds baselines.
- **M4**: public prompt-injection datasets plus a held-out set of jailbreak variants.
- **Red-team harness**: replay attacks with the existing scanning toolchain (the Trident pipeline tools: nuclei, ffuf, sqlmap, dalfox, arjun) against the demo upstream, both behind the sidecar and without it. Record detection rate, false-positive rate on a benign replay, and added latency.

Release gates for switching a profile to `enforce` by default:

| Metric | Target |
|---|---|
| Detection on attack replay (sidecar total) | 95% or better |
| False positives on benign replay | 0.1% or lower |
| Added latency p95 / p99 | under 25 ms / under 50 ms |
| Engine outage behavior | matches configured open/closed per route |

## 10. Phased plan

Each phase ends with a runnable demo and a verification step.

| Phase | Deliverable | Verification |
|---|---|---|
| 0 | Repo scaffold, config schema + loader, Envoy pass-through to demo upstream (Juice Shop), compose stack | `curl` through the sidecar reaches Juice Shop; an invalid config refuses to start |
| 1 | DONE. L0: Coraza + CRS 4.14.0, per-IP rate limits, IP deny/allow lists, Prometheus metrics, monitor/enforce/learn. Deferred to Phase 2: per-account limits, XFF identity, per-route CRS mode | CRS payloads block in enforce, log in monitor; per-IP 429; deny list 403/shadow; metrics on internal port |
| 2 | DONE. inline-engine via HTTP ext_authz, feature extraction, ensemble + thresholds, per-route fail-open/closed (two ext_authz filters), Redis events, engine metrics. Stand-in M1 scorer. Deferred: gRPC transport, per-account limits, CRS-score feed | Engine down: catch-all (open) 200, login (closed) 403, recovers on restart; events land; monitor downgrades block to log |
| 3 | DONE. M1 char-CNN trained (training/), INT8 ONNX 117 KB, served in engine via onnxruntime with heuristic fallback. Trained on synthetic corpus. Deferred: real corpora to hit the release gate | Held-out 100%/0% FPR; real-payload replay 83% detect / 0% FPR (eval/replay.py); ~0.3 ms/req; ONNX==PyTorch 100% |
| 4 | DONE. M2 behaviour (per-client Redis window: rate, fan-out, novelty), M3 bot (UA/header signatures), hard signals + noisy-OR blend, learn-mode baselines, JS/PoW challenge with HMAC clearance cookie. Deferred: response-side M2 signals | Scanner UA -> 403; >40-path fan-out -> 429 JS/PoW page; solved clearance cookie -> 200; normal browser -> 200; learn mode records baselines and never blocks |
| 5 | DONE. analyst/ consumes the event stream (consumer group); correlator raises distributed-stuffing and slow-scan campaigns; M5 (Ollama, qwen2.5:3b on CPU here) triages gray-zone events with strict JSON-schema validation and untrusted-data prompting. Findings only (campaigns/verdicts streams); applying them is Phase 6 | Stuffing injection -> distributed_stuffing alert; gray-zone SQLi -> schema-valid M5 verdict (sqli, block); analyst metrics on :9200 |
| 6 | DONE. Analyst applier writes escalating-TTL dynamic denylist entries from M5 verdicts + slow-scan campaigns (distributed-stuffing = proposal-only); engine enforces them inline; allowlist-safe; gated by auto_actions; audit stream + admin API (actions/denylist/proposals, DELETE to lift). M5 triage moved to a background pool. Also fixed: engine now derives client IP from Envoy's trusted address, not client XFF. Deferred: bounded threshold nudges | Slow-scan/M5 finding -> dyn:deny -> inline 429 within seconds -> audited -> lifted via admin API; allowlist/gating/TTL-escalation unit-tested |
| 7 | DONE. M4 prompt-injection char-CNN (INT8 ONNX), active only on llm_endpoint routes, hard-signal on confident injection. Response inspection via Envoy Lua: scans responses for leak markers, masks body or logs per config. Deferred: real corpora, granular span masking | Injection on llm_endpoint -> 403 (enforce) / m4=1.0 event (monitor); SQLITE_ERROR leak masked with x-sentinel-leak header |
| 8 | DONE. `make gate` (self-contained enforce stack -> detection/FPR/latency vs targets, PASS/FAIL + report); lite/full profiles (`full.compose.yaml` adds Ollama); k8s example (`deploy/k8s/`); env-tunable M2 thresholds; finalized docs | Gate PASS: detection 96.4%, FPR 0.000%, added latency within noise; lite runs CPU-only |

## 11. Risks and mitigations

| Risk | Mitigation |
|---|---|
| False positives break real users | Start in `monitor`; per-route thresholds; `learn` mode; `log` tier before `block`; allowlists |
| Engine latency spikes | Per-model timeouts, parallel inference, INT8 ONNX, route-level `inspect: false` for static assets |
| Sidecar becomes the single point of failure | Stateless gateway/engine (scale horizontally), Redis optional for L0 (falls back to local state), explicit fail-open/closed |
| Evasion via encoding or obfuscation | Normalize before inference (multi-pass URL/HTML/unicode decoding), train on obfuscated variants, CRS as a second opinion |
| LLM analyst manipulated by attacker-controlled content | Redaction, strict JSON-schema outputs, request content always framed as data, bounded auto-actions with TTL, no direct rule apply by default |
| Model drift | Periodic re-eval against the replay harness; versioned models with model cards |
