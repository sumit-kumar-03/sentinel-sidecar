"""Scorers turn a request context into a 0..1 risk per model id, and may raise a
hard signal that overrides the weighted blend.

Phase 3 added the ONNX M1 payload classifier. Phase 4 adds M2 (behaviour, from
per-client window state) and M3 (bot/automation, from request headers). A scorer
may implement hard(ctx, score) -> "challenge" | "block" | None so a decisive
detector (a confident payload, a known scanner, an extreme scan rate) is not
diluted by models that have no opinion.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Protocol

from .features import Features

MODEL_PATH = os.environ.get("SENTINEL_M1_MODEL", "/app/models/m1.onnx")
LABELS_PATH = os.environ.get("SENTINEL_M1_LABELS", "/app/models/m1_labels.json")
M4_MODEL_PATH = os.environ.get("SENTINEL_M4_MODEL", "/app/models/m4.onnx")


@dataclass
class Context:
    features: Features
    state: Optional[dict[str, Any]] = None   # per-client window stats, or None if Redis is down
    llm_endpoint: bool = False                # True on routes marked llm_endpoint (enables M4)


class Scorer(Protocol):
    id: str

    def score(self, ctx: Context) -> float:
        ...


def _clamp(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


# --- M1: payload classifier -------------------------------------------------

_HEUR_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sqli", re.compile(r"(?i)(\bunion\b\s+\bselect\b|\bor\b\s+1\s*=\s*1\b|;\s*drop\s+table\b|'\s*or\s*'?\d)")),
    ("xss", re.compile(r"(?i)(<script\b|onerror\s*=|javascript:|<img\b[^>]*onerror)")),
    ("traversal", re.compile(r"(\.\./){2,}|(\.\.\\){2,}|/etc/passwd\b|\bboot\.ini\b")),
    ("cmdi", re.compile(r"(?i)(;\s*(cat|ls|id|whoami|curl|wget)\b|\$\(.*\)|`.*`|\|\s*(nc|bash|sh)\b)")),
    ("ssti", re.compile(r"(\{\{.*\}\}|\$\{.*\}|#\{.*\})")),
]


class HeuristicM1:
    """Regex fallback used only when the ONNX model or onnxruntime is unavailable."""

    id = "m1"

    def score(self, ctx: Context) -> float:
        best = 0.0
        for value in ctx.features.scan_values():
            for _label, pattern in _HEUR_PATTERNS:
                if value and pattern.search(value):
                    best = max(best, 0.9)
        return best

    def hard(self, ctx: Context, score: float) -> Optional[str]:
        return "block" if score >= 0.9 else None

    def explain(self, ctx: Context) -> list[str]:
        hits = []
        for value in ctx.features.scan_values():
            for label, pattern in _HEUR_PATTERNS:
                if value and pattern.search(value):
                    hits.append(label)
        return sorted(set(hits))


class OnnxM1:
    """M1 payload classifier backed by the INT8 ONNX char-CNN."""

    id = "m1"

    def __init__(self, model_path: str = MODEL_PATH, labels_path: str = LABELS_PATH):
        import json
        import numpy as np
        import onnxruntime as ort
        from .encode import encode

        self._np = np
        self._encode = encode
        self._labels = json.loads(Path(labels_path).read_text())
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 1
        opts.inter_op_num_threads = 1
        self._sess = ort.InferenceSession(model_path, sess_options=opts, providers=["CPUExecutionProvider"])
        self._input = self._sess.get_inputs()[0].name

    def _probs(self, values: list[str]):
        np = self._np
        batch = np.array([self._encode(v) for v in values], dtype=np.int64)
        logits = self._sess.run(None, {self._input: batch})[0]
        logits = logits - logits.max(axis=1, keepdims=True)
        exp = np.exp(logits)
        return exp / exp.sum(axis=1, keepdims=True)

    def score(self, ctx: Context) -> float:
        values = [v for v in ctx.features.scan_values() if v]
        if not values:
            return 0.0
        probs = self._probs(values)
        return float((1.0 - probs[:, 0]).max())   # labels[0] == "benign"

    def hard(self, ctx: Context, score: float) -> Optional[str]:
        return "block" if score >= 0.9 else None

    def explain(self, ctx: Context) -> list[str]:
        values = [v for v in ctx.features.scan_values() if v]
        if not values:
            return []
        preds = self._probs(values).argmax(axis=1)
        return sorted({self._labels[i] for i in preds if self._labels[i] != "benign"})


# --- M2: behaviour / anomaly ------------------------------------------------

# Behaviour thresholds are env-tunable so operators (and the gate harness, which
# is a single client) can adjust or effectively disable behavioural scoring.
_RATE0 = int(os.environ.get("SENTINEL_M2_RATE_MIN", "15"))    # requests/window: soft start
_RATE1 = int(os.environ.get("SENTINEL_M2_RATE_MAX", "60"))    # requests/window: hard
_FAN0 = int(os.environ.get("SENTINEL_M2_FANOUT_MIN", "10"))   # distinct paths: soft start
_FAN1 = int(os.environ.get("SENTINEL_M2_FANOUT_MAX", "40"))   # distinct paths: hard


class BehaviorM2:
    """Scores automated behaviour from a client's recent window: request rate and
    distinct-path fan-out (scanning), plus parameter novelty vs the learned
    baseline. Abstains (0.0) when no state is available."""

    id = "m2"

    def score(self, ctx: Context) -> float:
        st = ctx.state
        if not st:
            return 0.0
        rate_s = _clamp((st["rate"] - _RATE0) / (_RATE1 - _RATE0))
        fan_s = _clamp((st["fanout"] - _FAN0) / (_FAN1 - _FAN0))
        nov_s = 0.5 * _clamp(st.get("novelty", 0.0))
        return _clamp(max(rate_s, fan_s, nov_s))

    def hard(self, ctx: Context, score: float) -> Optional[str]:
        st = ctx.state
        if not st:
            return None
        # Extreme automated activity: challenge (not block) to survive shared NAT.
        if st["fanout"] >= _FAN1 or st["rate"] >= _RATE1:
            return "challenge"
        return None


# --- M3: bot / automation ---------------------------------------------------

_SCANNERS = re.compile(r"(?i)(ffuf|fuzz faster u fool|sqlmap|nikto|nmap|masscan|gobuster|dirbuster|dirb|"
                       r"feroxbuster|wpscan|nuclei|acunetix|nessus|hydra|zgrab|arachni|"
                       r"metasploit|w3af|skipfish)")
_GENERIC_BOT = re.compile(r"(?i)(curl|wget|python-requests|go-http-client|libwww|scrapy|"
                          r"httpclient|okhttp|java/|axios|node-fetch|guzzle)")


class BotM3:
    """Scores bot/automation from request headers: known scanner and generic
    automation user-agents, and missing browser-shaped headers."""

    id = "m3"

    def score(self, ctx: Context) -> float:
        f = ctx.features
        ua = f.user_agent
        if not ua:
            return 0.75
        if _SCANNERS.search(ua):
            return 0.95
        s = 0.0
        if _GENERIC_BOT.search(ua):
            s = 0.6
        elif "mozilla" not in ua.lower():
            s = 0.5
        # Real browsers send Accept and usually Accept-Language.
        if not f.accept:
            s += 0.2
        if not f.accept_language and "mozilla" not in ua.lower():
            s += 0.1
        return _clamp(s)

    def hard(self, ctx: Context, score: float) -> Optional[str]:
        return "block" if _SCANNERS.search(ctx.features.user_agent or "") else None


class OnnxM4:
    """M4 prompt-injection classifier (binary char-CNN, INT8 ONNX).

    Only scores on routes marked llm_endpoint; elsewhere it abstains. A confident
    injection is a hard signal so it acts even when the m4 ensemble weight is 0.
    """

    id = "m4"

    def __init__(self, model_path: str = M4_MODEL_PATH):
        import numpy as np
        import onnxruntime as ort
        from .encode import encode
        self._np = np
        self._encode = encode
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 1
        opts.inter_op_num_threads = 1
        self._sess = ort.InferenceSession(model_path, sess_options=opts, providers=["CPUExecutionProvider"])
        self._input = self._sess.get_inputs()[0].name

    def _p_injection(self, values: list[str]) -> float:
        np = self._np
        batch = np.array([self._encode(v) for v in values], dtype=np.int64)
        logits = self._sess.run(None, {self._input: batch})[0]
        logits = logits - logits.max(axis=1, keepdims=True)
        exp = np.exp(logits)
        probs = exp / exp.sum(axis=1, keepdims=True)
        return float(probs[:, 1].max())  # labels[1] == "injection"

    def score(self, ctx: Context) -> float:
        if not ctx.llm_endpoint:
            return 0.0
        values = [v for v in ctx.features.scan_values() if v]
        if not values:
            return 0.0
        return self._p_injection(values)

    def hard(self, ctx: Context, score: float) -> Optional[str]:
        return "block" if (ctx.llm_endpoint and score >= 0.9) else None


def default_scorers() -> list["Scorer"]:
    """M1 (ONNX, heuristic fallback) plus M2 behaviour and M3 bot scorers."""
    try:
        m1: Scorer = OnnxM1()
    except Exception as exc:
        import sys
        print(f"sentinel-engine: ONNX M1 unavailable ({exc}); using heuristic M1", file=sys.stderr, flush=True)
        m1 = HeuristicM1()
    scorers: list[Scorer] = [m1, BehaviorM2(), BotM3()]
    try:
        scorers.append(OnnxM4())
    except Exception as exc:
        import sys
        print(f"sentinel-engine: ONNX M4 unavailable ({exc}); prompt-injection scoring disabled",
              file=sys.stderr, flush=True)
    return scorers
