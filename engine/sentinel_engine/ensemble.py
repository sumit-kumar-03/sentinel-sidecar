"""Combine scorer outputs into a decision under the active mode.

The soft blend is a weighted noisy-OR: each model can only raise the risk, so a
model with no opinion (score 0) never dilutes another that fired. On top of that,
a scorer may return a hard signal ("challenge"/"block") that overrides the soft
tier for decisive cases. A client that has passed the JS/PoW challenge has any
"challenge" outcome relaxed to "log" (but a "block" still blocks).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .scorers import Context, Scorer

ACTIONS = ["allow", "log", "challenge", "block"]
_RANK = {a: i for i, a in enumerate(ACTIONS)}


@dataclass
class Decision:
    risk: float
    scores: dict[str, float]
    intended: str
    effective: str
    route_id: str
    hard: str | None = None


def _clamp(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


def _action(risk: float, thresholds: dict[str, float]) -> str:
    if risk >= thresholds["block"]:
        return "block"
    if risk >= thresholds["challenge"]:
        return "challenge"
    if risk >= thresholds["log"]:
        return "log"
    return "allow"


def _worse(a: str, b: str | None) -> str:
    if b is None:
        return a
    return a if _RANK[a] >= _RANK[b] else b


def combine(ctx: Context, scorers: list[Scorer], policy: dict[str, Any], mode: str,
            cleared: bool = False) -> Decision:
    weights = policy["models"]
    scores = {s.id: _clamp(s.score(ctx)) for s in scorers}

    # Weighted noisy-OR: independent detectors accumulate, zeros do not dilute.
    prod = 1.0
    for sid, sc in scores.items():
        prod *= 1.0 - _clamp(weights.get(sid, 0.0)) * sc
    risk = round(_clamp(1.0 - prod), 4)

    hard: str | None = None
    for s in scorers:
        fn = getattr(s, "hard", None)
        if fn is not None:
            got = fn(ctx, scores[s.id])
            if got:
                hard = got if hard is None else _worse(hard, got)

    intended = _action(risk, policy["thresholds"])
    if hard:
        intended = _worse(intended, hard)
    if cleared and intended == "challenge":
        intended = "log"

    if mode == "enforce":
        effective = intended
    else:
        effective = "log" if intended in ("challenge", "block") else intended

    match = policy.get("match", {})
    route_id = match.get("path_prefix") or match.get("path_exact") or "default"
    return Decision(risk=risk, scores=scores, intended=intended, effective=effective,
                    route_id=route_id, hard=hard)
