"""Read the rendered engine.json for the analyst's view of the config."""

from __future__ import annotations

import json
import os
from pathlib import Path

CONFIG_PATH = os.environ.get("SENTINEL_ENGINE_CONFIG", "/rendered/engine.json")


class AnalystConfig:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        analyst = cfg.get("analyst", {})
        self.enabled: bool = bool(analyst.get("enabled", False))
        self.llm: dict = analyst.get("llm", {})
        self.mode: str = cfg.get("mode", "monitor")
        defaults = cfg.get("defaults", {})
        self.thresholds = defaults.get("thresholds", {"log": 0.4, "challenge": 0.7, "block": 0.85})

    @property
    def llm_ready(self) -> bool:
        return self.enabled and bool(self.llm.get("url") and self.llm.get("model"))


def load(path: str | Path = CONFIG_PATH) -> AnalystConfig:
    return AnalystConfig(json.loads(Path(path).read_text()))
