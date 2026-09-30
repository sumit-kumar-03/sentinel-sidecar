"""Entry point: python -m sentinel_engine [config.json]."""

from __future__ import annotations

import sys

from . import appconfig, server


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    path = argv[0] if argv else appconfig.CONFIG_PATH
    cfg = appconfig.load(path)
    print(f"sentinel-engine: loaded {path} (mode={cfg.mode}, routes={len(cfg.routes)})", flush=True)
    server.serve(cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
