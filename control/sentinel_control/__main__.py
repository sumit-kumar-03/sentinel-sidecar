"""CLI: python -m sentinel_control {validate,render} CONFIG [--out PATH]."""

from __future__ import annotations

import argparse
import sys

from . import config, render


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel-control")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="validate a sentinel.yaml")
    p_validate.add_argument("config")

    p_render = sub.add_parser("render", help="validate and render the gateway config")
    p_render.add_argument("config")
    p_render.add_argument("--out", required=True, help="path for the rendered envoy.yaml")
    p_render.add_argument("--engine-out", help="path for the rendered engine.json (the defaulted config)")

    args = parser.parse_args(argv)
    try:
        cfg = config.load(args.config)
    except config.ConfigError as exc:
        print(exc, file=sys.stderr)
        return 1

    if args.command == "render":
        try:
            render.write(render.render_envoy(cfg), args.out)
            if args.engine_out:
                render.write_json(cfg, args.engine_out)
        except OSError as exc:
            print(f"cannot write output: {exc.strerror}", file=sys.stderr)
            return 2
        extra = f", engine={args.engine_out}" if args.engine_out else ""
        print(f"rendered {args.out}{extra} (mode={cfg['mode']}, profile={cfg['profile']}, upstream={cfg['upstream']['url']})")
    else:
        print(f"{args.config}: valid (mode={cfg['mode']}, profile={cfg['profile']}, routes={len(cfg['routes'])})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
