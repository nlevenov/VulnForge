"""VulnForge command-line entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .app import create_app
from .config import Config
from .safety import BANNER, ExposureRefused


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulnforge",
        description="VulnForge - an intentionally vulnerable web app for learning "
                    "OWASP Top 10 defence. Runs on localhost only.")
    parser.add_argument("--version", action="version", version=f"vulnforge {__version__}")
    parser.add_argument("--host", default=None, help="bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="bind port (default 8000)")
    parser.add_argument("--sandbox", default=None, help="sandbox directory (default: a temp dir)")
    args = parser.parse_args(argv)

    config = Config.from_env()
    if args.host is not None:
        config.host = args.host
    if args.port is not None:
        config.port = args.port
    if args.sandbox is not None:
        config.sandbox_dir = args.sandbox

    print(BANNER)
    try:
        app = create_app(config)
    except ExposureRefused as exc:
        print(f"\nRefusing to start: {exc}", file=sys.stderr)
        return 2
    print(f"VulnForge {__version__} serving on http://{config.host}:{config.port}")
    print("This application is deliberately insecure. Keep it on your own machine.\n")
    app.run(host=config.host, port=config.port, debug=False)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
