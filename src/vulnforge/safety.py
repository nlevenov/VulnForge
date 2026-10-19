"""Guards that keep this intentionally-vulnerable app from becoming a hazard.

Two independent layers:
  1. It refuses to bind anywhere but loopback unless the operator explicitly
     opts in, so it is not accidentally exposed to a network.
  2. Everything a lesson can reach - the database, the file "download" area,
     the "shell", outbound "fetches" - is confined to a throwaway sandbox, so
     even successfully exploiting a vulnerable endpoint cannot touch the real
     host, its filesystem or its network.
"""

from __future__ import annotations

from .config import Config

BANNER = r"""
  ##################################################################
  #  VulnForge - INTENTIONALLY VULNERABLE training application     #
  #  Run on localhost only. Never deploy on a reachable network.   #
  #  Every vulnerability is sandboxed and cannot harm this host.   #
  ##################################################################
"""


class ExposureRefused(RuntimeError):
    """Raised when asked to bind to a non-loopback address without opt-in."""


def check_bind(config: Config) -> None:
    if config.is_loopback or config.allow_exposure:
        return
    raise ExposureRefused(
        f"Refusing to bind to {config.host}: VulnForge is intentionally vulnerable and must "
        "stay on localhost. If you are in an isolated lab and really mean it, set "
        "VULNFORGE_ALLOW_EXPOSURE=yes-i-understand (and understand the risk)."
    )
