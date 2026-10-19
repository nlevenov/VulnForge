"""Runtime configuration. Secure, contained defaults."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


@dataclass
class Config:
    host: str = "127.0.0.1"
    port: int = 8000
    # Explicit acknowledgement required before binding to anything but loopback.
    allow_exposure: bool = False
    # Per-process random key; sessions do not need to survive a restart here.
    secret_key: str = field(default_factory=lambda: secrets.token_hex(32))
    # Sandbox root for the contained command emulator, file jail and database.
    sandbox_dir: str = ""
    debug: bool = False

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            host=os.environ.get("VULNFORGE_HOST", "127.0.0.1"),
            port=int(os.environ.get("VULNFORGE_PORT", "8000")),
            allow_exposure=os.environ.get("VULNFORGE_ALLOW_EXPOSURE", "") == "yes-i-understand",
            sandbox_dir=os.environ.get("VULNFORGE_SANDBOX", ""),
        )

    @property
    def is_loopback(self) -> bool:
        return self.host in LOOPBACK

    def resolved_sandbox(self) -> Path:
        if self.sandbox_dir:
            return Path(self.sandbox_dir)
        import tempfile

        return Path(tempfile.gettempdir()) / f"vulnforge-sandbox-{os.getpid()}"
