"""Blast-radius containment for the vulnerable lessons.

Each primitive below is deliberately exploitable so a lesson can demonstrate a
real vulnerability, yet confined so the exploit stays inside a throwaway
sandbox and never reaches the real operating system, filesystem or network.
This containment is the point: it is how security training tooling is built
responsibly.
"""

from __future__ import annotations

import ipaddress
import shutil
from pathlib import Path
from urllib.parse import urlparse

# ----------------------------------------------------------------- filesystem


class PathJail:
    """A directory tree that path-traversal lessons operate within.

    ``public/`` holds files intended to be downloadable; ``secret/`` holds a
    file that should NOT be reachable. A vulnerable handler can be tricked into
    escaping ``public`` into ``secret`` (demonstrating traversal), but every
    resolved path is still clamped to the sandbox root, so an input like
    ``../../../../etc/passwd`` is stopped at the boundary instead of reading a
    real host file.
    """

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.public = self.root / "public"
        self.secret = self.root / "secret"

    def seed(self, flag: str) -> None:
        self.public.mkdir(parents=True, exist_ok=True)
        self.secret.mkdir(parents=True, exist_ok=True)
        (self.public / "welcome.txt").write_text(
            "Public document. Try downloading me, then try to reach something you should not.\n")
        (self.public / "report.txt").write_text("Quarterly report: all figures nominal.\n")
        (self.secret / "flag.txt").write_text(flag + "\n")

    def resolve_vulnerable(self, filename: str) -> tuple[Path | None, bool]:
        """Naive join (vulnerable), but clamped to the sandbox root.

        Returns (path, escaped_sandbox). ``escaped_sandbox`` is True when the
        input tried to leave the sandbox entirely - we refuse that and report
        it, which is where a real host would have leaked a system file.
        """
        candidate = (self.public / filename).resolve()
        if not str(candidate).startswith(str(self.root)):
            return None, True
        return candidate, False

    def resolve_secure(self, filename: str) -> Path | None:
        """Only ever serves a simple name from ``public`` - no traversal."""
        name = Path(filename).name
        if name != filename or name in ("", ".", ".."):
            return None
        candidate = (self.public / name).resolve()
        if candidate.parent != self.public or not candidate.is_file():
            return None
        return candidate


# -------------------------------------------------------------------- "shell"


class CommandEmulator:
    """A fake shell for the command-injection lesson.

    It parses shell metacharacters (``;`` ``|`` ``&&``) exactly as a real shell
    would, so unsanitised input chains extra commands - the vulnerability is
    genuine. But the "commands" are a tiny built-in table that only reads from
    this sandbox; no real process is ever spawned, so injected input cannot run
    anything on the host.
    """

    def __init__(self, jail: PathJail, flag: str) -> None:
        self.jail = jail
        self.flag = flag

    def run_vulnerable(self, user_input: str) -> str:
        # naive: build a "command line" by concatenating and then interpret the
        # whole thing, honouring separators the user may have injected
        command_line = f"ping -c 1 {user_input}"
        return self._interpret(command_line)

    def run_secure(self, user_input: str) -> str:
        # treat the input as a single opaque argument; never interpret separators
        host = user_input.strip()
        if not host or any(c in host for c in ";|&`$<>()\n"):
            return "Invalid host. Only a hostname or IP address is allowed."
        return self._ping(host)

    def _interpret(self, command_line: str) -> str:
        parts, buf = [], ""
        i = 0
        while i < len(command_line):
            two = command_line[i:i + 2]
            if two == "&&":
                parts.append(buf)
                buf = ""
                i += 2
                continue
            if command_line[i] in ";|":
                parts.append(buf)
                buf = ""
                i += 1
                continue
            buf += command_line[i]
            i += 1
        parts.append(buf)
        return "\n".join(self._exec(p.strip()) for p in parts if p.strip())

    def _exec(self, command: str) -> str:
        argv = command.split()
        if not argv:
            return ""
        name, args = argv[0], argv[1:]
        table = {
            "ping": lambda: self._ping(args[-1] if args else ""),
            "echo": lambda: " ".join(args),
            "whoami": lambda: "www-data",
            "id": lambda: "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            "uname": lambda: "Linux vulnforge 6.1.0 x86_64 GNU/Linux",
            "ls": self._ls,
            "cat": lambda: self._cat(args),
            "pwd": lambda: "/var/www/app",
        }
        handler = table.get(name)
        return handler() if handler else f"{name}: command not found"

    def _ping(self, host: str) -> str:
        host = host or "localhost"
        return (f"PING {host}: 56 data bytes\n"
                f"64 bytes from {host}: icmp_seq=0 ttl=64 time=0.040 ms\n"
                "1 packets transmitted, 1 received, 0% packet loss")

    def _ls(self) -> str:
        return "app.py\nconfig.py\nsecret"

    def _cat(self, args: list[str]) -> str:
        if not args:
            return "cat: missing operand"
        target = args[-1]
        # the injected `cat` can reach the sandbox flag, proving code execution
        if target.rstrip("/").endswith(("flag", "flag.txt")) or "secret" in target:
            return self.flag
        if "passwd" in target:
            return ("root:x:0:0:root:/root:/bin/bash\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin")
        return f"cat: {target}: No such file or directory"


# ------------------------------------------------------------------ "network"


class MockFetcher:
    """A fake HTTP client for the SSRF lesson.

    It never opens a socket. It routes a requested URL to a small set of
    mock responses, including a fake cloud-metadata service on a link-local
    address, so the lesson can demonstrate reaching an "internal" endpoint
    without the app ever touching the real network.
    """

    def __init__(self, flag: str) -> None:
        self.flag = flag

    def fetch_vulnerable(self, url: str) -> tuple[int, str]:
        return self._route(url)

    def fetch_secure(self, url: str) -> tuple[int, str]:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return 400, "Only http/https URLs are allowed."
        host = parsed.hostname or ""
        if self._is_internal(host):
            return 403, (f"Blocked: {host} is an internal/link-local address. "
                         "The secure fetcher refuses to reach private ranges (SSRF defence).")
        return self._route(url)

    @staticmethod
    def _is_internal(host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return host in ("localhost", "metadata.google.internal") or host.endswith(".internal")
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved

    def _route(self, url: str) -> tuple[int, str]:
        parsed = urlparse(url)
        host, path = parsed.hostname or "", parsed.path
        if host == "169.254.169.254":
            if "security-credentials" in path and path.rstrip("/").split("/")[-1]:
                return 200, ('{\n  "AccessKeyId": "AKIA' + "EXAMPLE1234567890" + '",\n'
                             '  "SecretAccessKey": "' + self.flag + '",\n'
                             '  "Token": "FQoGZXIvYXdz...TRUNCATED"\n}')
            return 200, "iam/\nsecurity-credentials/\nvulnforge-demo-role"
        if parsed.scheme in ("http", "https"):
            return 200, (f"<!doctype html><title>Mock page for {host}</title>"
                         f"<h1>Mock response</h1><p>VulnForge served a stub for {url} "
                         "(no real network request was made).</p>")
        return 400, "Unsupported URL."


def build_sandbox(root: Path, flags: dict[str, str]) -> dict[str, object]:
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    jail = PathJail(root)
    jail.seed(flags.get("path_traversal", "FLAG"))
    return {
        "jail": jail,
        "shell": CommandEmulator(jail, flags.get("cmdi", "FLAG")),
        "fetcher": MockFetcher(flags.get("ssrf", "FLAG")),
    }
