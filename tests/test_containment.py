"""Containment tests: the real vulnerabilities must never affect anything
outside the sandbox - no host process, no filesystem escape, no live socket."""

import pathlib
import tempfile

from vulnforge.app import FLAGS
from vulnforge.sandbox import CommandEmulator, MockFetcher, PathJail, build_sandbox


def _jail():
    root = pathlib.Path(tempfile.mkdtemp()) / "files"
    return build_sandbox(root, FLAGS)


def test_command_injection_spawns_no_process(monkeypatch):
    import subprocess

    def _boom(*a, **k):  # any real spawn is a containment failure
        raise AssertionError("a real process was spawned by the emulator")

    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "call", _boom)
    shell = _jail()["shell"]
    out = shell.run_vulnerable("8.8.8.8; cat /secret/flag.txt")
    assert FLAGS["cmdi"] in out            # injection is still demonstrated
    assert isinstance(shell, CommandEmulator)


def test_path_traversal_cannot_escape_sandbox():
    jail: PathJail = _jail()["jail"]
    # climbing far past the root is clamped to None (no real host file)
    path, escaped = jail.resolve_vulnerable("../../../../../../etc/passwd")
    assert path is None and escaped is True
    # reaching the sandbox's own secret dir is allowed (that is the lesson)
    path, _ = jail.resolve_vulnerable("../secret/flag.txt")
    assert path is not None and jail.root in path.parents


def test_path_traversal_real_etc_passwd_never_read():
    jail: PathJail = _jail()["jail"]
    for probe in ("/etc/passwd", "../../../../etc/passwd", "....//....//etc/passwd"):
        path, _ = jail.resolve_vulnerable(probe)
        if path is not None:
            assert jail.root in path.resolve().parents  # still inside the sandbox


def test_ssrf_opens_no_socket(monkeypatch):
    import socket

    def _boom(*a, **k):
        raise AssertionError("MockFetcher opened a real socket")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    fetcher: MockFetcher = _jail()["fetcher"]
    status, body = fetcher.fetch_vulnerable(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/role")
    assert status == 200 and FLAGS["ssrf"] in body   # SSRF still demonstrated


def test_secure_paths_block_the_same_attacks():
    sb = _jail()
    assert FLAGS["cmdi"] not in sb["shell"].run_secure("8.8.8.8; cat /secret/flag.txt")
    assert sb["jail"].resolve_secure("../secret/flag.txt") is None
    status, body = sb["fetcher"].fetch_secure(
        "http://169.254.169.254/latest/meta-data/")
    assert status == 403 and FLAGS["ssrf"] not in body
