# VulnForge architecture

VulnForge is a small Flask application whose design goal is unusual: it must contain **real, working vulnerabilities** while guaranteeing they cannot harm the host it runs on. The architecture is organised around that tension.

## Request flow

```
browser ──► Flask route (app.py)
               │
               ├─ loads the Lesson (lessons/<topic>.py)
               ├─ builds a LessonContext { db, sandbox, session, flags }
               └─ calls lesson.run(mode, params, ctx)
                        │
          mode="vuln" ──┤── exploit succeeds ──► flag captured
        mode="secure" ──┘── exploit blocked
```

Every lesson implements the **same feature twice** behind one `run(mode, ...)` entry point. The web UI and the test suite drive lessons through that identical interface, which is what lets the tests assert "exploit works on vuln, fails on secure" uniformly across all eleven topics.

## The containment layer (`sandbox.py`)

This is the security-critical module. It provides three primitives that make dangerous-looking operations safe:

- **`CommandEmulator`** — a fake shell with a small built-in command table. It honours shell metacharacters (`;`, `|`, `&&`) so command injection genuinely "works" and reveals the flag, but it never calls `subprocess` or spawns a process.
- **`PathJail`** — a disposable directory tree with `public/` and `secret/` subfolders. The vulnerable resolver performs a naive join so `../` escapes `public/` into `secret/` (the lesson), but any path that would leave the sandbox root is clamped to `None` — the real filesystem is never reached.
- **`MockFetcher`** — a URL router returning invented responses, including fake cloud-metadata credentials for `169.254.169.254`. It demonstrates SSRF without ever opening a socket.

`build_sandbox()` wipes and recreates the sandbox on each start, so state never leaks between runs.

## Data (`db.py`)

An isolated SQLite database seeded with entirely fictional users and notes. It is recreated (tables dropped and reseeded) on start and on reset. Passwords are stored as unsalted MD5 **on purpose** — the "crypto failures" and "auth" lessons exist to show why that is wrong.

## Safety guard (`safety.py`, `config.py`)

`check_bind()` runs in the app factory and raises `ExposureRefused` unless the bind host is loopback or the operator has set `VULNFORGE_ALLOW_EXPOSURE=yes-i-understand`. This makes accidental network exposure impossible by default.

## Defence-in-depth headers (`app.py`)

Every response carries `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, and a strict `Content-Security-Policy`. Even the XSS lessons, which render raw markup to demonstrate the flaw, are wrapped in a CSP that would stop the payload from reaching a real victim outside the lab.

## Keeping the scanners honest

The intentionally-vulnerable code lives only under `src/vulnforge/lessons/`, which is the single directory scoped out of `ruff`'s `S` rules and `bandit`. Two more deliberate items — the MD5 helper and the raw-markup render that powers the XSS demos — carry inline `# nosec` / `# noqa` annotations with justifications. Everything else in the codebase is held to a clean bar, so a genuine new finding outside the lessons will fail CI.
