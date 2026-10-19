# VulnForge

**An intentionally vulnerable web application for learning the OWASP Top 10 — attack it, then see exactly how to defend it.**

VulnForge is a hands-on security lab. Every lesson exposes the *same* feature twice: once written the insecure way and once written correctly. You run a real exploit against the vulnerable version to capture its flag, then flip a switch and watch the identical attack bounce off the secure version. The point is not just to break things — it is to understand, line by line, why the vulnerable code fails and what the fix actually does.

> ⚠️ **This application is deliberately insecure by design.** It exists to be exploited in a controlled, local setting. It binds to `127.0.0.1` only, refuses to start on a public interface unless you explicitly override it, and uses a disposable sandbox and fake data. **Never deploy it, never expose it to a network, and never point it at real data or credentials.**

---

## Why this project exists

Reading about SQL injection is not the same as watching `admin'--` walk straight past a login form — and then watching the parameterised version shrug off the exact same input. VulnForge was built to make that contrast concrete for all eleven of the vulnerability classes below, in a way that is safe to run, easy to reason about, and honest about both the attack and the defence.

It is equal parts offensive and defensive: each lesson proves the exploit works *and* ships the production-grade fix beside it, with an automated test suite that asserts both halves on every commit.

## The lessons

| # | Lesson | OWASP 2021 | CWE | What you exploit |
|---|--------|-----------|-----|------------------|
| 1 | SQL Injection | A03 Injection | CWE-89 | Bypass login with a string-built query |
| 2 | Reflected XSS | A03 Injection | CWE-79 | Run script reflected from a query parameter |
| 3 | Stored XSS | A03 Injection | CWE-79 | Persist a payload that fires for every visitor |
| 4 | IDOR / Broken Access Control | A01 Broken Access Control | CWE-639 | Read another user's private record by its id |
| 5 | Authentication Failures | A07 Auth Failures | CWE-307/916 | Brute-force unsalted-MD5 logins with no lockout |
| 6 | Command Injection | A03 Injection | CWE-78 | Chain a second OS command through an input |
| 7 | Path Traversal | A01 Broken Access Control | CWE-22 | Escape a directory with `../` sequences |
| 8 | Server-Side Request Forgery | A10 SSRF | CWE-918 | Make the server fetch an internal metadata endpoint |
| 9 | Template Injection (SSTI) | A03 Injection | CWE-94 | Get user input evaluated as template code |
| 10 | Open Redirect | A01 Broken Access Control | CWE-601 | Bounce a trusted link to an attacker's site |
| 11 | Sensitive Data Exposure | A02/A05 | CWE-200/215 | Pull secrets out of an over-sharing endpoint |

Each lesson page shows the vulnerable source, the secure source, an exploit hint, and a plain-English explanation of the fix — then lets you run either implementation against your own input and see the result rendered live.

## How the vulnerabilities are kept safe

The vulnerabilities are **real** — they genuinely work — but their blast radius is contained so that running the lab can never harm the host:

- **Command injection** runs against an in-process command *emulator*. The injection fires and reveals the flag, but **no real OS process is ever spawned** (a test asserts this by poisoning `subprocess`).
- **Path traversal** operates inside a disposable sandbox directory. `../` genuinely escapes the "public" folder into a "secret" one, but attempts to climb past the sandbox root are clamped — **no real host file is ever read** (asserted against `/etc/passwd`).
- **SSRF** uses a mock fetcher that returns invented internal responses. The attack reaches the "metadata endpoint" and leaks fake credentials, but **no socket is ever opened** (asserted by poisoning `socket`).
- **SSTI** is evaluated inside Jinja's own sandboxed environment, so the injection is demonstrated without exposing real builtins.
- The **database** is an isolated SQLite instance seeded with entirely fake users and content. It is reset on demand and never touches a real datastore.
- The app sends hardening headers (including a strict **Content-Security-Policy**) on every response, so even the XSS payloads cannot reach a real victim outside the lab.

## Safety guard

VulnForge refuses to serve to anything but loopback. Starting it on a routable interface raises `ExposureRefused` unless you set an explicit, deliberately awkward opt-in:

```bash
VULNFORGE_ALLOW_EXPOSURE=yes-i-understand vulnforge --host 0.0.0.0
```

If you find yourself typing that, stop and reconsider: this application is built to be exploited.

## Install & run

Requires Python 3.10+.

```bash
git clone https://github.com/nlevenov/VulnForge.git
cd VulnForge
pip install -e .
vulnforge
```

Then open <http://127.0.0.1:8000> and start with the SQL Injection lesson.

### Options

```
vulnforge --host 127.0.0.1 --port 8000 --sandbox /path/to/tmpdir
```

| Env var | Meaning | Default |
|---------|---------|---------|
| `VULNFORGE_HOST` | Bind host | `127.0.0.1` |
| `VULNFORGE_PORT` | Bind port | `8000` |
| `VULNFORGE_SANDBOX` | Sandbox directory | a fresh temp dir |
| `VULNFORGE_ALLOW_EXPOSURE` | Set to `yes-i-understand` to permit a non-loopback bind | off |

### Docker

```bash
docker compose up --build
# serves on http://127.0.0.1:8000 (published to loopback only)
```

## Development

```bash
pip install -e ".[dev]"
pytest            # 49 tests: every exploit proven + containment + web layer
ruff check .      # lint
bandit -r src -c pyproject.toml   # SAST (intentional lesson code is scoped out)
pip-audit -r requirements.txt     # dependency advisories
```

### The test contract

The suite is the heart of the project. For **every** lesson it asserts:

1. the exploit **captures the flag** against the vulnerable implementation,
2. the identical exploit is **blocked** against the secure implementation, and
3. **benign input never** trips the flag.

Plus dedicated containment tests proving no process is spawned, no file escapes the sandbox, and no socket is opened. If a fix ever stops working — or a "vulnerable" demo ever stops being exploitable — CI goes red.

## Project layout

```
src/vulnforge/
  app.py            Flask factory, routes, security headers, flag tracking
  cli.py            command-line entry point
  config.py         configuration + loopback detection
  safety.py         the bind guard (refuses non-loopback by default)
  sandbox.py        containment: command emulator, path jail, mock fetcher
  db.py             isolated, reset-on-start SQLite with fake data
  lessons/          one module per OWASP topic (vulnerable + secure twin)
  templates/        home + lesson UI
  static/           styling
tests/              proof tests, containment tests, web + safety tests
```

## Disclaimer

VulnForge is for education and authorised security training on your own machine. The author is not responsible for any misuse. Do not run it against systems you do not own, and do not expose it to untrusted networks.

## License

MIT — see [LICENSE](LICENSE).
