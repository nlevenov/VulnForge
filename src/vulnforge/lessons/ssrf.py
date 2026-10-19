"""A10 - Server-side request forgery (CWE-918). Uses a mock fetcher, no sockets."""

from __future__ import annotations

from .base import Lesson, LessonContext, LessonResponse, register

VULN = '''@app.post("/fetch")
def fetch(url):
    # The server fetches whatever URL the user supplies.
    return httpx.get(url).text        # http://169.254.169.254/... -> cloud creds'''

SECURE = '''@app.post("/fetch")
def fetch(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        abort(400)
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    # Block loopback, private, link-local and reserved ranges.
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        abort(403)
    return httpx.get(url).text'''


def run(mode: str, params: dict[str, str], ctx: LessonContext) -> LessonResponse:
    url = params.get("url", "")
    fetcher = ctx.sandbox["fetcher"]
    if mode == "vuln":
        status, body = fetcher.fetch_vulnerable(url)
        flag = ctx.flags.get("ssrf") if (ctx.flags.get("ssrf") and ctx.flags["ssrf"] in body) else None
        return LessonResponse(output=f"HTTP {status}\n\n{body}", status=status, flag=flag,
                              detail="Server fetched an internal-only endpoint (mocked)."
                              if flag else "Fetched (mocked response).")
    status, body = fetcher.fetch_secure(url)
    return LessonResponse(output=f"HTTP {status}\n\n{body}", status=status,
                          detail="Destination validated against internal ranges before fetch.")


register(Lesson(
    id="ssrf",
    title="Server-Side Request Forgery",
    owasp="A10:2021 - Server-Side Request Forgery",
    cwe="CWE-918",
    difficulty="hard",
    summary="Making the server fetch an internal cloud-metadata endpoint.",
    description=(
        "The vulnerable 'fetch a URL' feature will request any address the user gives it, including "
        "internal services like the cloud metadata endpoint at 169.254.169.254 that return "
        "credentials. This lesson uses a mock fetcher that NEVER opens a real socket - the internal "
        "responses are invented - so it demonstrates SSRF with zero real network access. The fix "
        "resolves and validates the destination, blocking private and link-local ranges."),
    exploit_hint="URL:  http://169.254.169.254/latest/meta-data/iam/security-credentials/role",
    fix_explanation=(
        "Validate the destination after DNS resolution and block loopback, private, link-local and "
        "reserved IP ranges (mind DNS-rebinding and redirects - re-check every hop). Prefer an "
        "allowlist of permitted hosts, disable unneeded URL schemes, and never return raw internal "
        "responses to the caller."),
    inputs=(("url", "URL to fetch", "http://169.254.169.254/latest/meta-data/iam/security-credentials/role", "text"),),
    vuln_code=VULN, secure_code=SECURE, run=run, output_label="Fetched response (mocked)"))
