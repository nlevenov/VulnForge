"""A01 - Unvalidated redirect (CWE-601)."""

from __future__ import annotations

from urllib.parse import urlparse

from .base import Lesson, LessonContext, LessonResponse, register

VULN = '''@app.get("/go")
def go(next):
    # Redirects anywhere the "next" parameter points.
    return redirect(next)         # ?next=https://evil.example/phish'''

SECURE = '''ALLOWED_HOSTS = {"", "vulnforge.test"}   # empty host == same-site path

@app.get("/go")
def go(next):
    parsed = urlparse(next)
    # Allow only same-site relative paths (no scheme, no host).
    if parsed.scheme or parsed.netloc not in ALLOWED_HOSTS:
        return redirect("/")
    return redirect(next)'''

_ALLOWED = {"", "vulnforge.test"}


def run(mode: str, params: dict[str, str], ctx: LessonContext) -> LessonResponse:
    nxt = params.get("next", "")
    parsed = urlparse(nxt)
    offsite = bool(parsed.scheme or parsed.netloc)
    if mode == "vuln":
        flag = ctx.flags.get("open_redirect") if offsite else None
        return LessonResponse(
            output=f"302 Location: {nxt}", status=302, flag=flag,
            detail=f"Redirecting off-site to {parsed.netloc or nxt} - usable for phishing."
            if offsite else f"Redirecting to {nxt}.")
    if parsed.scheme or parsed.netloc not in _ALLOWED:
        return LessonResponse(output="302 Location: /  (off-site target rejected)", status=302,
                              detail="Only same-site relative paths are allowed.")
    return LessonResponse(output=f"302 Location: {nxt}", status=302, detail="Same-site redirect allowed.")


register(Lesson(
    id="open_redirect",
    title="Open Redirect",
    owasp="A01:2021 - Broken Access Control",
    cwe="CWE-601",
    difficulty="easy",
    summary="A redirect endpoint that will forward users to any external site.",
    description=(
        "The vulnerable endpoint redirects to whatever the 'next' parameter contains. Attackers "
        "wrap it in a link on the trusted domain that bounces victims to a phishing page, lending "
        "their lookalike the trust of your domain. The fix allows only same-site relative paths."),
    exploit_hint="next=https://evil.example/login   (the trusted link silently sends users off-site)",
    fix_explanation=(
        "Validate redirect targets against an allowlist, or accept only relative same-site paths "
        "(reject any value with a scheme or host). If external redirects are genuinely needed, show "
        "an interstitial so users know they are leaving."),
    inputs=(("next", "Redirect target", "https://evil.example/login", "text"),),
    vuln_code=VULN, secure_code=SECURE, run=run, output_label="Redirect response"))
