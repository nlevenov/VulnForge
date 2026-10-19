"""A03 - Reflected cross-site scripting (CWE-79)."""

from __future__ import annotations

from markupsafe import escape

from .base import Lesson, LessonContext, LessonResponse, register

VULN = '''@app.get("/search")
def search(q):
    # The query is dropped into the HTML response unescaped.
    return f"<p>No results for <b>{q}</b></p>"   # <script> runs in the browser'''

SECURE = '''@app.get("/search")
def search(q):
    # markupsafe.escape turns < > & " into entities before they reach HTML.
    return f"<p>No results for <b>{escape(q)}</b></p>"'''


def run(mode: str, params: dict[str, str], ctx: LessonContext) -> LessonResponse:
    q = params.get("q", "")
    if mode == "vuln":
        body = f'<div class="reflect">No results for <b>{q}</b></div>'
        fired = "<script" in q.lower() or "onerror" in q.lower() or "onload" in q.lower()
        return LessonResponse(
            output=body, is_html=True,
            flag=ctx.flags.get("xss_reflected") if fired else None,
            detail="Your markup was reflected verbatim and will execute."
            if fired else "Input reflected without escaping.")
    safe = escape(q)
    return LessonResponse(
        output=f'<div class="reflect">No results for <b>{safe}</b></div>', is_html=True,
        detail="Input HTML-escaped; the browser renders it as text.")


register(Lesson(
    id="xss_reflected",
    title="Reflected XSS",
    owasp="A03:2021 - Injection",
    cwe="CWE-79",
    difficulty="easy",
    summary="Unescaped user input reflected into an HTML response.",
    description=(
        "The vulnerable search page echoes the query parameter directly into the HTML it "
        "returns. A query containing a script tag or an event handler is parsed as markup and "
        "executes in the victim's browser. The fix HTML-escapes the value so it is rendered as "
        "inert text."),
    exploit_hint="Search for:  <img src=x onerror=alert(document.domain)>  or  <script>alert(1)</script>",
    fix_explanation=(
        "Contextually escape all user data on output. Templating engines that autoescape (Jinja2 "
        "here, markupsafe under the hood) do this for you; never mark untrusted data safe and never "
        "build HTML with raw string formatting. A strict Content-Security-Policy is defence in depth."),
    inputs=(("q", "Search query", "<img src=x onerror=alert(document.domain)>", "text"),),
    vuln_code=VULN, secure_code=SECURE, run=run, output_label="Rendered page fragment"))
