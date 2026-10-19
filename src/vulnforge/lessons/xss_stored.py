"""A03 - Stored cross-site scripting (CWE-79)."""

from __future__ import annotations

from markupsafe import escape

from .base import Lesson, LessonContext, LessonResponse, register

VULN = '''def add_comment(body):
    db.execute("INSERT INTO notes (owner, title, body, private) "
               "VALUES ('guest', 'comment', ?, 0)", (body,))

def show_comments():
    rows = db.execute("SELECT body FROM notes WHERE title='comment'")
    # Stored bodies are concatenated into the page unescaped.
    return "".join(f"<li>{r['body']}</li>" for r in rows)'''

SECURE = '''def show_comments():
    rows = db.execute("SELECT body FROM notes WHERE title='comment'")
    # Every stored value is escaped on the way out.
    return "".join(f"<li>{escape(r['body'])}</li>" for r in rows)'''


def run(mode: str, params: dict[str, str], ctx: LessonContext) -> LessonResponse:
    body = params.get("comment", "").strip()
    if body:
        ctx.db.execute(
            "INSERT INTO notes (owner, title, body, private) VALUES ('guest','comment',?,0)",
            (body,))
        ctx.db.commit()
    rows = ctx.db.execute("SELECT body FROM notes WHERE title='comment' ORDER BY id").fetchall()
    if mode == "vuln":
        html = "".join(f"<li>{r['body']}</li>" for r in rows) or "<li><i>no comments yet</i></li>"
        fired = any(("<script" in r["body"].lower() or "onerror" in r["body"].lower()
                     or "onload" in r["body"].lower()) for r in rows)
        return LessonResponse(
            output=f"<ul class='comments'>{html}</ul>", is_html=True,
            flag=ctx.flags.get("xss_stored") if fired else None,
            detail="A stored comment contains live markup - it executes for every visitor."
            if fired else "Comments stored and rendered without escaping.")
    html = "".join(f"<li>{escape(r['body'])}</li>" for r in rows) or "<li><i>no comments yet</i></li>"
    return LessonResponse(output=f"<ul class='comments'>{html}</ul>", is_html=True,
                          detail="Stored values escaped on output; markup is inert.")


register(Lesson(
    id="xss_stored",
    title="Stored XSS",
    owasp="A03:2021 - Injection",
    cwe="CWE-79",
    difficulty="medium",
    summary="A persisted comment executes in every visitor's browser.",
    description=(
        "Comments are saved to the database and later rendered into the page without escaping. "
        "Unlike reflected XSS, the payload is stored once and fires for everyone who views the "
        "page. The secure version escapes each value on output."),
    exploit_hint="Post a comment:  <script>alert(document.domain)</script>  then reload - it fires every time.",
    fix_explanation=(
        "Escape on output, not on input (so the stored data stays faithful). Autoescaping "
        "templates handle this; a CSP that forbids inline script blocks the payload even if one "
        "slips through. Validate/limit what you store, but never rely on input filtering alone."),
    inputs=(("comment", "New comment", "<script>alert(document.domain)</script>", "text"),),
    vuln_code=VULN, secure_code=SECURE, run=run, output_label="Comment wall"))
