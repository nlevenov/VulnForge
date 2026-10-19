"""A02 / A05 - Sensitive data exposure & misconfiguration (CWE-200 / CWE-215)."""

from __future__ import annotations

from markupsafe import escape

from .base import Lesson, LessonContext, LessonResponse, register

VULN = '''@app.get("/profile")
def profile(username):
    row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    # SELECT * dumps every column - including ssn, api_key, password hash.
    return dict(row)

app.run(debug=True)   # debug console + full tracebacks exposed to the world'''

SECURE = '''@app.get("/profile")
def profile(username):
    row = db.execute("SELECT username, role, email FROM users WHERE username=?",
                     (username,)).fetchone()
    return {"username": row["username"], "role": row["role"], "email": row["email"]}

app.run(debug=False)  # no debug console; generic error pages only'''


def run(mode: str, params: dict[str, str], ctx: LessonContext) -> LessonResponse:
    user = params.get("username", "")
    row = ctx.db.execute("SELECT * FROM users WHERE username=?", (user,)).fetchone()
    if row is None:
        return LessonResponse(output=f"No such user '{user}'.", status=404, detail="Not found.")
    if mode == "vuln":
        dump = "\n".join(f"{k}: {v}" for k, v in dict(row).items())
        return LessonResponse(
            output=dump, flag=ctx.flags.get("sensitive_data"),
            detail="SELECT * leaked ssn, api_key and the password hash to an unauthenticated caller.")
    safe = {"username": row["username"], "role": row["role"], "email": escape(row["email"])}
    dump = "\n".join(f"{k}: {v}" for k, v in safe.items())
    return LessonResponse(output=dump, detail="Only non-sensitive fields returned; debug disabled.")


register(Lesson(
    id="sensitive_data",
    title="Sensitive Data Exposure",
    owasp="A02:2021 - Cryptographic Failures / A05 - Misconfiguration",
    cwe="CWE-200, CWE-215",
    difficulty="easy",
    summary="A profile endpoint that returns every column, secrets included.",
    description=(
        "The vulnerable profile endpoint runs SELECT * and serialises the whole row, so SSNs, API "
        "keys and password hashes leak to anyone. Paired with debug mode left on, tracebacks and a "
        "live console compound the exposure. The fix returns only the fields the caller needs and "
        "disables debug."),
    exploit_hint="Look up username 'admin' and read the fields that should never leave the server.",
    fix_explanation=(
        "Return only the fields a response needs - never SELECT * into a payload. Keep secrets out "
        "of responses and logs, encrypt sensitive data at rest, and disable debug/verbose errors in "
        "production so stack traces and consoles are never exposed."),
    inputs=(("username", "Username", "admin", "text"),),
    vuln_code=VULN, secure_code=SECURE, run=run, output_label="Profile data"))
