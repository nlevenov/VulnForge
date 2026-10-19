"""A01/A03 - SQL injection via string-built query (CWE-89)."""

from __future__ import annotations

from ..db import md5
from .base import Lesson, LessonContext, LessonResponse, register

VULN = '''def login(username, password):
    # String interpolation puts attacker input straight into SQL.
    query = (
        "SELECT * FROM users WHERE username = '%s' "
        "AND password_md5 = '%s'" % (username, md5(password))
    )
    row = db.execute(query).fetchone()      # ' OR '1'='1'-- bypasses auth
    return row'''

SECURE = '''def login(username, password):
    # Parameters are bound, never concatenated: input can only ever be data.
    row = db.execute(
        "SELECT * FROM users WHERE username = ? AND password_md5 = ?",
        (username, md5(password)),
    ).fetchone()
    return row'''


def _vuln(params: dict[str, str], ctx: LessonContext) -> LessonResponse:
    user = params.get("username", "")
    pw = params.get("password", "")
    query = (
        "SELECT username, role, secret_note FROM users "
        f"WHERE username = '{user}' AND password_md5 = '{md5(pw)}'"
    )
    try:
        rows = ctx.db.execute(query).fetchall()  # noqa: S608 - intentional (lesson)
    except Exception as exc:  # a broken query is itself a teachable signal
        return LessonResponse(output=f"SQL error: {exc}\n\nquery was:\n{query}",
                              detail="The raw error leaks query structure.")
    if not rows:
        return LessonResponse(output=f"No match.\n\nquery was:\n{query}",
                              detail="Login failed.")
    lines = [f"Logged in as {r['username']} ({r['role']}) :: {r['secret_note']}" for r in rows]
    flag = ctx.flags.get("sqli") if any(r["role"] == "admin" for r in rows) else None
    return LessonResponse(
        output="\n".join(lines) + f"\n\nquery was:\n{query}",
        flag=flag,
        detail="Returned rows without valid credentials - injection succeeded."
        if flag else "Authenticated.")


def _secure(params: dict[str, str], ctx: LessonContext) -> LessonResponse:
    user = params.get("username", "")
    pw = params.get("password", "")
    row = ctx.db.execute(
        "SELECT username, role, secret_note FROM users "
        "WHERE username = ? AND password_md5 = ?", (user, md5(pw))).fetchone()
    if not row:
        return LessonResponse(output="Invalid username or password.",
                              detail="Parameters bound; injection is inert.", status=401)
    return LessonResponse(output=f"Logged in as {row['username']} ({row['role']}).",
                          detail="Authenticated with bound parameters.")


def run(mode: str, params: dict[str, str], ctx: LessonContext) -> LessonResponse:
    return _vuln(params, ctx) if mode == "vuln" else _secure(params, ctx)


register(Lesson(
    id="sqli",
    title="SQL Injection",
    owasp="A03:2021 - Injection",
    cwe="CWE-89",
    difficulty="easy",
    summary="Authentication bypass through a string-built SQL query.",
    description=(
        "The vulnerable login concatenates the username and password straight into a SQL "
        "statement. Any apostrophe in the input ends the string literal and lets the rest of "
        "the field be interpreted as SQL. The fix binds every value as a parameter so input "
        "can never change the query's structure."),
    exploit_hint="Username: admin'--   Password: anything   (or  ' OR '1'='1'-- )",
    fix_explanation=(
        "Use parameterised queries (bound ? placeholders). The database driver keeps data and "
        "code separate, so a quote in the input stays a literal quote. Never build SQL with "
        "string formatting, and never show raw driver errors to users."),
    inputs=(("username", "Username", "admin'--", "text"),
            ("password", "Password", "anything", "text")),
    vuln_code=VULN, secure_code=SECURE, run=run, output_label="Login result"))
