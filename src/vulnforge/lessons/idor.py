"""A01 - Insecure direct object reference / broken access control (CWE-639)."""

from __future__ import annotations

from .base import Lesson, LessonContext, LessonResponse, register

VULN = '''@app.get("/notes/<int:note_id>")
def read_note(note_id):
    # The note id comes from the URL and nothing checks ownership.
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    return note["body"]           # any id -> anyone's private note'''

SECURE = '''@app.get("/notes/<int:note_id>")
def read_note(note_id):
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if note is None:
        abort(404)
    # Authorisation check: the note must belong to the caller (or be public).
    if note["private"] and note["owner"] != session["user"]:
        abort(403)
    return note["body"]'''


def _lookup(ctx: LessonContext, note_id: int):
    return ctx.db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()


def run(mode: str, params: dict[str, str], ctx: LessonContext) -> LessonResponse:
    current = "bob"  # the logged-in demo user
    raw = params.get("note_id", "").strip()
    try:
        note_id = int(raw)
    except ValueError:
        return LessonResponse(output="note_id must be an integer.", status=400,
                              detail="Bad input.")
    note = _lookup(ctx, note_id)
    if note is None:
        return LessonResponse(output=f"No note with id {note_id}.", status=404, detail="Not found.")
    if mode == "vuln":
        leaked = note["private"] and note["owner"] != current
        flag = ctx.flags.get("idor") if (leaked and ctx.flags.get("idor") in note["body"]) else None
        return LessonResponse(
            output=f"[{note['owner']}] {note['title']}\n\n{note['body']}",
            flag=flag,
            detail=f"You are '{current}' but just read {note['owner']}'s private note."
            if leaked else "Note returned.")
    if note["private"] and note["owner"] != current:
        return LessonResponse(output="Forbidden: this note belongs to another user.",
                              status=403, detail="Ownership check blocked the access.")
    return LessonResponse(output=f"[{note['owner']}] {note['title']}\n\n{note['body']}",
                          detail="Authorised read.")


register(Lesson(
    id="idor",
    title="IDOR / Broken Access Control",
    owasp="A01:2021 - Broken Access Control",
    cwe="CWE-639",
    difficulty="easy",
    summary="Reading another user's private note by changing an id in the URL.",
    description=(
        "You are logged in as 'bob'. The vulnerable endpoint fetches a note by the id in the URL "
        "and never checks who owns it, so incrementing the id walks straight into other users' "
        "private notes. The fix adds a server-side ownership check on every access."),
    exploit_hint="You are 'bob'. Try note_id 1, 2, 3... one of them is alice's private diary.",
    fix_explanation=(
        "Enforce authorisation on every object access, server-side, keyed to the authenticated "
        "user - never trust an id from the client to imply permission. Unpredictable ids (UUIDs) "
        "help but are not a substitute for an access-control check."),
    inputs=(("note_id", "Note id", "3", "text"),),
    vuln_code=VULN, secure_code=SECURE, run=run, output_label="Note contents"))
