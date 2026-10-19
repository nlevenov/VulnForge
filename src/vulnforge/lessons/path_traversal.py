"""A01 - Path traversal (CWE-22). Confined to the throwaway sandbox."""

from __future__ import annotations

from .base import Lesson, LessonContext, LessonResponse, register

VULN = '''@app.get("/download")
def download(filename):
    # Joins user input onto a base dir without normalising it.
    path = os.path.join(PUBLIC_DIR, filename)
    return open(path).read()          # ../secret/flag.txt escapes PUBLIC_DIR'''

SECURE = '''@app.get("/download")
def download(filename):
    # Reject separators outright, then verify the resolved path stays inside.
    name = os.path.basename(filename)
    if name != filename:
        abort(400)
    full = (PUBLIC_DIR / name).resolve()
    if PUBLIC_DIR.resolve() not in full.parents:
        abort(403)
    return full.read_text()'''


def run(mode: str, params: dict[str, str], ctx: LessonContext) -> LessonResponse:
    filename = params.get("filename", "")
    jail = ctx.sandbox["jail"]
    if mode == "vuln":
        path, escaped_sandbox = jail.resolve_vulnerable(filename)
        if path is None:
            return LessonResponse(
                output="(blocked at the host boundary by the sandbox - no real file was read)",
                detail="Traversal left the sandbox and was clamped; nothing real is exposed.")
        if not path.is_file():
            return LessonResponse(output=f"'{filename or '.'}' is not a readable file.",
                                  status=400, detail="No such file in the sandbox.")
        text = path.read_text()
        reached_secret = "secret" in str(path.relative_to(jail.root))
        flag = ctx.flags.get("path_traversal") if (
            reached_secret and ctx.flags.get("path_traversal") in text) else None
        return LessonResponse(output=f"{path.relative_to(jail.root)}:\n\n{text}", flag=flag,
                              detail="Traversed out of the public dir into a restricted file."
                              if flag else "File served.")
    path = jail.resolve_secure(filename)
    if path is None:
        return LessonResponse(output="Forbidden: filename must be a simple name with no path separators.",
                              status=403, detail="Separators rejected; traversal impossible.")
    return LessonResponse(output=f"{path.name}:\n\n{path.read_text()}", detail="Served from public dir only.")


register(Lesson(
    id="path_traversal",
    title="Path Traversal",
    owasp="A01:2021 - Broken Access Control",
    cwe="CWE-22",
    difficulty="easy",
    summary="Reading files outside the intended directory with ../ sequences.",
    description=(
        "The vulnerable download joins the requested filename onto a base directory without "
        "normalising it, so ../ sequences climb out and reach restricted files. Everything here "
        "happens inside a disposable sandbox directory - attempts to leave it entirely are clamped, "
        "so no real host file is ever exposed. The fix strips separators and verifies the resolved "
        "path stays inside the base directory."),
    exploit_hint="Filename:  ../secret/flag.txt",
    fix_explanation=(
        "Treat the filename as a bare name (os.path.basename), then resolve the final path and "
        "confirm it is inside the intended root before opening. Reject anything with separators or "
        "'..'. Prefer serving by an opaque id mapped server-side to a known-safe path."),
    inputs=(("filename", "File to download", "../secret/flag.txt", "text"),),
    vuln_code=VULN, secure_code=SECURE, run=run, output_label="File contents (sandboxed)"))
