"""A03 - OS command injection (CWE-78). Runs against a fake in-process shell."""

from __future__ import annotations

from .base import Lesson, LessonContext, LessonResponse, register

VULN = '''@app.post("/ping")
def ping(host):
    # User input is interpolated into a shell command line.
    cmd = f"ping -c 1 {host}"
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
    #                          ^^^^^^^^^^  ;  cat /etc/secret  runs too'''

SECURE = '''@app.post("/ping")
def ping(host):
    if not re.fullmatch(r"[A-Za-z0-9.\\-]+", host):   # strict allowlist
        abort(400)
    # No shell, arguments passed as a list - the OS never parses metachars.
    return subprocess.run(["ping", "-c", "1", host],
                          shell=False, capture_output=True).stdout'''


def run(mode: str, params: dict[str, str], ctx: LessonContext) -> LessonResponse:
    host = params.get("host", "")
    shell = ctx.sandbox["shell"]
    if mode == "vuln":
        out = shell.run_vulnerable(host)
        flag = ctx.flags.get("cmdi") if (ctx.flags.get("cmdi") and ctx.flags["cmdi"] in out) else None
        return LessonResponse(
            output=out, flag=flag,
            detail="Injected command executed in the (emulated) shell."
            if flag else "Command executed in the emulated shell.")
    out = shell.run_secure(host)
    return LessonResponse(output=out,
                          detail="Input allowlisted and passed as argv - no shell parsing.")


register(Lesson(
    id="cmdi",
    title="Command Injection",
    owasp="A03:2021 - Injection",
    cwe="CWE-78",
    difficulty="medium",
    summary="Shell metacharacters in a 'ping' box run extra commands.",
    description=(
        "The vulnerable handler builds a shell command string from user input and runs it with "
        "shell=True, so a semicolon or pipe chains in a second command. This lesson runs entirely "
        "against an in-process emulated shell - no real process is ever spawned - yet it faithfully "
        "shows the injection. The fix allowlists the input and passes argv without a shell."),
    exploit_hint="Host:  8.8.8.8; cat /secret/flag.txt   (the ; starts a second command)",
    fix_explanation=(
        "Never pass user input through a shell. Execute with an argument list (shell=False) so the "
        "OS treats each argument as literal data, and validate against a strict allowlist. If a "
        "shell is truly unavoidable, quote every argument - but avoiding it is the real fix."),
    inputs=(("host", "Host to ping", "8.8.8.8; cat /secret/flag.txt", "text"),),
    vuln_code=VULN, secure_code=SECURE, run=run, output_label="Command output (emulated)"))
