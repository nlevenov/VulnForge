"""A03 - Server-side template injection (CWE-94). Evaluated in a locked-down sandbox."""

from __future__ import annotations

from jinja2 import Environment
from jinja2.sandbox import SandboxedEnvironment

from .base import Lesson, LessonContext, LessonResponse, register

VULN = '''def greet(name):
    # User input becomes part of the template SOURCE, not the data.
    tmpl = Environment().from_string("Hello " + name + "!")
    return tmpl.render()          # {{7*7}} -> 49 ; access to object internals'''

SECURE = '''def greet(name):
    # Input is passed as data to a fixed template; it is never compiled.
    tmpl = Environment(autoescape=True).from_string("Hello {{ name }}!")
    return tmpl.render(name=name)'''

_UNSAFE = Environment(autoescape=False)  # noqa: S701 - deliberate (lesson)
_SANDBOX = SandboxedEnvironment(autoescape=True)


def run(mode: str, params: dict[str, str], ctx: LessonContext) -> LessonResponse:
    name = params.get("name", "")
    if mode == "vuln":
        try:
            # Confined to Jinja's own sandbox so arithmetic/introspection is shown
            # without exposing real builtins or the host.
            rendered = _SANDBOX.from_string("Hello " + name + "!").render()
        except Exception as exc:
            rendered = f"(template error: {exc})"
        evaluated = rendered != f"Hello {name}!"
        flag = ctx.flags.get("ssti") if evaluated else None
        return LessonResponse(
            output=rendered, flag=flag,
            detail="Your input was compiled as template code and evaluated."
            if evaluated else "Input compiled into the template source.")
    rendered = _SANDBOX.from_string("Hello {{ name }}!").render(name=name)
    return LessonResponse(output=rendered, detail="Input passed as data to a fixed template.")


register(Lesson(
    id="ssti",
    title="Template Injection (SSTI)",
    owasp="A03:2021 - Injection",
    cwe="CWE-94",
    difficulty="hard",
    summary="User input compiled as template code instead of passed as data.",
    description=(
        "The vulnerable greeter concatenates user input into the template source string, so the "
        "template engine compiles and evaluates it. An expression like {{7*7}} renders as 49 - and "
        "in an unrestricted engine the same door reaches object internals and code execution. This "
        "lesson evaluates inside Jinja's own locked-down sandbox so the concept is demonstrated "
        "safely. The fix keeps a fixed template and passes input only as render data."),
    exploit_hint="Name:  {{7*7}}   (if it echoes 49, your input was executed as code)",
    fix_explanation=(
        "Never build template source from user input. Keep templates static and pass user values as "
        "context data to render(). If users must supply templates, use a sandboxed environment with "
        "a strict allowlist - but static templates are the real fix."),
    inputs=(("name", "Your name", "{{7*7}}", "text"),),
    vuln_code=VULN, secure_code=SECURE, run=run, output_label="Greeting"))
