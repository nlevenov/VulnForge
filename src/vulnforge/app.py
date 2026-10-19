"""Flask application factory for VulnForge.

The app binds to loopback only unless the operator explicitly opts into
exposure, resets its isolated sandbox and database on every start, and serves
each OWASP lesson as a side-by-side vulnerable/secure demonstration.
"""

from __future__ import annotations

import secrets
from typing import Any

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup

from .config import Config
from .db import connect
from .lessons import base as lessons
from .safety import BANNER, check_bind
from .sandbox import build_sandbox

# one invented flag per lesson; capturing one proves the exploit worked.
FLAGS: dict[str, str] = {
    "sqli": "VF{sql1_1nj3ct10n_bypass}",
    "xss_reflected": "VF{r3fl3ct3d_scr1pt_f1r3d}",
    "xss_stored": "VF{st0r3d_p3rs1st3nt_xss}",
    "idor": "VF{1d0r_br0k3n_acc3ss}",
    "auth": "VF{w3ak_auth_brut3_f0rc3d}",
    "cmdi": "VF{c0mmand_1nj3ct10n_rc3}",
    "path_traversal": "VF{dot_dot_sl@sh_tr@v3rsal}",
    "ssrf": "VF{ssrf_m3tadata_l00t}",
    "ssti": "VF{t3mpl@t3_1nj3ct10n_3val}",
    "open_redirect": "VF{0p3n_r3d1r3ct_ph1sh}",
    "sensitive_data": "VF{s3ns1t1v3_data_l3ak}",
}


def create_app(config: Config | None = None) -> Flask:
    config = config or Config()
    check_bind(config)  # refuse non-loopback binds unless explicitly allowed

    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.secret_key
    app.config["VF_CONFIG"] = config

    sandbox_dir = config.resolved_sandbox()
    app.config["VF_SANDBOX"] = build_sandbox(sandbox_dir / "files", FLAGS)
    app.config["VF_DB"] = connect(sandbox_dir, FLAGS)
    lessons.load_all()

    # Security headers, including a CSP that would stop the XSS demos from
    # reaching a real victim outside this learning context.
    @app.after_request
    def _headers(resp):  # type: ignore[no-untyped-def]
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
        return resp

    def _context() -> lessons.LessonContext:
        return lessons.LessonContext(
            db=app.config["VF_DB"],
            sandbox=app.config["VF_SANDBOX"],
            session=session.setdefault("state", {}),
            flags=FLAGS)

    def _captured() -> set[str]:
        return set(session.get("captured", []))

    @app.route("/")
    def home():  # type: ignore[no-untyped-def]
        groups: dict[str, list[Any]] = {}
        for lesson in lessons.all_lessons():
            groups.setdefault(lesson.owasp, []).append(lesson)
        return render_template("home.html", banner=BANNER, groups=groups,
                               captured=_captured(), total=len(FLAGS))

    @app.route("/lesson/<lesson_id>", methods=["GET", "POST"])
    def lesson_view(lesson_id: str):  # type: ignore[no-untyped-def]
        lesson = lessons.get_lesson(lesson_id)
        if lesson is None:
            abort(404)
        result = None
        mode = "vuln"
        if request.method == "POST":
            mode = "secure" if request.form.get("mode") == "secure" else "vuln"
            params = {name: request.form.get(name, "") for (name, *_rest) in lesson.inputs}
            session["state"] = session.get("state", {})
            result = lesson.run(mode, params, _context())
            session["state"] = _context().session
            if result.flag:
                captured = set(session.get("captured", []))
                captured.add(lesson.id)
                session["captured"] = sorted(captured)
        rendered_output = None
        if result is not None:
            # Deliberately render the vulnerable XSS lessons' output as raw markup:
            # this is the mechanism being taught. It is reached only for lessons that
            # set is_html, is confined to this localhost learning lab, and the secure
            # twin of each lesson escapes its output so nothing is rendered raw there.
            rendered_output = (
                Markup(result.output)  # noqa: S704  # nosec B704
                if result.is_html else result.output)
        return render_template(
            "lesson.html", banner=BANNER, lesson=lesson, result=result, mode=mode,
            rendered_output=rendered_output, captured=_captured(), total=len(FLAGS))

    @app.route("/reset", methods=["POST"])
    def reset():  # type: ignore[no-untyped-def]
        session.clear()
        app.config["VF_DB"] = connect(sandbox_dir, FLAGS)
        return redirect(url_for("home"))

    return app


def _nonce() -> str:  # pragma: no cover - trivial
    return secrets.token_hex(8)
