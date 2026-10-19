"""The lesson abstraction.

A lesson is a self-contained OWASP topic exposing the *same* feature twice: a
``vulnerable`` implementation and a ``secure`` one, plus the metadata, code
snippets and explanation that turn it into a teaching artifact. The web UI and
the test suite both drive lessons through ``run(mode, params, ctx)``.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LessonContext:
    db: sqlite3.Connection
    sandbox: dict[str, Any]
    session: dict[str, Any] = field(default_factory=dict)
    flags: dict[str, str] = field(default_factory=dict)


@dataclass
class LessonResponse:
    output: str                      # text/HTML result shown to the user
    is_html: bool = False            # True -> rendered raw (this is how XSS demos fire)
    flag: str | None = None          # set when the exploit succeeded
    detail: str = ""                 # short note on what just happened
    status: int = 200


@dataclass
class Lesson:
    id: str
    title: str
    owasp: str
    cwe: str
    difficulty: str                  # easy | medium | hard
    summary: str
    description: str
    exploit_hint: str
    fix_explanation: str
    # the feature's input fields, as (name, label, placeholder, kind)
    inputs: tuple[tuple[str, str, str, str], ...]
    vuln_code: str
    secure_code: str
    run: Callable[[str, dict[str, str], LessonContext], LessonResponse]
    output_label: str = "Response"


REGISTRY: dict[str, Lesson] = []  # type: ignore[assignment]
_ORDER: list[Lesson] = []


def register(lesson: Lesson) -> Lesson:
    if any(existing.id == lesson.id for existing in _ORDER):
        raise ValueError(f"duplicate lesson id {lesson.id}")
    _ORDER.append(lesson)
    return lesson


def all_lessons() -> list[Lesson]:
    return list(_ORDER)


def get_lesson(lesson_id: str) -> Lesson | None:
    return next((lesson for lesson in _ORDER if lesson.id == lesson_id), None)


def load_all() -> None:
    from . import (  # noqa: F401
        auth,
        cmdi,
        idor,
        open_redirect,
        path_traversal,
        sensitive_data,
        sqli,
        ssrf,
        ssti,
        xss_reflected,
        xss_stored,
    )
