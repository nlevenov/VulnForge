"""Isolated, reset-on-start SQLite with entirely fake data.

The database lives in the throwaway sandbox (or in memory), is recreated every
run, and contains only invented users and content. Nothing here is real, and
nothing a lesson does to it can affect anything outside this file.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

SCHEMA = """
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS notes;
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    -- stored as an unsalted MD5 hash ON PURPOSE, to demonstrate CWE-916.
    password_md5 TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT NOT NULL,
    ssn TEXT NOT NULL,            -- fake "sensitive" data for the exposure lesson
    api_key TEXT NOT NULL,
    secret_note TEXT NOT NULL
);
CREATE TABLE notes (
    id INTEGER PRIMARY KEY,
    owner TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    private INTEGER NOT NULL DEFAULT 0
);
"""


def md5(text: str) -> str:
    # Deliberately weak, unsalted MD5: the "crypto failures" and "auth" lessons
    # exist to show why this is wrong and how to do it right. Not used for any
    # real security decision in this app.
    return hashlib.md5(text.encode()).hexdigest()  # noqa: S324  # nosec B324


def connect(sandbox_dir: Path | None, flags: dict[str, str]) -> sqlite3.Connection:
    path = ":memory:" if sandbox_dir is None else str(sandbox_dir / "vulnforge.db")
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    _seed(conn, flags)
    return conn


def _seed(conn: sqlite3.Connection, flags: dict[str, str]) -> None:
    users = [
        ("admin", "S3cr3tAdminPass!", "admin", "admin@vulnforge.test", "901-23-4567",
         "VF-ADMIN-APIKEY-7f3a9c", flags.get("sqli", "FLAG")),
        ("alice", "sunshine", "user", "alice@vulnforge.test", "078-05-1120",
         "VF-ALICE-APIKEY-11b2d4", "Nothing secret here."),
        ("bob", "password123", "user", "bob@vulnforge.test", "219-09-9999",
         "VF-BOB-APIKEY-55e1a0", "Nothing secret here."),
    ]
    conn.executemany(
        "INSERT INTO users (username, password_md5, role, email, ssn, api_key, secret_note) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(u[0], md5(u[1]), u[2], u[3], u[4], u[5], u[6]) for u in users])
    notes = [
        ("admin", "Infra credentials", "Rotate the gateway key quarterly.", 1),
        ("alice", "Shopping list", "Milk, eggs, bread.", 0),
        ("alice", "Private diary",
         f"My deepest secret and the flag you are looking for: {flags.get('idor', 'FLAG')}", 1),
        ("bob", "Weekend plans", "Hiking on Saturday.", 0),
    ]
    conn.executemany("INSERT INTO notes (owner, title, body, private) VALUES (?, ?, ?, ?)", notes)
    conn.commit()


# plaintext passwords are kept only in code (not the DB) so a lesson can show
# the real credential behind a cracked MD5 hash.
CREDENTIALS = {"admin": "S3cr3tAdminPass!", "alice": "sunshine", "bob": "password123"}
