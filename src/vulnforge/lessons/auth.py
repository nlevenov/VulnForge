"""A07 - Identification & authentication failures (CWE-307 / CWE-916)."""

from __future__ import annotations

import hashlib
import hmac
import time

from ..db import CREDENTIALS
from .base import Lesson, LessonContext, LessonResponse, register

VULN = '''ATTEMPTS = []  # no rate limiting, no lockout

def login(username, password):
    ATTEMPTS.append(username)                 # unlimited guesses
    row = db.execute("SELECT password_md5 FROM users WHERE username=?",
                     (username,)).fetchone()
    # Unsalted MD5 + early-return string compare (timing + weak hash).
    return row and row["password_md5"] == md5(password)'''

SECURE = '''BUCKET = {}  # per-account attempt counter

def login(username, password):
    if BUCKET.get(username, 0) >= 5:
        raise TooManyAttempts()               # lockout after 5 failures
    row = db.execute("SELECT pw_hash, salt FROM users WHERE username=?",
                     (username,)).fetchone()
    # Salted scrypt + constant-time comparison; generic error either way.
    ok = row and hmac.compare_digest(
        scrypt(password, row["salt"]), row["pw_hash"])
    BUCKET[username] = 0 if ok else BUCKET.get(username, 0) + 1
    return ok'''


def _scrypt(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)


def run(mode: str, params: dict[str, str], ctx: LessonContext) -> LessonResponse:
    user = params.get("username", "")
    pw = params.get("password", "")
    bucket = ctx.session.setdefault("auth_attempts", {})
    if mode == "vuln":
        row = ctx.db.execute("SELECT password_md5, role FROM users WHERE username=?",
                             (user,)).fetchone()
        from ..db import md5
        n = bucket.get(user, 0) + 1
        bucket[user] = n
        ok = bool(row) and row["password_md5"] == md5(pw)
        flag = ctx.flags.get("auth") if (ok and user == "admin") else None
        note = (f"Attempt #{n} for '{user}' - no lockout, unsalted MD5. "
                "An offline wordlist cracks these instantly.")
        if ok:
            return LessonResponse(output=f"Welcome back, {user} ({row['role']}).", flag=flag,
                                  detail=note + (" Admin reached." if flag else ""))
        return LessonResponse(output=f"Login failed for '{user}'. ({n} attempts, still allowed)",
                              status=401, detail=note)
    # secure path
    if bucket.get(user, 0) >= 5:
        return LessonResponse(output="Account temporarily locked after 5 failed attempts.",
                              status=429, detail="Lockout stops online brute force.")
    real = CREDENTIALS.get(user)
    salt = (user or "x").encode().ljust(16, b"0")[:16]
    ok = real is not None and hmac.compare_digest(_scrypt(pw, salt), _scrypt(real, salt))
    time.sleep(0)  # scrypt itself dominates timing; comparison is constant-time
    if ok:
        bucket[user] = 0
        return LessonResponse(output=f"Welcome back, {user}.",
                              detail="Salted scrypt + constant-time compare + lockout.")
    bucket[user] = bucket.get(user, 0) + 1
    return LessonResponse(output="Invalid username or password.", status=401,
                          detail=f"Generic error; {5 - bucket[user]} attempts before lockout.")


register(Lesson(
    id="auth",
    title="Authentication Failures",
    owasp="A07:2021 - Identification and Authentication Failures",
    cwe="CWE-307, CWE-916",
    difficulty="medium",
    summary="Unlimited guesses against unsalted MD5 password hashes.",
    description=(
        "The vulnerable login has no rate limiting and stores passwords as unsalted MD5, which a "
        "commodity GPU reverses in moments. The secure version salts and stretches with scrypt, "
        "compares in constant time, returns a generic error, and locks the account after five "
        "failures."),
    exploit_hint=("Brute force admin: try admin / password, admin / 123456 ... "
                  "then admin / S3cr3tAdminPass! - nothing stops you."),
    fix_explanation=(
        "Store passwords with a slow, salted KDF (scrypt/argon2/bcrypt). Compare in constant time, "
        "give one generic failure message, and throttle or lock accounts to kill online brute "
        "force. Add MFA for anything sensitive."),
    inputs=(("username", "Username", "admin", "text"),
            ("password", "Password", "S3cr3tAdminPass!", "text")),
    vuln_code=VULN, secure_code=SECURE, run=run, output_label="Login result"))
