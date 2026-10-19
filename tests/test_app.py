"""Web layer: routes, security headers, flag capture over HTTP, reset."""


def test_home_lists_lessons_with_banner(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"intentionally vulnerable" in r.data
    assert b"SQL Injection" in r.data


def test_security_headers_present(client):
    r = client.get("/")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in r.headers


def test_lesson_page_shows_both_implementations(client):
    r = client.get("/lesson/sqli")
    assert r.status_code == 200
    assert b"Vulnerable" in r.data and b"Secure" in r.data


def test_unknown_lesson_404(client):
    assert client.get("/lesson/does-not-exist").status_code == 404


def test_flag_capture_over_http(client):
    r = client.post("/lesson/sqli", data={"username": "admin'--", "password": "x", "mode": "vuln"})
    assert b"Flag captured" in r.data
    r = client.post("/lesson/sqli", data={"username": "admin'--", "password": "x", "mode": "secure"})
    assert b"Flag captured" not in r.data


def test_reflected_xss_renders_then_escapes(client):
    r = client.post("/lesson/xss_reflected", data={"q": "<script>alert(1)</script>", "mode": "vuln"})
    assert b"<script>alert(1)</script>" in r.data           # raw -> vulnerable
    r = client.post("/lesson/xss_reflected", data={"q": "<script>alert(1)</script>", "mode": "secure"})
    assert b"&lt;script&gt;" in r.data                      # escaped -> safe


def test_reset_clears_progress(client):
    client.post("/lesson/sqli", data={"username": "admin'--", "password": "x", "mode": "vuln"})
    assert client.post("/reset").status_code == 302
