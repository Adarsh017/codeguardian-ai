"""API integration tests: auth, upload, background scan, findings, reports."""
import io
import tempfile
import time
import zipfile
from pathlib import Path

_tmp = tempfile.mkdtemp()

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

SAMPLE = Path(__file__).resolve().parents[2] / "samples" / "vulnerable-app"


def sample_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for p in SAMPLE.rglob("*"):
            if p.is_file():
                zf.write(p, f"vulnerable-app/{p.relative_to(SAMPLE).as_posix()}")
    return buf.getvalue()


def test_end_to_end():
    with TestClient(app) as client:
        r = client.post("/api/auth/register", json={"email": "dev@example.com", "password": "password123", "name": "Dev"})
        assert r.status_code == 200
        headers = {"Authorization": f"Bearer {r.json()['token']}"}
        assert client.post("/api/auth/login", json={"email": "dev@example.com", "password": "wrong-pass"}).status_code == 401
        assert client.get("/api/projects").status_code == 401

        r = client.post("/api/projects/upload", headers=headers, data={"name": "Sample"},
                        files={"file": ("sample.zip", sample_zip(), "application/zip")})
        assert r.status_code == 200, r.text
        scan_id = r.json()["scan"]["id"]

        for _ in range(120):
            scan = client.get(f"/api/scans/{scan_id}", headers=headers).json()
            if scan["status"] in ("completed", "failed"):
                break
            time.sleep(0.25)
        assert scan["status"] == "completed", scan
        assert scan["gate_passed"] is False
        assert scan["summary"]["severity_counts"]["Critical"] > 0

        findings = client.get(f"/api/scans/{scan_id}/findings", headers=headers).json()
        assert findings and findings[0]["severity"] == "Critical"
        crit = client.get(f"/api/scans/{scan_id}/findings?severity=Critical", headers=headers).json()
        assert all(f["severity"] == "Critical" for f in crit)

        ctx = client.get(f"/api/scans/{scan_id}/findings/{findings[0]['id']}/context", headers=headers).json()
        assert ctx["lines"]

        for fmt, ctype in (("pdf", "application/pdf"), ("json", "application/json"), ("csv", "text/csv"),
                           ("sarif", "application/sarif+json")):
            r = client.get(f"/api/scans/{scan_id}/report?format={fmt}", headers=headers)
            assert r.status_code == 200 and r.headers["content-type"].startswith(ctype)

        dash = client.get("/api/dashboard", headers=headers).json()
        assert dash["projects"] == 1 and dash["severity_totals"]["Critical"] > 0

        # another user cannot see this scan
        other = client.post("/api/auth/register", json={"email": "x@example.com", "password": "password123"}).json()
        assert client.get(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {other['token']}"}).status_code == 404


def test_zip_slip_rejected():
    from app.services.ingestion import IngestionError, safe_extract_zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.py", "x = 1")
    try:
        safe_extract_zip(buf.getvalue(), Path(_tmp) / "slip")
        raise AssertionError("zip slip not blocked")
    except IngestionError:
        pass


def test_upload_limit_and_skipped_folders():
    from app.config import settings
    with TestClient(app) as client:
        r = client.post("/api/auth/register", json={"email": "big@example.com", "password": "password123"})
        headers = {"Authorization": f"Bearer {r.json()['token']}"}
        old = settings.MAX_UPLOAD_MB
        settings.MAX_UPLOAD_MB = 1
        try:
            big = io.BytesIO()
            with zipfile.ZipFile(big, "w", zipfile.ZIP_STORED) as zf:
                zf.writestr("app.py", "x = 1\n")
                zf.writestr("blob.txt", "a" * (2 * 1024 * 1024))
            r = client.post("/api/projects/upload", headers=headers, data={"name": "too-big"},
                            files={"file": ("big.zip", big.getvalue(), "application/zip")})
            assert r.status_code == 413 and "1 MB" in r.json()["detail"]
            assert client.get("/api/projects", headers=headers).json() == []  # no half-created project left
        finally:
            settings.MAX_UPLOAD_MB = old

    from app.services.ingestion import safe_extract_zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("proj/main.py", "print(1)\n")
        zf.writestr("proj/node_modules/lib/index.js", "eval(x)\n")
        zf.writestr("proj/.git/config", "[core]\n")
    dest = Path(_tmp) / "skip"
    assert safe_extract_zip(buf.getvalue(), dest) == 1
    assert (dest / "main.py").exists() and not (dest / "node_modules").exists()
