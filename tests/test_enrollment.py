import importlib
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash


def load_modules(tmp_path, monkeypatch):
    app_root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(app_root))
    import pki_paths

    monkeypatch.setattr(pki_paths, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(pki_paths, "CA_ROOT", tmp_path / "data" / "ca")
    monkeypatch.setattr(pki_paths, "ISSUED_ROOT", tmp_path / "data" / "issued")

    for name in ["pki_auth", "pki_enrollment"]:
        sys.modules.pop(name, None)

    import pki_auth
    import pki_enrollment

    importlib.reload(pki_auth)
    importlib.reload(pki_enrollment)
    return pki_auth, pki_enrollment


def load_app_modules(tmp_path, monkeypatch):
    app_root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(app_root))
    import pki_paths

    monkeypatch.setattr(pki_paths, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(pki_paths, "CA_ROOT", tmp_path / "data" / "ca")
    monkeypatch.setattr(pki_paths, "ISSUED_ROOT", tmp_path / "data" / "issued")

    for name in [
        "app",
        "pki_auth",
        "pki_ca",
        "pki_certificates",
        "pki_enrollment",
        "pki_storage",
    ]:
        sys.modules.pop(name, None)

    import app
    import pki_auth
    import pki_enrollment

    return app, pki_auth, pki_enrollment, pki_paths


def test_create_token_returns_plaintext_once_and_stores_hash(tmp_path, monkeypatch):
    pki_auth, pki_enrollment = load_modules(tmp_path, monkeypatch)
    pki_auth.ensure_db()

    token = pki_enrollment.create_enrollment_token("node-a", "ca-main")

    assert token["plain_token"].startswith("pki_")
    assert token["name"] == "node-a"
    assert token["ca_slug"] == "ca-main"
    stored = pki_enrollment.list_enrollment_tokens()
    assert stored[0]["name"] == "node-a"
    assert "token_hash" not in stored[0]
    assert "plain_token" not in stored[0]
    assert stored[0]["active"] == 1

    with sqlite3.connect(tmp_path / "data" / "pki.db") as conn:
        raw_hash = conn.execute(
            "select token_hash from enrollment_tokens where name = ?",
            ("node-a",),
        ).fetchone()[0]
    assert check_password_hash(raw_hash, token["plain_token"])


def test_verify_token_rejects_unknown_and_disabled_tokens(tmp_path, monkeypatch):
    pki_auth, pki_enrollment = load_modules(tmp_path, monkeypatch)
    pki_auth.ensure_db()
    created = pki_enrollment.create_enrollment_token("node-a", "ca-main")

    assert pki_enrollment.verify_enrollment_token("wrong") is None
    verified = pki_enrollment.verify_enrollment_token(created["plain_token"])
    assert verified["name"] == "node-a"

    with sqlite3.connect(tmp_path / "data" / "pki.db") as conn:
        conn.execute(
            "update enrollment_tokens set token_hash = ? where id = ?",
            (generate_password_hash("replacement"), verified["id"]),
        )

    assert pki_enrollment.verify_enrollment_token(created["plain_token"]) is None
    replaced = pki_enrollment.verify_enrollment_token("replacement")
    assert replaced["id"] == verified["id"]

    pki_enrollment.set_enrollment_token_active(verified["id"], False)
    assert pki_enrollment.verify_enrollment_token("replacement") is None


def test_audit_entry_is_recorded(tmp_path, monkeypatch):
    pki_auth, pki_enrollment = load_modules(tmp_path, monkeypatch)
    pki_auth.ensure_db()
    created = pki_enrollment.create_enrollment_token("node-a", "ca-main")
    verified = pki_enrollment.verify_enrollment_token(created["plain_token"])

    pki_enrollment.record_enrollment_audit(
        token_id=verified["id"],
        ca_slug="ca-main",
        certificate_slug="host-20260511120000",
        subject="CN=host.example",
        sans="DNS:host.example",
        validity_days=90,
    )

    entries = pki_enrollment.list_enrollment_audit()
    assert entries[0]["token_id"] == verified["id"]
    assert entries[0]["certificate_slug"] == "host-20260511120000"


def test_api_enroll_missing_token_returns_invalid_token(tmp_path, monkeypatch):
    app_module, pki_auth, _pki_enrollment, _pki_paths = load_app_modules(tmp_path, monkeypatch)
    pki_auth.ensure_db()

    def fail_if_called(_plain_token):
        raise AssertionError("verify_enrollment_token should not be called without a token")

    monkeypatch.setattr(app_module, "verify_enrollment_token", fail_if_called)

    response = app_module.app.test_client().post(
        "/api/v1/enroll",
        json={"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----"},
    )

    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_token"}


def test_api_enroll_bad_csr_with_valid_token_returns_invalid_csr(tmp_path, monkeypatch):
    app_module, pki_auth, pki_enrollment, pki_paths = load_app_modules(tmp_path, monkeypatch)
    pki_auth.ensure_db()
    ca_dir = pki_paths.CA_ROOT / "ca-main"
    (ca_dir / "certs").mkdir(parents=True)
    (ca_dir / "private").mkdir(parents=True)
    (ca_dir / "certs" / "ca.crt").write_text("not used by this test", encoding="utf-8")
    (ca_dir / "private" / "ca.key").write_text("not used by this test", encoding="utf-8")
    token = pki_enrollment.create_enrollment_token("node-a", "ca-main")

    response = app_module.app.test_client().post(
        "/api/v1/enroll",
        headers={"Authorization": f"Bearer {token['plain_token']}"},
        json={"csr_pem": "not a csr", "validity_days": 90},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid_csr"}


def test_api_enroll_returns_renew_after_before_expiration(tmp_path, monkeypatch):
    app_module, pki_auth, pki_enrollment, pki_paths = load_app_modules(tmp_path, monkeypatch)
    pki_auth.ensure_db()
    ca_dir = pki_paths.CA_ROOT / "ca-main"
    certs_dir = ca_dir / "certs"
    private_dir = ca_dir / "private"
    certs_dir.mkdir(parents=True)
    private_dir.mkdir(parents=True)
    (certs_dir / "ca.crt").write_text("ca cert", encoding="utf-8")
    (private_dir / "ca.key").write_text("ca key", encoding="utf-8")
    token = pki_enrollment.create_enrollment_token("node-a", "ca-main")

    def fake_issue_from_csr(ca_path, csr_bytes, days_valid):
        cert_dir = pki_paths.ISSUED_ROOT / ca_path.name / "host-20260511120000"
        cert_dir.mkdir(parents=True)
        cert_path = cert_dir / "host-20260511120000.crt"
        csr_path = cert_dir / "host-20260511120000.csr"
        cert_path.write_text("issued cert", encoding="utf-8")
        csr_path.write_bytes(csr_bytes)
        return "host-20260511120000", cert_path, csr_path, cert_dir

    monkeypatch.setattr(app_module, "issue_from_csr", fake_issue_from_csr)
    monkeypatch.setattr(app_module, "certificate_enddate_iso", lambda _path: "2099-01-01T00:00:00Z")
    monkeypatch.setattr(app_module, "csr_subject", lambda _path: "CN=host.example")
    monkeypatch.setattr(app_module, "csr_sans", lambda _path: "DNS:host.example")

    before = datetime.now(UTC) + timedelta(days=60)
    response = app_module.app.test_client().post(
        "/api/v1/enroll",
        headers={"Authorization": f"Bearer {token['plain_token']}"},
        json={
            "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----",
            "validity_days": 90,
        },
    )
    after = datetime.now(UTC) + timedelta(days=60)

    assert response.status_code == 200
    body = response.get_json()
    renew_after = datetime.fromisoformat(body["renew_after"].replace("Z", "+00:00"))
    assert body["renew_after"] != body["expires_at"]
    assert before <= renew_after <= after
