import importlib
import sqlite3
import sys
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
