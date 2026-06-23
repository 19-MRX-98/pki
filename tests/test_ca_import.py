import importlib
import io
import inspect
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest


def load_import_modules(tmp_path, monkeypatch):
    app_root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(app_root))
    import pki_paths

    monkeypatch.setattr(pki_paths, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(pki_paths, "CA_ROOT", tmp_path / "data" / "ca")
    monkeypatch.setattr(pki_paths, "ISSUED_ROOT", tmp_path / "data" / "issued")

    for name in ["pki_ca", "pki_ca_import", "pki_storage"]:
        sys.modules.pop(name, None)

    import pki_ca_import
    import pki_storage

    importlib.reload(pki_ca_import)
    importlib.reload(pki_storage)
    return pki_ca_import, pki_storage, pki_paths


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
        "pki_ca_import",
        "pki_certificates",
        "pki_enrollment",
        "pki_storage",
    ]:
        sys.modules.pop(name, None)

    import app
    import pki_auth
    import pki_paths as reloaded_paths
    import pki_storage

    return app, pki_auth, pki_storage, reloaded_paths


def login_test_client(app_module):
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
    return client


def make_zip(entries: dict[str, bytes | str]) -> io.BytesIO:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries.items():
            if name.endswith("/"):
                archive.writestr(name, b"")
            elif isinstance(content, str):
                archive.writestr(name, content.encode("utf-8"))
            else:
                archive.writestr(name, content)
    buffer.seek(0)
    return buffer


def make_required_ca_zip() -> io.BytesIO:
    return make_zip(
        {
            "certs/ca.crt": "not a cert",
            "private/ca.key": "not a key",
            "index.txt": "",
            "serial": "1000\n",
            "crlnumber": "1000\n",
            "newcerts/": b"",
            "crl/": b"",
        }
    )


def corrupt_zip_member_payload(archive: io.BytesIO, payload: bytes = b"not a cert") -> io.BytesIO:
    data = bytearray(archive.getvalue())
    offset = data.index(payload)
    data[offset] ^= 0x01
    return io.BytesIO(bytes(data))


def test_import_rejects_zip_path_traversal(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)
    archive = make_zip({"../escape.txt": "bad"})

    with pytest.raises(pki_ca_import.CaImportError, match="unsichere ZIP-Pfade"):
        pki_ca_import.import_ca_zip(archive, "imported-ca")


def test_import_rejects_unsafe_directory_entries(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)
    archive = make_zip({"../bad/": b""})

    with pytest.raises(pki_ca_import.CaImportError, match="unsichere ZIP-Pfade"):
        pki_ca_import.import_ca_zip(archive, "imported-ca")


def test_import_rejects_missing_required_files(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)
    archive = make_zip({"certs/ca.crt": "not a cert"})

    with pytest.raises(pki_ca_import.CaImportError, match="Pflichtbestandteile fehlen"):
        pki_ca_import.import_ca_zip(archive, "imported-ca")


def test_import_rejects_missing_required_ca_structure(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)
    archive = make_zip(
        {
            "certs/ca.crt": "not a cert",
            "private/ca.key": "not a key",
        }
    )

    with pytest.raises(pki_ca_import.CaImportError, match="Pflichtbestandteile fehlen"):
        pki_ca_import.import_ca_zip(archive, "imported-ca")


def test_import_rejects_multiple_top_level_folders(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)
    archive = make_zip(
        {
            "one/certs/ca.crt": "not a cert",
            "two/private/ca.key": "not a key",
        }
    )

    with pytest.raises(pki_ca_import.CaImportError, match="mehrere Top-Level-Ordner"):
        pki_ca_import.import_ca_zip(archive, "imported-ca")


def test_import_public_api_signature(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)

    signature = inspect.signature(pki_ca_import.import_ca_zip)

    assert list(signature.parameters) == ["archive_file", "target_slug"]
    assert signature.parameters["target_slug"].default is None
    assert signature.parameters["target_slug"].annotation == str | None
    assert signature.return_annotation is str


def test_import_rejects_existing_slug_without_overwriting(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, pki_paths = load_import_modules(tmp_path, monkeypatch)
    existing_cert = pki_paths.CA_ROOT / "imported-ca" / "certs" / "ca.crt"
    existing_cert.parent.mkdir(parents=True)
    existing_cert.write_text("original cert\n", encoding="utf-8")
    monkeypatch.setattr(pki_ca_import, "run_openssl_capture", lambda _args: "")
    archive = make_required_ca_zip()

    with pytest.raises(pki_ca_import.CaImportError, match="existiert"):
        pki_ca_import.import_ca_zip(archive, "imported-ca")

    assert existing_cert.read_text(encoding="utf-8") == "original cert\n"


def test_import_invalid_material_does_not_leave_partial_ca_dir(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, pki_paths = load_import_modules(tmp_path, monkeypatch)
    archive = make_required_ca_zip()

    with pytest.raises(pki_ca_import.CaImportError):
        pki_ca_import.import_ca_zip(archive, "imported-ca")

    assert not (pki_paths.CA_ROOT / "imported-ca").exists()


def test_import_rejects_corrupt_zip_upload(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)
    archive = io.BytesIO(b"not a zip")

    with pytest.raises(pki_ca_import.CaImportError, match="ungueltige ZIP-Datei"):
        pki_ca_import.import_ca_zip(archive, "imported-ca")


def test_import_rejects_corrupt_zip_member(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)
    archive = corrupt_zip_member_payload(make_required_ca_zip())

    with pytest.raises(pki_ca_import.CaImportError, match="ungueltige ZIP-Datei"):
        pki_ca_import.import_ca_zip(archive, "imported-ca")


def test_ca_import_route_uploads_zip_and_redirects_to_imported_ca(tmp_path, monkeypatch):
    app_module, pki_auth, _pki_storage, pki_paths = load_app_modules(tmp_path, monkeypatch)
    pki_auth.ensure_db()
    source = tmp_path / "backup"
    create_openssl_ca(source, "Route Imported CA")
    client = login_test_client(app_module)

    response = client.post(
        "/ca/import",
        data={
            "ca_import_slug": "route-imported-ca",
            "ca_import_file": (zip_directory(source), "ca-backup.zip"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/cas?ca=route-imported-ca")
    ca_dir = pki_paths.CA_ROOT / "route-imported-ca"
    assert (ca_dir / "certs" / "ca.crt").exists()
    assert (ca_dir / "private" / "ca.key").exists()


def test_ca_import_route_duplicate_slug_flashes_and_preserves_existing_ca(
    tmp_path, monkeypatch
):
    app_module, pki_auth, _pki_storage, pki_paths = load_app_modules(tmp_path, monkeypatch)
    pki_auth.ensure_db()
    existing_cert = pki_paths.CA_ROOT / "existing-ca" / "certs" / "ca.crt"
    existing_cert.parent.mkdir(parents=True)
    existing_cert.write_text("original cert\n", encoding="utf-8")
    source = tmp_path / "backup"
    create_openssl_ca(source, "Duplicate Import CA")
    client = login_test_client(app_module)

    response = client.post(
        "/ca/import",
        data={
            "ca_import_slug": "existing-ca",
            "ca_import_file": (zip_directory(source), "ca-backup.zip"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Ziel-Slug existiert bereits" in response.get_data(as_text=True)
    assert existing_cert.read_text(encoding="utf-8") == "original cert\n"


def test_ca_import_route_missing_file_flashes_message(tmp_path, monkeypatch):
    app_module, pki_auth, _pki_storage, _pki_paths = load_app_modules(tmp_path, monkeypatch)
    pki_auth.ensure_db()
    client = login_test_client(app_module)

    response = client.post(
        "/ca/import",
        data={"ca_import_slug": "missing-file"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Bitte ein CA-Backup-ZIP auswählen." in response.get_data(as_text=True)


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def create_openssl_ca(source_dir: Path, common_name: str = "Imported CA") -> None:
    (source_dir / "certs").mkdir(parents=True)
    (source_dir / "private").mkdir(parents=True)
    (source_dir / "newcerts").mkdir(parents=True)
    (source_dir / "crl").mkdir(parents=True)
    (source_dir / "index.txt").write_text("", encoding="utf-8")
    (source_dir / "serial").write_text("1000\n", encoding="utf-8")
    (source_dir / "crlnumber").write_text("1000\n", encoding="utf-8")
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(source_dir / "private" / "ca.key"),
            "-out",
            str(source_dir / "certs" / "ca.crt"),
            "-days",
            "365",
            "-subj",
            f"/CN={common_name}",
        ]
    )


def create_openssl_leaf_cert(source_dir: Path, common_name: str = "Imported Leaf") -> None:
    (source_dir / "certs").mkdir(parents=True)
    (source_dir / "private").mkdir(parents=True)
    (source_dir / "newcerts").mkdir(parents=True)
    (source_dir / "crl").mkdir(parents=True)
    (source_dir / "index.txt").write_text("", encoding="utf-8")
    (source_dir / "serial").write_text("1000\n", encoding="utf-8")
    (source_dir / "crlnumber").write_text("1000\n", encoding="utf-8")
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(source_dir / "private" / "ca.key"),
            "-out",
            str(source_dir / "certs" / "ca.crt"),
            "-days",
            "365",
            "-subj",
            f"/CN={common_name}",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=digitalSignature,keyEncipherment",
        ]
    )


def zip_directory(source_dir: Path, prefix: str | None = None) -> io.BytesIO:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path in source_dir.rglob("*"):
            arcname = path.relative_to(source_dir).as_posix()
            if prefix:
                arcname = f"{prefix}/{arcname}"
            if path.is_dir():
                archive.writestr(f"{arcname}/", b"")
            else:
                archive.write(path, arcname)
    buffer.seek(0)
    return buffer


def zip_files_only(source_dir: Path, prefix: str | None = None) -> io.BytesIO:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path in source_dir.rglob("*"):
            if path.is_dir():
                continue
            arcname = path.relative_to(source_dir).as_posix()
            if prefix:
                arcname = f"{prefix}/{arcname}"
            archive.write(path, arcname)
    buffer.seek(0)
    return buffer


def test_import_valid_zip_with_top_level_folder(tmp_path, monkeypatch):
    pki_ca_import, pki_storage, pki_paths = load_import_modules(tmp_path, monkeypatch)
    source = tmp_path / "backup"
    create_openssl_ca(source, "Restored Root")
    archive = zip_directory(source, prefix="restored-root")

    slug = pki_ca_import.import_ca_zip(archive)

    assert slug == "restored-root"
    ca_dir = pki_paths.CA_ROOT / slug
    assert (ca_dir / "certs" / "ca.crt").exists()
    assert (ca_dir / "private" / "ca.key").exists()
    assert (ca_dir / "openssl.cnf").exists()
    assert pki_storage.list_cas()[0]["slug"] == "restored-root"
    assert pki_storage.list_cas()[0]["name"] == "Restored Root"


def test_import_regenerates_openssl_config_with_final_ca_dir(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, pki_paths = load_import_modules(tmp_path, monkeypatch)
    source = tmp_path / "backup"
    create_openssl_ca(source, "Config Path CA")
    archive = zip_directory(source)

    slug = pki_ca_import.import_ca_zip(archive, "config-path-ca")

    ca_dir = pki_paths.CA_ROOT / slug
    config_text = (ca_dir / "openssl.cnf").read_text(encoding="utf-8")
    assert f"dir = {ca_dir}" in config_text
    assert "-import-" not in config_text


def test_import_restricts_private_key_permissions(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, pki_paths = load_import_modules(tmp_path, monkeypatch)
    source = tmp_path / "backup"
    create_openssl_ca(source, "Key Mode CA")
    (source / "private" / "ca.key").chmod(0o644)
    archive = zip_directory(source)

    slug = pki_ca_import.import_ca_zip(archive, "key-mode-ca")

    ca_key = pki_paths.CA_ROOT / slug / "private" / "ca.key"
    assert ca_key.stat().st_mode & 0o777 == 0o600


def test_import_accepts_zip_without_explicit_directory_entries(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, pki_paths = load_import_modules(tmp_path, monkeypatch)
    source = tmp_path / "backup"
    create_openssl_ca(source, "Implicit Dirs CA")
    (source / "newcerts" / "placeholder.txt").write_text("", encoding="utf-8")
    (source / "crl" / "placeholder.txt").write_text("", encoding="utf-8")
    archive = zip_files_only(source)

    slug = pki_ca_import.import_ca_zip(archive, "implicit-dirs-ca")

    ca_dir = pki_paths.CA_ROOT / slug
    assert (ca_dir / "certs" / "ca.crt").exists()
    assert (ca_dir / "newcerts" / "placeholder.txt").exists()
    assert (ca_dir / "crl" / "placeholder.txt").exists()


def test_import_valid_zip_with_root_files_and_explicit_slug(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, pki_paths = load_import_modules(tmp_path, monkeypatch)
    source = tmp_path / "backup"
    create_openssl_ca(source, "Root Layout CA")
    archive = zip_directory(source)

    slug = pki_ca_import.import_ca_zip(archive, "manual-slug")

    assert slug == "manual-slug"
    assert (pki_paths.CA_ROOT / "manual-slug" / "certs" / "ca.crt").exists()


def test_import_derives_slug_from_common_name_for_root_files(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, pki_paths = load_import_modules(tmp_path, monkeypatch)
    source = tmp_path / "backup"
    create_openssl_ca(source, "Common Name CA")
    archive = zip_directory(source)

    slug = pki_ca_import.import_ca_zip(archive)

    assert slug == "Common_Name_CA"
    assert (pki_paths.CA_ROOT / slug).exists()


def test_import_existing_slug_aborts_without_overwrite(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, pki_paths = load_import_modules(tmp_path, monkeypatch)
    existing = pki_paths.CA_ROOT / "existing-ca"
    (existing / "certs").mkdir(parents=True)
    (existing / "private").mkdir(parents=True)
    marker = existing / "marker.txt"
    marker.write_text("keep", encoding="utf-8")
    source = tmp_path / "backup"
    create_openssl_ca(source)
    archive = zip_directory(source)

    with pytest.raises(pki_ca_import.CaImportError, match="existiert"):
        pki_ca_import.import_ca_zip(archive, "existing-ca")

    assert marker.read_text(encoding="utf-8") == "keep"


def test_import_existing_empty_slug_aborts_without_overwrite(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, pki_paths = load_import_modules(tmp_path, monkeypatch)
    existing = pki_paths.CA_ROOT / "empty-ca"
    existing.mkdir(parents=True)
    source = tmp_path / "backup"
    create_openssl_ca(source)
    archive = zip_directory(source)

    with pytest.raises(pki_ca_import.CaImportError, match="existiert"):
        pki_ca_import.import_ca_zip(archive, "empty-ca")

    assert existing.exists()
    assert list(existing.iterdir()) == []


def test_import_late_existing_empty_slug_aborts_without_overwrite(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, pki_paths = load_import_modules(tmp_path, monkeypatch)
    source = tmp_path / "backup"
    create_openssl_ca(source)
    archive = zip_directory(source)
    original_publish = pki_ca_import._publish_staging_dir

    def publish_after_empty_target_appears(staging_dir: Path, target_dir: Path) -> None:
        target_dir.mkdir()
        original_publish(staging_dir, target_dir)

    monkeypatch.setattr(
        pki_ca_import, "_publish_staging_dir", publish_after_empty_target_appears
    )

    with pytest.raises(pki_ca_import.CaImportError, match="existiert"):
        pki_ca_import.import_ca_zip(archive, "late-empty-ca")

    target_dir = pki_paths.CA_ROOT / "late-empty-ca"
    assert target_dir.exists()
    assert list(target_dir.iterdir()) == []


def test_import_rejects_non_ca_certificate_with_matching_key(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, pki_paths = load_import_modules(tmp_path, monkeypatch)
    source = tmp_path / "backup"
    create_openssl_leaf_cert(source)
    archive = zip_directory(source)

    with pytest.raises(pki_ca_import.CaImportError, match="CA-Zertifikat"):
        pki_ca_import.import_ca_zip(archive, "leaf-cert")

    assert not (pki_paths.CA_ROOT / "leaf-cert").exists()


def test_import_rejects_mismatched_private_key(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)
    source = tmp_path / "backup"
    create_openssl_ca(source)
    run(
        [
            "openssl",
            "genrsa",
            "-out",
            str(source / "private" / "ca.key"),
            "2048",
        ]
    )
    archive = zip_directory(source)

    with pytest.raises(pki_ca_import.CaImportError, match="passt nicht"):
        pki_ca_import.import_ca_zip(archive, "bad-key")


def test_import_rejects_encrypted_private_key(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)
    source = tmp_path / "backup"
    create_openssl_ca(source)
    run(
        [
            "openssl",
            "rsa",
            "-aes256",
            "-in",
            str(source / "private" / "ca.key"),
            "-out",
            str(source / "private" / "encrypted.key"),
            "-passout",
            "pass:secret",
        ]
    )
    (source / "private" / "encrypted.key").replace(source / "private" / "ca.key")
    archive = zip_directory(source)

    with pytest.raises(pki_ca_import.CaImportError, match="verschlüsselter Private Key"):
        pki_ca_import.import_ca_zip(archive, "encrypted-key")
