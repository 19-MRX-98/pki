import importlib
import io
import inspect
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
