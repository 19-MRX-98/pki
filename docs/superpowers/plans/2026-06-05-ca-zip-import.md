# CA ZIP Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a ZIP-based complete CA backup import that restores an existing CA into the app-managed `data/ca/<slug>` structure without overwriting existing CAs.

**Architecture:** Put ZIP parsing, validation, OpenSSL checks, and final move logic in a new focused module `pki_ca_import.py`. Keep `app.py` responsible only for reading form data, calling the import function, flashing user-facing messages, and redirecting. Reuse existing CA conventions from `pki_ca.py` and `pki_storage.py`.

**Tech Stack:** Flask, Werkzeug `secure_filename`, Python stdlib `zipfile`/`tempfile`/`shutil`, OpenSSL through existing `pki_utils.run_openssl_capture`, pytest.

---

## File Structure

- Create `pki_ca_import.py`: CA ZIP import service. Owns archive safety checks, structure normalization, slug derivation, OpenSSL validation, encrypted-key rejection, config regeneration, and final move into `CA_ROOT`.
- Modify `app.py`: import `CaImportError` and `import_ca_zip`; add `POST /ca/import` route.
- Modify `templates/cas.html`: add import form with `multipart/form-data`.
- Create `tests/test_ca_import.py`: unit tests for the import module and one route test through Flask test client.
- Modify `README.md`: document the ZIP backup format and import behavior.

---

### Task 1: ZIP Structure Validation

**Files:**
- Create: `pki_ca_import.py`
- Create: `tests/test_ca_import.py`

- [ ] **Step 1: Write failing tests for unsafe and incomplete ZIP archives**

Add this initial test file:

```python
import importlib
import io
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


def test_import_rejects_zip_path_traversal(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)
    archive = make_zip({"../escape.txt": "bad"})

    with pytest.raises(pki_ca_import.CaImportError, match="unsichere ZIP-Pfade"):
        pki_ca_import.import_ca_zip(archive, "imported-ca")


def test_import_rejects_missing_required_files(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)
    archive = make_zip({"certs/ca.crt": "not a cert"})

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
pytest tests/test_ca_import.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'pki_ca_import'`.

- [ ] **Step 3: Add minimal import module with ZIP safety and required path checks**

Create `pki_ca_import.py`:

```python
from __future__ import annotations

import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from werkzeug.utils import secure_filename

from pki_ca import ensure_ca_config, ensure_ca_dirs
from pki_paths import CA_ROOT
from pki_utils import run_openssl_capture


REQUIRED_FILES = (
    "certs/ca.crt",
    "private/ca.key",
    "index.txt",
    "serial",
    "crlnumber",
)
REQUIRED_DIRS = ("newcerts", "crl")


class CaImportError(RuntimeError):
    """User-facing CA import validation error."""


def _safe_zip_member(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts


def _extract_zip(archive_file, destination: Path) -> None:
    try:
        with zipfile.ZipFile(archive_file) as archive:
            for info in archive.infolist():
                if not _safe_zip_member(info.filename):
                    raise CaImportError("Import abgebrochen: unsichere ZIP-Pfade.")
            archive.extractall(destination)
    except zipfile.BadZipFile as exc:
        raise CaImportError("Import abgebrochen: ungültiges ZIP-Archiv.") from exc


def _contains_required_layout(root: Path) -> bool:
    return all((root / item).is_file() for item in REQUIRED_FILES) and all(
        (root / item).is_dir() for item in REQUIRED_DIRS
    )


def _ca_source_root(extracted: Path) -> tuple[Path, str]:
    if _contains_required_layout(extracted):
        return extracted, ""
    folders = [entry for entry in extracted.iterdir() if entry.is_dir()]
    files = [entry for entry in extracted.iterdir() if entry.is_file()]
    if len(folders) > 1:
        raise CaImportError("Import abgebrochen: mehrere Top-Level-Ordner gefunden.")
    if len(folders) == 1 and not files:
        return folders[0], folders[0].name
    raise CaImportError("Import abgebrochen: Pflichtbestandteile fehlen.")


def _check_required_layout(source_root: Path) -> None:
    if not _contains_required_layout(source_root):
        raise CaImportError("Import abgebrochen: Pflichtbestandteile fehlen.")


def _copy_source(source_root: Path, staging_ca: Path) -> None:
    shutil.copytree(source_root, staging_ca)


def _read_ca_common_name(ca_cert: Path) -> str:
    output = run_openssl_capture(["x509", "-in", str(ca_cert), "-noout", "-subject"]).strip()
    subject = output.removeprefix("subject=").strip()
    for part in subject.split(","):
        part = part.strip()
        if part.startswith("CN="):
            return part.replace("CN=", "", 1).strip()
    return ""


def _derive_slug(target_slug: str | None, folder_name: str, ca_cert: Path) -> str:
    candidate = (target_slug or "").strip() or folder_name.strip() or _read_ca_common_name(ca_cert)
    slug = secure_filename(candidate)
    if not slug:
        raise CaImportError("Import abgebrochen: leerer oder ungültiger Slug.")
    return slug


def _validate_ca_material(ca_dir: Path) -> None:
    ca_cert = ca_dir / "certs" / "ca.crt"
    ca_key = ca_dir / "private" / "ca.key"
    run_openssl_capture(["x509", "-in", str(ca_cert), "-noout"])
    run_openssl_capture(["pkey", "-in", str(ca_key), "-noout"])


def import_ca_zip(archive_file, target_slug: str | None = None) -> str:
    CA_ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=CA_ROOT.parent) as temp_name:
        temp_dir = Path(temp_name)
        extracted = temp_dir / "extracted"
        staging_ca = temp_dir / "ca"
        extracted.mkdir()

        _extract_zip(archive_file, extracted)
        source_root, folder_name = _ca_source_root(extracted)
        _check_required_layout(source_root)
        _copy_source(source_root, staging_ca)

        ca_cert = staging_ca / "certs" / "ca.crt"
        slug = _derive_slug(target_slug, folder_name, ca_cert)
        final_dir = CA_ROOT / slug
        if final_dir.exists():
            raise CaImportError("Import abgebrochen: Ziel-Slug existiert bereits.")

        _validate_ca_material(staging_ca)
        ensure_ca_dirs(staging_ca)
        ensure_ca_config(staging_ca)

        if final_dir.exists():
            raise CaImportError("Import abgebrochen: Ziel-Slug existiert bereits.")
        shutil.move(str(staging_ca), str(final_dir))
        return slug
```

- [ ] **Step 4: Run tests to verify ZIP validation passes and OpenSSL validation now fails where expected**

Run:

```bash
pytest tests/test_ca_import.py -v
```

Expected: all three tests PASS. The missing required files test must fail before OpenSSL is called.

- [ ] **Step 5: Commit**

```bash
git add pki_ca_import.py tests/test_ca_import.py
git commit -m "feat: validate CA ZIP import structure"
```

---

### Task 2: OpenSSL CA Material Validation and Successful Import

**Files:**
- Modify: `pki_ca_import.py`
- Modify: `tests/test_ca_import.py`

- [ ] **Step 1: Add tests for successful import, existing slug, mismatched key, encrypted key, and root layout**

Append these helpers and tests to `tests/test_ca_import.py`:

```python
import subprocess


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

    with pytest.raises(pki_ca_import.CaImportError, match="Ziel-Slug existiert bereits"):
        pki_ca_import.import_ca_zip(archive, "existing-ca")

    assert marker.read_text(encoding="utf-8") == "keep"


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
```

- [ ] **Step 2: Run new tests to verify failures**

Run:

```bash
pytest tests/test_ca_import.py -v
```

Expected: the new tests for mismatched and encrypted keys FAIL because `_validate_ca_material()` does not yet translate OpenSSL failures into the required `CaImportError` messages and does not compare public keys.

- [ ] **Step 3: Implement certificate/key validation and OpenSSL error mapping**

Replace `_validate_ca_material()` in `pki_ca_import.py` with:

```python
def _key_looks_encrypted(ca_key: Path) -> bool:
    try:
        key_text = ca_key.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        raise CaImportError("Import abgebrochen: privater Key konnte nicht gelesen werden.") from exc
    return "ENCRYPTED" in key_text or "Proc-Type: 4,ENCRYPTED" in key_text


def _validate_ca_material(ca_dir: Path) -> None:
    ca_cert = ca_dir / "certs" / "ca.crt"
    ca_key = ca_dir / "private" / "ca.key"
    if _key_looks_encrypted(ca_key):
        raise CaImportError("Import abgebrochen: verschlüsselter Private Key wird nicht unterstützt.")
    try:
        cert_pubkey = run_openssl_capture(
            ["x509", "-in", str(ca_cert), "-noout", "-pubkey"]
        ).strip()
    except Exception as exc:
        raise CaImportError("Import abgebrochen: ungültiges CA-Zertifikat.") from exc
    try:
        key_pubkey = run_openssl_capture(["pkey", "-in", str(ca_key), "-pubout"]).strip()
    except Exception as exc:
        raise CaImportError("Import abgebrochen: ungültiger privater Key.") from exc
    if cert_pubkey != key_pubkey:
        raise CaImportError("Import abgebrochen: Private Key passt nicht zum CA-Zertifikat.")
```

- [ ] **Step 4: Run import tests**

Run:

```bash
pytest tests/test_ca_import.py -v
```

Expected: PASS for all tests in `tests/test_ca_import.py`.

- [ ] **Step 5: Commit**

```bash
git add pki_ca_import.py tests/test_ca_import.py
git commit -m "feat: import validated CA ZIP backups"
```

---

### Task 3: Flask Route and CA Page Form

**Files:**
- Modify: `app.py`
- Modify: `templates/cas.html`
- Modify: `tests/test_ca_import.py`

- [ ] **Step 1: Add route test for successful upload and duplicate slug error**

Append this app loader and route test to `tests/test_ca_import.py`:

```python
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

    importlib.reload(app)
    importlib.reload(pki_auth)
    return app, pki_auth, reloaded_paths


def logged_in_client(app_module):
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
    return client


def test_ca_import_route_uploads_zip_and_redirects_to_imported_ca(tmp_path, monkeypatch):
    app_module, pki_auth, pki_paths = load_app_modules(tmp_path, monkeypatch)
    pki_auth.ensure_db()
    source = tmp_path / "backup"
    create_openssl_ca(source, "Route Import CA")
    archive = zip_directory(source)
    client = logged_in_client(app_module)

    response = client.post(
        "/ca/import",
        data={
            "ca_import_slug": "route-ca",
            "ca_import_file": (archive, "route-ca.zip"),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/cas?ca=route-ca")
    assert (pki_paths.CA_ROOT / "route-ca" / "certs" / "ca.crt").exists()


def test_ca_import_route_reports_duplicate_slug(tmp_path, monkeypatch):
    app_module, pki_auth, pki_paths = load_app_modules(tmp_path, monkeypatch)
    pki_auth.ensure_db()
    existing = pki_paths.CA_ROOT / "dupe-ca"
    (existing / "certs").mkdir(parents=True)
    (existing / "private").mkdir(parents=True)
    (existing / "certs" / "ca.crt").write_text("existing", encoding="utf-8")
    (existing / "private" / "ca.key").write_text("existing", encoding="utf-8")
    source = tmp_path / "backup"
    create_openssl_ca(source, "Duplicate Route CA")
    archive = zip_directory(source)
    client = logged_in_client(app_module)

    response = client.post(
        "/ca/import",
        data={
            "ca_import_slug": "dupe-ca",
            "ca_import_file": (archive, "dupe-ca.zip"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Ziel-Slug existiert bereits" in response.data
    assert (existing / "certs" / "ca.crt").read_text(encoding="utf-8") == "existing"
```

- [ ] **Step 2: Run route tests to verify they fail**

Run:

```bash
pytest tests/test_ca_import.py::test_ca_import_route_uploads_zip_and_redirects_to_imported_ca tests/test_ca_import.py::test_ca_import_route_reports_duplicate_slug -v
```

Expected: FAIL with 404 for `/ca/import`.

- [ ] **Step 3: Add route imports and route handler**

In `app.py`, add this import near the existing CA import:

```python
from pki_ca_import import CaImportError, import_ca_zip
```

Add this route after `create_ca_route()`:

```python
@app.route("/ca/import", methods=["POST"])
def import_ca_route():
    prepare_storage()
    file = request.files.get("ca_import_file")
    requested_slug = request.form.get("ca_import_slug", "").strip()
    if not file or not file.filename:
        flash("Bitte ein CA-Backup-ZIP auswählen.", "error")
        return redirect(url_for("cas_page"))
    try:
        imported_slug = import_ca_zip(file, requested_slug or None)
    except CaImportError as exc:
        flash(str(exc), "error")
        return redirect(url_for("cas_page"))
    except OSError:
        flash("Import abgebrochen: CA-Backup konnte nicht geschrieben werden.", "error")
        return redirect(url_for("cas_page"))
    flash("CA-Backup erfolgreich importiert.", "success")
    return redirect(url_for("cas_page", ca=imported_slug))
```

- [ ] **Step 4: Add import form to CA template**

In `templates/cas.html`, add this section after the existing `Neue CA anlegen` form section and before the CA list status:

```html
  <section class="card">
    <h2>CA-Backup importieren</h2>
    <form method="post" action="{{ url_for('import_ca_route') }}" enctype="multipart/form-data">
      <label>
        ZIP-Archiv
        <input name="ca_import_file" type="file" accept=".zip,application/zip" required />
      </label>
      <label>
        Ziel-Kurzname (optional)
        <input name="ca_import_slug" />
      </label>
      <button type="submit">CA-Backup importieren</button>
    </form>
  </section>
```

Keep the existing list rendering unchanged.

- [ ] **Step 5: Run route tests**

Run:

```bash
pytest tests/test_ca_import.py::test_ca_import_route_uploads_zip_and_redirects_to_imported_ca tests/test_ca_import.py::test_ca_import_route_reports_duplicate_slug -v
```

Expected: PASS.

- [ ] **Step 6: Run all CA import tests**

Run:

```bash
pytest tests/test_ca_import.py -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add app.py templates/cas.html tests/test_ca_import.py
git commit -m "feat: add CA ZIP import route"
```

---

### Task 4: Documentation and Full Verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add README section for CA backup import**

In `README.md`, add `CA-Backup importieren` after the `Mehrere CAs` section:

```markdown
## CA-Backup importieren

- Im Menüpunkt **CAs** kann ein vollständiges CA-Backup als ZIP importiert werden.
- Das ZIP muss die App-kompatible CA-Struktur enthalten:
  - `certs/ca.crt`
  - `private/ca.key`
  - `index.txt`
  - `serial`
  - `crlnumber`
  - `newcerts/`
  - `crl/`
- Das ZIP darf diese Dateien direkt im Archiv-Root enthalten oder in einem einzelnen Top-Level-Ordner.
- Ein optionaler Ziel-Kurzname kann im Formular angegeben werden. Ohne Ziel-Kurznamen nutzt die App den Top-Level-Ordner oder den Common Name des CA-Zertifikats.
- Existiert der Ziel-Kurzname bereits, wird der Import abgebrochen. Bestehende CAs werden nicht überschrieben.
- Passwortgeschützte private CA-Keys werden nicht unterstützt, weil Signieren und CRL-Erzeugung ohne Passphrase laufen.
- Eine enthaltene `openssl.cnf` wird durch eine App-kompatible Konfiguration ersetzt, damit die Pfade zum neuen Speicherort passen.
```

- [ ] **Step 2: Run all tests**

Run:

```bash
pytest -v
```

Expected: PASS for the existing enrollment tests and new CA import tests.

- [ ] **Step 3: Run a focused syntax check**

Run:

```bash
python -m py_compile app.py pki_ca_import.py pki_ca.py pki_storage.py
```

Expected: command exits with status 0 and prints no output.

- [ ] **Step 4: Check git diff**

Run:

```bash
git diff --stat HEAD
git diff -- app.py pki_ca_import.py templates/cas.html tests/test_ca_import.py README.md
```

Expected: diff only contains the CA ZIP import feature, tests, and docs.

- [ ] **Step 5: Commit docs and final verification changes**

```bash
git add README.md
git commit -m "docs: document CA ZIP import"
```

---

## Self-Review

- Spec coverage: ZIP input shape, required CA files, optional `openssl.cnf`, slug derivation, duplicate-slug abort, temporary validation, path traversal rejection, CA certificate validation, private-key validation, key-match validation, encrypted-key rejection, UI form, route handling, README docs, and tests are covered by Tasks 1-4.
- Placeholder scan: this plan has no unfinished markers or intentionally vague implementation steps.
- Type consistency: the plan consistently uses `CaImportError`, `import_ca_zip(archive_file, target_slug: str | None = None) -> str`, route form fields `ca_import_file` and `ca_import_slug`, and route endpoint `import_ca_route`.
