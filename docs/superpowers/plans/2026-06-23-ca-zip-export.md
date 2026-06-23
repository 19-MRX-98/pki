# CA ZIP Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a full unencrypted ZIP backup export for a single CA, including the private CA key, in the same structure accepted by the existing import.

**Architecture:** Add a focused export helper next to the CA import code so backup structure validation can reuse the import constants. Keep Flask route logic thin: resolve CA, call export helper, send the generated ZIP, and flash errors. Add route/UI tests plus a restore compatibility test that feeds an exported ZIP back into `import_ca_zip`.

**Tech Stack:** Flask, Python `zipfile`/`tempfile`, pathlib, existing PKI storage helpers, pytest.

---

## File Structure

- Modify `pki_ca_import.py`: add `CaExportError`, `validate_ca_backup_source(ca_dir)`, and `write_ca_backup_zip(ca_dir, output_file)`.
- Modify `app.py`: import export helper and add `GET /ca/<slug>/backup`.
- Modify `templates/cas.html`: add `CA-Backup` download button per CA.
- Modify `tests/test_ca_import.py`: add export helper and route tests.
- Modify `README.md`: add backup export notes near the CA import section.

---

### Task 1: Export Helper

**Files:**
- Modify: `pki_ca_import.py`
- Modify: `tests/test_ca_import.py`

- [ ] **Step 1: Add failing helper tests**

Append tests:

```python
def test_export_valid_ca_zip_contains_required_backup_files(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)
    source = tmp_path / "source-ca"
    create_openssl_ca(source, "Exported CA")
    output = io.BytesIO()

    pki_ca_import.write_ca_backup_zip(source, output)

    output.seek(0)
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        assert "certs/ca.crt" in names
        assert "private/ca.key" in names
        assert "index.txt" in names
        assert "serial" in names
        assert "crlnumber" in names
        assert "newcerts/" in names
        assert "crl/" in names
        assert archive.read("private/ca.key")


def test_exported_zip_can_be_imported(tmp_path, monkeypatch):
    pki_ca_import, pki_storage, pki_paths = load_import_modules(tmp_path, monkeypatch)
    source = tmp_path / "source-ca"
    create_openssl_ca(source, "Round Trip CA")
    output = io.BytesIO()

    pki_ca_import.write_ca_backup_zip(source, output)
    output.seek(0)
    imported_slug = pki_ca_import.import_ca_zip(output, "round-trip-ca")

    assert imported_slug == "round-trip-ca"
    assert (pki_paths.CA_ROOT / "round-trip-ca" / "private" / "ca.key").exists()
    assert pki_storage.list_cas()[0]["name"] == "Round Trip CA"


def test_export_rejects_incomplete_ca(tmp_path, monkeypatch):
    pki_ca_import, _pki_storage, _pki_paths = load_import_modules(tmp_path, monkeypatch)
    ca_dir = tmp_path / "broken-ca"
    (ca_dir / "certs").mkdir(parents=True)
    (ca_dir / "certs" / "ca.crt").write_text("not enough", encoding="utf-8")

    with pytest.raises(pki_ca_import.CaExportError, match="unvollständig"):
        pki_ca_import.write_ca_backup_zip(ca_dir, io.BytesIO())
```

- [ ] **Step 2: Run focused tests**

Run:

```bash
pytest tests/test_ca_import.py -k export -v
```

Expected: FAIL because `write_ca_backup_zip` and `CaExportError` do not exist.

- [ ] **Step 3: Implement export helper**

Add to `pki_ca_import.py`:

```python
class CaExportError(ValueError):
    pass


def validate_ca_backup_source(ca_dir: Path) -> None:
    missing = []
    for relative in REQUIRED_FILES:
        if not (ca_dir / Path(*relative.parts)).is_file():
            missing.append(str(relative))
    for relative in REQUIRED_DIRS:
        if not (ca_dir / Path(*relative.parts)).is_dir():
            missing.append(str(relative))
    if missing:
        raise CaExportError("CA ist unvollständig und kann nicht exportiert werden.")


def write_ca_backup_zip(ca_dir: Path, output_file) -> None:
    validate_ca_backup_source(ca_dir)
    with zipfile.ZipFile(output_file, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative in sorted(REQUIRED_DIRS, key=str):
            archive.writestr(f"{relative.as_posix()}/", b"")
        files: list[Path] = []
        for relative in REQUIRED_FILES:
            files.append(ca_dir / Path(*relative.parts))
        config_path = ca_dir / "openssl.cnf"
        if config_path.exists():
            files.append(config_path)
        for directory_name in ("newcerts", "crl"):
            directory = ca_dir / directory_name
            for path in sorted(directory.rglob("*")):
                if path.is_file():
                    files.append(path)
        for path in sorted(set(files)):
            archive.write(path, path.relative_to(ca_dir).as_posix())
```

- [ ] **Step 4: Run focused tests**

Run:

```bash
pytest tests/test_ca_import.py -k export -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pki_ca_import.py tests/test_ca_import.py
git commit -m "feat: add CA ZIP export helper"
```

---

### Task 2: Route, UI, and Documentation

**Files:**
- Modify: `app.py`
- Modify: `templates/cas.html`
- Modify: `tests/test_ca_import.py`
- Modify: `README.md`

- [ ] **Step 1: Add failing route tests**

Append tests:

```python
def test_ca_backup_route_downloads_zip(tmp_path, monkeypatch):
    app_module, pki_auth, _pki_storage, pki_paths = load_app_modules(tmp_path, monkeypatch)
    pki_auth.ensure_db()
    create_openssl_ca(pki_paths.CA_ROOT / "backup-ca", "Backup Route CA")
    client = login_test_client(app_module)

    response = client.get("/ca/backup-ca/backup")

    assert response.status_code == 200
    assert response.mimetype == "application/zip"
    assert "backup-ca-ca-backup.zip" in response.headers["Content-Disposition"]
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert "private/ca.key" in archive.namelist()


def test_ca_backup_route_missing_ca_redirects(tmp_path, monkeypatch):
    app_module, pki_auth, _pki_storage, _pki_paths = load_app_modules(tmp_path, monkeypatch)
    pki_auth.ensure_db()
    client = login_test_client(app_module)

    response = client.get("/ca/missing/backup", follow_redirects=True)

    assert response.status_code == 200
    assert b"CA nicht gefunden" in response.data
```

- [ ] **Step 2: Run route tests**

Run:

```bash
pytest tests/test_ca_import.py -k backup_route -v
```

Expected: FAIL with 404 because route does not exist.

- [ ] **Step 3: Implement route**

In `app.py`, import `CaExportError` and `write_ca_backup_zip`. Add route:

```python
@app.route("/ca/<slug>/backup", methods=["GET"])
def download_ca_backup(slug: str):
    prepare_storage()
    ca_dir = get_ca_dir(slug)
    if not ca_dir or not ca_exists(ca_dir):
        flash("CA nicht gefunden.", "error")
        return redirect(url_for("cas_page", ca=slug))
    output = io.BytesIO()
    try:
        write_ca_backup_zip(ca_dir, output)
    except CaExportError as exc:
        flash(str(exc), "error")
        return redirect(url_for("cas_page", ca=slug))
    except OSError as exc:
        flash(f"CA-Backup konnte nicht erzeugt werden: {exc}", "error")
        return redirect(url_for("cas_page", ca=slug))
    output.seek(0)
    return send_file(
        output,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{slug}-ca-backup.zip",
    )
```

Also add `import io` near the top if missing.

- [ ] **Step 4: Add UI button**

In `templates/cas.html`, add a button next to CA certificate download:

```html
<a class="button-secondary" href="{{ url_for('download_ca_backup', slug=ca.slug) }}">
  CA-Backup
</a>
```

- [ ] **Step 5: Add README docs**

Add a short section:

```markdown
## CA-Backup exportieren

- Im Menüpunkt **CAs** kann pro CA ein vollständiges unverschlüsseltes ZIP-Backup heruntergeladen werden.
- Das Backup enthält auch `private/ca.key` und muss sicher abgelegt werden.
- Das ZIP nutzt dieselbe Struktur wie der CA-Import und kann direkt wieder importiert werden.
```

- [ ] **Step 6: Verify**

Run:

```bash
pytest tests/test_ca_import.py -v
pytest -v
python3 -m py_compile app.py pki_ca_import.py pki_ca.py pki_storage.py
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add app.py templates/cas.html tests/test_ca_import.py README.md
git commit -m "feat: add CA ZIP backup download"
```

---

## Self-Review

- Spec coverage: export helper, route, UI button, full unencrypted backup with private key, incomplete CA rejection, import compatibility, route response, and README documentation are covered.
- Placeholder scan: no unfinished markers or vague implementation steps.
- Type consistency: the plan consistently uses `CaExportError`, `write_ca_backup_zip(ca_dir, output_file)`, route endpoint `download_ca_backup`, and URL `/ca/<slug>/backup`.
