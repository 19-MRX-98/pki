import os
import subprocess
from pathlib import Path

from werkzeug.utils import secure_filename

from pki_ca import ca_crl_path, ca_exists
from pki_paths import CA_ROOT, DATA_DIR, ISSUED_ROOT
from pki_utils import run_openssl_capture


def get_crl_info(ca_dir: Path) -> dict[str, str]:
    crl_path = ca_crl_path(ca_dir)
    if not crl_path.exists():
        return {"path": str(crl_path), "last_update": "-", "next_update": "-"}
    try:
        output = run_openssl_capture(
            ["crl", "-in", str(crl_path), "-noout", "-lastupdate", "-nextupdate"]
        )
    except subprocess.CalledProcessError:
        return {"path": str(crl_path), "last_update": "-", "next_update": "-"}
    last_update = "-"
    next_update = "-"
    for line in output.splitlines():
        if line.startswith("lastUpdate="):
            last_update = line.split("=", 1)[1].strip()
        elif line.startswith("nextUpdate="):
            next_update = line.split("=", 1)[1].strip()
    return {"path": str(crl_path), "last_update": last_update, "next_update": next_update}


def get_crl_entries(ca_dir: Path) -> list[dict[str, str]]:
    crl_path = ca_crl_path(ca_dir)
    if not crl_path.exists():
        return []
    try:
        output = run_openssl_capture(["crl", "-in", str(crl_path), "-noout", "-text"])
    except subprocess.CalledProcessError:
        return []
    entries: list[dict[str, str]] = []
    in_revoked = False
    current: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Revoked Certificates:"):
            in_revoked = True
            continue
        if not in_revoked:
            continue
        if line.startswith("Serial Number:"):
            if current:
                entries.append(current)
            current = {"serial": line.split(":", 1)[1].strip()}
        elif line.startswith("Revocation Date:"):
            current["revoked_at"] = line.split(":", 1)[1].strip()
        elif line.startswith("CRL extensions:"):
            continue
    if current:
        entries.append(current)
    return entries

def list_crls() -> list[dict[str, str | bool]]:
    if not CA_ROOT.exists():
        return []
    rows = []
    for entry in sorted(CA_ROOT.iterdir()):
        if not entry.is_dir():
            continue
        if not ca_exists(entry):
            continue
        info = get_crl_info(entry)
        rows.append(
            {
                "slug": entry.name,
                "name": get_ca_display_name(entry),
                "crl_ready": ca_crl_path(entry).exists(),
                "path": info["path"],
                "last_update": info["last_update"],
                "next_update": info["next_update"],
            }
        )
    return rows


def list_issued(ca_slug: str) -> list[dict[str, str | bool | None]]:
    safe_ca = secure_filename(ca_slug)
    if not safe_ca:
        return []
    issued_dir = ISSUED_ROOT / safe_ca
    if not issued_dir.exists():
        return []
    entries = []
    for entry in sorted(issued_dir.iterdir(), reverse=True):
        if not entry.is_dir():
            continue
        certs = list(entry.glob("*.crt"))
        keys = list(entry.glob("*.key"))
        if certs:
            revoked_at = get_revoked_marker(entry)
            entries.append(
                {
                    "slug": entry.name,
                    "cert": certs[0].name,
                    "key": keys[0].name if keys else None,
                    "revoked": bool(revoked_at),
                    "revoked_at": revoked_at,
                }
            )
    return entries


def get_ca_dir(slug: str) -> Path | None:
    safe_slug = secure_filename(slug)
    if not safe_slug:
        return None
    ca_dir = CA_ROOT / safe_slug
    if not ca_dir.exists():
        return None
    return ca_dir


def get_ca_display_name(ca_dir: Path) -> str:
    ca_cert = ca_dir / "certs" / "ca.crt"
    if not ca_cert.exists():
        return ca_dir.name
    try:
        subject = run_openssl_capture(["x509", "-in", str(ca_cert), "-noout", "-subject"]).strip()
    except subprocess.CalledProcessError:
        return ca_dir.name
    prefix = "subject="
    if subject.startswith(prefix):
        subject = subject[len(prefix) :].strip()
    for part in subject.split(","):
        part = part.strip()
        if part.startswith("CN="):
            return part.replace("CN=", "", 1).strip()
    return ca_dir.name


def list_cas() -> list[dict[str, str | bool]]:
    if not CA_ROOT.exists():
        return []
    cas = []
    for entry in sorted(CA_ROOT.iterdir()):
        if not entry.is_dir():
            continue
        if not ca_exists(entry):
            continue
        cas.append(
            {
                "slug": entry.name,
                "name": get_ca_display_name(entry),
                "crl_ready": ca_crl_path(entry).exists(),
            }
        )
    return cas


def resolve_selected_ca(cas: list[dict[str, str | bool]], requested: str | None) -> str:
    if requested and any(ca["slug"] == requested for ca in cas):
        return requested
    return cas[0]["slug"] if cas else ""


def get_ca_name(cas: list[dict[str, str | bool]], slug: str) -> str:
    for ca in cas:
        if ca["slug"] == slug:
            return str(ca["name"])
    return slug


def migrate_legacy_ca() -> None:
    if not CA_ROOT.exists():
        return
    legacy_items = [
        "certs",
        "private",
        "newcerts",
        "crl",
        "index.txt",
        "serial",
        "crlnumber",
        "openssl.cnf",
    ]
    if not any((CA_ROOT / item).exists() for item in legacy_items):
        return
    target = CA_ROOT / "default"
    target.mkdir(parents=True, exist_ok=True)
    for item in legacy_items:
        source = CA_ROOT / item
        if source.exists():
            destination = target / item
            if destination.exists():
                continue
            source.replace(destination)


def migrate_legacy_issued() -> None:
    if not ISSUED_ROOT.exists():
        return
    target = ISSUED_ROOT / "default"
    moved_any = False
    for entry in ISSUED_ROOT.iterdir():
        if not entry.is_dir():
            continue
        if entry.name == "default":
            continue
        certs = list(entry.glob("*.crt"))
        keys = list(entry.glob("*.key"))
        if certs and keys:
            target.mkdir(parents=True, exist_ok=True)
            entry.replace(target / entry.name)
            moved_any = True
    if moved_any:
        target.mkdir(parents=True, exist_ok=True)


def get_cert_dir(ca_slug: str, slug: str) -> Path | None:
    safe_slug = secure_filename(slug)
    safe_ca = secure_filename(ca_slug)
    cert_dir = ISSUED_ROOT / safe_ca / safe_slug
    if not cert_dir.exists():
        return None
    return cert_dir


def prepare_storage() -> None:
    CA_ROOT.mkdir(parents=True, exist_ok=True)
    ISSUED_ROOT.mkdir(parents=True, exist_ok=True)
    migrate_legacy_ca()
    migrate_legacy_issued()


def get_revoked_marker(cert_dir: Path) -> str | None:
    revoked_marker = cert_dir / "revoked.txt"
    if revoked_marker.exists():
        return revoked_marker.read_text(encoding="utf-8").strip()
    return None


def list_upstream_suggestions() -> list[dict[str, str]]:
    suggestions: list[dict[str, str]] = []
    env_values = os.environ.get("NGINX_UPSTREAM_SUGGESTIONS", "")
    for raw in [value.strip() for value in env_values.split(",") if value.strip()]:
        suggestions.append({"label": raw, "url": raw})

    file_path = DATA_DIR / "upstreams.txt"
    if file_path.exists():
        for line in file_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "|" in line:
                label, url = [part.strip() for part in line.split("|", 1)]
            else:
                label, url = line, line
            suggestions.append({"label": label, "url": url})

    seen = set()
    unique = []
    for item in suggestions:
        if item["url"] in seen:
            continue
        seen.add(item["url"])
        unique.append(item)
    return unique


def list_certificates_with_keys() -> list[dict[str, str]]:
    if not ISSUED_ROOT.exists():
        return []
    results = []
    for ca_dir in sorted(ISSUED_ROOT.iterdir()):
        if not ca_dir.is_dir():
            continue
        for cert_dir in sorted(ca_dir.iterdir(), reverse=True):
            if not cert_dir.is_dir():
                continue
            cert_path = next(cert_dir.glob("*.crt"), None)
            key_path = next(cert_dir.glob("*.key"), None)
            if not cert_path or not key_path:
                continue
            results.append(
                {
                    "ca_slug": ca_dir.name,
                    "slug": cert_dir.name,
                    "cert_path": str(cert_path),
                    "key_path": str(key_path),
                    "label": f"{ca_dir.name}/{cert_dir.name}",
                }
            )
    return results
