from __future__ import annotations

import datetime
import os
import subprocess
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

APP_ROOT = Path(__file__).parent.resolve()
DATA_DIR = APP_ROOT / "data"
CA_DIR = DATA_DIR / "ca"
ISSUED_DIR = DATA_DIR / "issued"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")


def run_openssl(args: list[str]) -> None:
    subprocess.run(["openssl", *args], check=True)


def ca_exists() -> bool:
    return (CA_DIR / "certs" / "ca.crt").exists() and (CA_DIR / "private" / "ca.key").exists()


def ensure_ca_dirs() -> None:
    (CA_DIR / "certs").mkdir(parents=True, exist_ok=True)
    (CA_DIR / "private").mkdir(parents=True, exist_ok=True)
    (CA_DIR / "newcerts").mkdir(parents=True, exist_ok=True)
    (CA_DIR / "crl").mkdir(parents=True, exist_ok=True)
    (CA_DIR / "index.txt").touch(exist_ok=True)
    serial_file = CA_DIR / "serial"
    if not serial_file.exists():
        serial_file.write_text("1000\n", encoding="utf-8")


def create_ca(common_name: str, days_valid: int) -> None:
    ensure_ca_dirs()
    ca_key = CA_DIR / "private" / "ca.key"
    ca_cert = CA_DIR / "certs" / "ca.crt"
    run_openssl(
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:4096",
            "-nodes",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_cert),
            "-days",
            str(days_valid),
            "-subj",
            f"/CN={common_name}",
        ]
    )


def build_subject(common_name: str, organization: str, country: str) -> str:
    parts = [f"/CN={common_name}"]
    if organization:
        parts.append(f"/O={organization}")
    if country:
        parts.append(f"/C={country}")
    return "".join(parts)


def build_san_config(hostnames: list[str], ip_addresses: list[str]) -> str:
    dns_entries = [f"DNS.{idx + 1} = {value}" for idx, value in enumerate(hostnames) if value]
    ip_entries = [f"IP.{idx + 1} = {value}" for idx, value in enumerate(ip_addresses) if value]
    san_lines = "\n".join(dns_entries + ip_entries)
    return "\n".join(
        [
            "[req]",
            "distinguished_name = req_distinguished_name",
            "req_extensions = v3_req",
            "prompt = no",
            "",
            "[req_distinguished_name]",
            "CN = localhost",
            "",
            "[v3_req]",
            "keyUsage = critical, digitalSignature, keyEncipherment",
            "extendedKeyUsage = serverAuth, clientAuth",
            "subjectAltName = @alt_names",
            "",
            "[alt_names]",
            san_lines or "DNS.1 = localhost",
        ]
    )


def issue_certificate(
    common_name: str,
    organization: str,
    country: str,
    hostnames: list[str],
    ip_addresses: list[str],
    days_valid: int,
) -> tuple[str, Path, Path]:
    ISSUED_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = secure_filename(common_name) or "certificate"
    timestamp = datetime.datetime.now(tz=datetime.UTC).strftime("%Y%m%d%H%M%S")
    cert_slug = f"{safe_name}-{timestamp}"
    cert_dir = ISSUED_DIR / cert_slug
    cert_dir.mkdir(parents=True, exist_ok=True)

    key_path = cert_dir / f"{cert_slug}.key"
    csr_path = cert_dir / f"{cert_slug}.csr"
    cert_path = cert_dir / f"{cert_slug}.crt"
    san_config_path = cert_dir / "san.cnf"

    san_config_path.write_text(build_san_config(hostnames, ip_addresses), encoding="utf-8")

    subject = build_subject(common_name, organization, country)
    run_openssl(
        [
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_path),
            "-out",
            str(csr_path),
            "-subj",
            subject,
            "-config",
            str(san_config_path),
        ]
    )

    ca_cert = CA_DIR / "certs" / "ca.crt"
    ca_key = CA_DIR / "private" / "ca.key"
    run_openssl(
        [
            "x509",
            "-req",
            "-in",
            str(csr_path),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(cert_path),
            "-days",
            str(days_valid),
            "-sha256",
            "-extfile",
            str(san_config_path),
            "-extensions",
            "v3_req",
        ]
    )

    return cert_slug, cert_path, key_path


def list_issued() -> list[dict[str, str]]:
    if not ISSUED_DIR.exists():
        return []
    entries = []
    for entry in sorted(ISSUED_DIR.iterdir(), reverse=True):
        if not entry.is_dir():
            continue
        certs = list(entry.glob("*.crt"))
        keys = list(entry.glob("*.key"))
        if certs and keys:
            entries.append({"slug": entry.name, "cert": certs[0].name, "key": keys[0].name})
    return entries


@app.route("/", methods=["GET"])
def index() -> str:
    return render_template(
        "index.html",
        ca_ready=ca_exists(),
        issued=list_issued(),
    )


@app.route("/ca", methods=["POST"])
def create_ca_route():
    common_name = request.form.get("ca_common_name", "").strip()
    days_valid = int(request.form.get("ca_days_valid", "3650"))
    if not common_name:
        flash("Bitte einen Common Name für die CA angeben.", "error")
        return redirect(url_for("index"))
    try:
        create_ca(common_name, days_valid)
    except subprocess.CalledProcessError:
        flash("Fehler beim Erstellen der CA. Prüfe die OpenSSL-Installation.", "error")
        return redirect(url_for("index"))
    flash("CA erfolgreich erstellt.", "success")
    return redirect(url_for("index"))


@app.route("/cert", methods=["POST"])
def create_cert_route():
    if not ca_exists():
        flash("Bitte zuerst eine CA erstellen.", "error")
        return redirect(url_for("index"))

    common_name = request.form.get("common_name", "").strip()
    organization = request.form.get("organization", "").strip()
    country = request.form.get("country", "").strip()
    hostnames = [value.strip() for value in request.form.get("hostnames", "").split(",") if value.strip()]
    ip_addresses = [value.strip() for value in request.form.get("ip_addresses", "").split(",") if value.strip()]
    days_valid = int(request.form.get("days_valid", "825"))

    if not common_name:
        flash("Bitte einen Common Name für das Zertifikat angeben.", "error")
        return redirect(url_for("index"))

    try:
        issue_certificate(common_name, organization, country, hostnames, ip_addresses, days_valid)
    except subprocess.CalledProcessError:
        flash("Fehler beim Erstellen des Zertifikats. Prüfe die OpenSSL-Installation.", "error")
        return redirect(url_for("index"))

    flash("Zertifikat erfolgreich erstellt.", "success")
    return redirect(url_for("index"))


@app.route("/download/ca", methods=["GET"])
def download_ca():
    if not ca_exists():
        flash("Keine CA vorhanden.", "error")
        return redirect(url_for("index"))
    return send_file(CA_DIR / "certs" / "ca.crt", as_attachment=True, download_name="ca.crt")


@app.route("/download/issued/<slug>/<filetype>", methods=["GET"])
def download_issued(slug: str, filetype: str):
    safe_slug = secure_filename(slug)
    cert_dir = ISSUED_DIR / safe_slug
    if not cert_dir.exists():
        flash("Zertifikat nicht gefunden.", "error")
        return redirect(url_for("index"))

    if filetype == "cert":
        file_path = next(cert_dir.glob("*.crt"), None)
        download_name = f"{safe_slug}.crt"
    elif filetype == "key":
        file_path = next(cert_dir.glob("*.key"), None)
        download_name = f"{safe_slug}.key"
    else:
        flash("Ungültiger Dateityp.", "error")
        return redirect(url_for("index"))

    if not file_path:
        flash("Datei nicht gefunden.", "error")
        return redirect(url_for("index"))
    return send_file(file_path, as_attachment=True, download_name=download_name)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
