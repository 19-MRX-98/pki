import datetime
import ipaddress
import subprocess
import tempfile
from pathlib import Path

from werkzeug.utils import secure_filename

from pki_ca import ensure_ca_config, generate_crl
from pki_paths import ISSUED_ROOT
from pki_utils import run_openssl, run_openssl_capture


def build_subject(common_name: str, organization: str, country: str) -> str:
    parts = [f"/CN={common_name}"]
    if organization:
        parts.append(f"/O={organization}")
    if country:
        parts.append(f"/C={country}")
    return "".join(parts)


def normalize_san_entries(
    common_name: str, hostnames: list[str], ip_addresses: list[str]
) -> tuple[list[str], list[str]]:
    clean_hosts = [value for value in hostnames if value]
    clean_ips = [value for value in ip_addresses if value]
    if common_name:
        try:
            ipaddress.ip_address(common_name)
        except ValueError:
            if common_name not in clean_hosts:
                clean_hosts.insert(0, common_name)
        else:
            if common_name not in clean_ips:
                clean_ips.insert(0, common_name)
    return clean_hosts, clean_ips


def build_san_config(common_name: str, hostnames: list[str], ip_addresses: list[str]) -> str:
    dns_entries = [f"DNS.{idx + 1} = {value}" for idx, value in enumerate(hostnames) if value]
    ip_entries = [f"IP.{idx + 1} = {value}" for idx, value in enumerate(ip_addresses) if value]
    san_lines = "\n".join(dns_entries + ip_entries)
    cn_value = common_name or "localhost"
    return "\n".join(
        [
            "[req]",
            "distinguished_name = req_distinguished_name",
            "req_extensions = v3_req",
            "prompt = no",
            "",
            "[req_distinguished_name]",
            f"CN = {cn_value}",
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


def extract_csr_common_name(csr_path: Path) -> str:
    try:
        subject = run_openssl_capture(["req", "-in", str(csr_path), "-noout", "-subject"]).strip()
    except subprocess.CalledProcessError:
        return "csr"
    prefix = "subject="
    if subject.startswith(prefix):
        subject = subject[len(prefix) :].strip()
    for part in subject.split(","):
        part = part.strip()
        if part.startswith("CN="):
            return part.replace("CN=", "", 1).strip()
    return "csr"


def verify_key_matches_csr(csr_bytes: bytes, key_bytes: bytes) -> bool:
    with tempfile.NamedTemporaryFile(suffix=".csr", delete=False) as csr_file:
        csr_file.write(csr_bytes)
        csr_path = Path(csr_file.name)
    with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as key_file:
        key_file.write(key_bytes)
        key_path = Path(key_file.name)
    try:
        csr_pubkey = run_openssl_capture(["req", "-in", str(csr_path), "-noout", "-pubkey"]).strip()
        key_pubkey = run_openssl_capture(["pkey", "-in", str(key_path), "-pubout"]).strip()
        return csr_pubkey == key_pubkey
    except subprocess.CalledProcessError:
        return False
    finally:
        for path in (csr_path, key_path):
            try:
                path.unlink()
            except OSError:
                pass


def issue_certificate(
    ca_dir: Path,
    common_name: str,
    organization: str,
    country: str,
    hostnames: list[str],
    ip_addresses: list[str],
    days_valid: int,
) -> tuple[str, Path, Path]:
    ISSUED_ROOT.mkdir(parents=True, exist_ok=True)
    issued_dir = ISSUED_ROOT / ca_dir.name
    issued_dir.mkdir(parents=True, exist_ok=True)
    safe_name = secure_filename(common_name) or "certificate"
    timestamp = datetime.datetime.now(tz=datetime.UTC).strftime("%Y%m%d%H%M%S")
    cert_slug = f"{safe_name}-{timestamp}"
    cert_dir = issued_dir / cert_slug
    cert_dir.mkdir(parents=True, exist_ok=True)

    key_path = cert_dir / f"{cert_slug}.key"
    csr_path = cert_dir / f"{cert_slug}.csr"
    cert_path = cert_dir / f"{cert_slug}.crt"
    san_config_path = cert_dir / "san.cnf"

    hostnames, ip_addresses = normalize_san_entries(common_name, hostnames, ip_addresses)
    san_config_path.write_text(
        build_san_config(common_name, hostnames, ip_addresses), encoding="utf-8"
    )

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

    ca_cert = ca_dir / "certs" / "ca.crt"
    ca_key = ca_dir / "private" / "ca.key"
    if not ca_cert.exists() or not ca_key.exists():
        raise subprocess.CalledProcessError(1, "openssl")

    config_path = ensure_ca_config(ca_dir)
    run_openssl(
        [
            "ca",
            "-batch",
            "-config",
            str(config_path),
            "-in",
            str(csr_path),
            "-out",
            str(cert_path),
            "-days",
            str(days_valid),
            "-extfile",
            str(san_config_path),
            "-extensions",
            "v3_req",
        ]
    )

    return cert_slug, cert_path, key_path


def issue_from_csr(
    ca_dir: Path, csr_bytes: bytes, days_valid: int
) -> tuple[str, Path, Path, Path]:
    ISSUED_ROOT.mkdir(parents=True, exist_ok=True)
    issued_dir = ISSUED_ROOT / ca_dir.name
    issued_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(suffix=".csr", delete=False) as tmp_file:
        tmp_file.write(csr_bytes)
        tmp_path = Path(tmp_file.name)

    try:
        common_name = extract_csr_common_name(tmp_path)
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass

    safe_name = secure_filename(common_name) or "csr"
    timestamp = datetime.datetime.now(tz=datetime.UTC).strftime("%Y%m%d%H%M%S")
    cert_slug = f"{safe_name}-{timestamp}"
    cert_dir = issued_dir / cert_slug
    cert_dir.mkdir(parents=True, exist_ok=True)

    csr_path = cert_dir / f"{cert_slug}.csr"
    cert_path = cert_dir / f"{cert_slug}.crt"
    csr_path.write_bytes(csr_bytes)

    config_path = ensure_ca_config(ca_dir)
    run_openssl(
        [
            "ca",
            "-batch",
            "-config",
            str(config_path),
            "-in",
            str(csr_path),
            "-out",
            str(cert_path),
            "-days",
            str(days_valid),
        ]
    )

    return cert_slug, cert_path, csr_path, cert_dir


def revoke_certificate(ca_dir: Path, cert_path: Path) -> None:
    config_path = ensure_ca_config(ca_dir)
    run_openssl(["ca", "-batch", "-config", str(config_path), "-revoke", str(cert_path)])
    generate_crl(ca_dir)
