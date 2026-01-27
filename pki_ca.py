from pathlib import Path

from pki_utils import run_openssl


def ca_exists(ca_dir: Path) -> bool:
    return (ca_dir / "certs" / "ca.crt").exists() and (ca_dir / "private" / "ca.key").exists()


def ensure_ca_dirs(ca_dir: Path) -> None:
    (ca_dir / "certs").mkdir(parents=True, exist_ok=True)
    (ca_dir / "private").mkdir(parents=True, exist_ok=True)
    (ca_dir / "newcerts").mkdir(parents=True, exist_ok=True)
    (ca_dir / "crl").mkdir(parents=True, exist_ok=True)
    (ca_dir / "index.txt").touch(exist_ok=True)
    serial_file = ca_dir / "serial"
    if not serial_file.exists():
        serial_file.write_text("1000\n", encoding="utf-8")
    crl_number = ca_dir / "crlnumber"
    if not crl_number.exists():
        crl_number.write_text("1000\n", encoding="utf-8")


def ca_config_path(ca_dir: Path) -> Path:
    return ca_dir / "openssl.cnf"


def ca_crl_path(ca_dir: Path) -> Path:
    return ca_dir / "crl" / "ca.crl"


def ensure_ca_config(ca_dir: Path) -> Path:
    ensure_ca_dirs(ca_dir)
    config_path = ca_config_path(ca_dir)
    config = f"""[ ca ]
default_ca = CA_default

[ CA_default ]
dir = {ca_dir}
certs = $dir/certs
crl_dir = $dir/crl
database = $dir/index.txt
new_certs_dir = $dir/newcerts
certificate = $dir/certs/ca.crt
private_key = $dir/private/ca.key
serial = $dir/serial
crlnumber = $dir/crlnumber
crl = $dir/crl/ca.crl
default_md = sha256
default_days = 825
default_crl_days = 30
crl_extensions = crl_ext
policy = policy_loose
unique_subject = no
copy_extensions = copy
x509_extensions = v3_req

[ policy_loose ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth

[ crl_ext ]
authorityKeyIdentifier = keyid:always
"""
    if config_path.exists():
        try:
            existing = config_path.read_text(encoding="utf-8")
        except OSError:
            existing = ""
        if (
            f"dir = {ca_dir}" in existing
            and "default_crl_days" in existing
            and "crl_extensions" in existing
        ):
            return config_path
    config_path.write_text(config, encoding="utf-8")
    return config_path


def create_ca(ca_dir: Path, common_name: str, days_valid: int) -> None:
    ensure_ca_dirs(ca_dir)
    ca_key = ca_dir / "private" / "ca.key"
    ca_cert = ca_dir / "certs" / "ca.crt"
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
    ensure_ca_config(ca_dir)


def generate_crl(ca_dir: Path) -> None:
    config_path = ensure_ca_config(ca_dir)
    run_openssl(
        [
            "ca",
            "-config",
            str(config_path),
            "-gencrl",
            "-out",
            str(ca_crl_path(ca_dir)),
        ]
    )
