import os
import re
import shlex
import shutil
import socket
import subprocess
import json
from pathlib import Path

NGINX_SITES_DIR = Path(os.environ.get("NGINX_SITES_DIR", "/etc/nginx/sites-enabled"))
NGINX_CERTS_DIR = Path(os.environ.get("NGINX_CERTS_DIR", "/etc/nginx/certs"))
NGINX_RELOAD_CONTAINER = os.environ.get("NGINX_RELOAD_CONTAINER", "")
NGINX_RELOAD_CMD = os.environ.get("NGINX_RELOAD_CMD", "")

_DOMAIN_RE = re.compile(r"^(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


def parse_domains(primary: str, extra: str) -> list[str]:
    domains = []
    for value in [primary, extra]:
        if not value:
            continue
        parts = [part.strip() for part in value.replace("\n", ",").split(",")]
        domains.extend([part for part in parts if part])
    return domains


def validate_domains(domains: list[str]) -> list[str]:
    valid = []
    for domain in domains:
        if _DOMAIN_RE.match(domain):
            valid.append(domain)
    return valid


def sanitize_domain(domain: str) -> str:
    safe = domain.replace("*", "_wildcard_")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", safe)
    return safe


def build_vhost(
    server_names: list[str],
    upstream_url: str,
    cert_path: Path,
    key_path: Path,
    redirect_http: bool,
) -> str:
    server_name = " ".join(server_names)
    lines = []
    if redirect_http:
        lines.append("server {")
        lines.append("    listen 80;")
        lines.append(f"    server_name {server_name};")
        lines.append("    return 301 https://$host$request_uri;")
        lines.append("}")
        lines.append("")

    lines.append("server {")
    lines.append("    listen 443 ssl;")
    lines.append(f"    server_name {server_name};")
    lines.append("")
    lines.append(f"    ssl_certificate {cert_path};")
    lines.append(f"    ssl_certificate_key {key_path};")
    lines.append("")
    lines.append("    location / {")
    lines.append(f"        proxy_pass {upstream_url};")
    lines.append("        proxy_set_header Host $host;")
    lines.append("        proxy_set_header X-Real-IP $remote_addr;")
    lines.append("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
    lines.append("        proxy_set_header X-Forwarded-Proto $scheme;")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def write_nginx_files(
    primary_domain: str,
    server_names: list[str],
    upstream_url: str,
    cert_pem: str,
    key_pem: str,
    ca_pem: str | None,
    redirect_http: bool,
) -> tuple[Path, Path, Path]:
    domain_slug = sanitize_domain(primary_domain)
    NGINX_CERTS_DIR.mkdir(parents=True, exist_ok=True)
    NGINX_SITES_DIR.mkdir(parents=True, exist_ok=True)

    cert_path = NGINX_CERTS_DIR / f"{domain_slug}.crt"
    key_path = NGINX_CERTS_DIR / f"{domain_slug}.key"
    fullchain = cert_pem.strip()
    if ca_pem:
        fullchain = f"{fullchain}\n{ca_pem.strip()}\n"
    else:
        fullchain = f"{fullchain}\n"
    cert_path.write_text(fullchain, encoding="utf-8")
    key_path.write_text(key_pem.strip() + "\n", encoding="utf-8")

    vhost_path = NGINX_SITES_DIR / f"{domain_slug}.conf"
    vhost_path.write_text(
        build_vhost(server_names, upstream_url, cert_path, key_path, redirect_http),
        encoding="utf-8",
    )

    return vhost_path, cert_path, key_path


def _run_command(command: list[str]) -> None:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "Unbekannter Fehler"
        raise RuntimeError(message)


def _docker_http_request(method: str, path: str, body: bytes | None) -> tuple[int, bytes]:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect("/var/run/docker.sock")
    headers = [
        f"{method} {path} HTTP/1.1",
        "Host: docker",
    ]
    if body is None:
        headers.append("Content-Length: 0")
        payload = "\r\n".join(headers).encode("utf-8") + b"\r\n\r\n"
    else:
        headers.append("Content-Type: application/json")
        headers.append(f"Content-Length: {len(body)}")
        payload = "\r\n".join(headers).encode("utf-8") + b"\r\n\r\n" + body
    sock.sendall(payload)

    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    header, rest = data.split(b"\r\n\r\n", 1)
    header_lines = header.decode("utf-8", errors="replace").split("\r\n")
    status_line = header_lines[0]
    try:
        status_code = int(status_line.split(" ")[1])
    except (IndexError, ValueError):
        status_code = 0
    headers_map = {}
    for line in header_lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers_map[key.strip().lower()] = value.strip()
    content_length = headers_map.get("content-length")
    body_bytes = rest
    if content_length is not None:
        target = int(content_length)
        while len(body_bytes) < target:
            chunk = sock.recv(4096)
            if not chunk:
                break
            body_bytes += chunk
        body_bytes = body_bytes[:target]
    else:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            body_bytes += chunk
    sock.close()
    return status_code, body_bytes


def _docker_exec(container: str, cmd: list[str]) -> None:
    create_body = json.dumps(
        {"AttachStdout": True, "AttachStderr": True, "Cmd": cmd}
    ).encode("utf-8")
    status, body = _docker_http_request("POST", f"/containers/{container}/exec", create_body)
    if status < 200 or status >= 300:
        message = body.decode("utf-8", errors="replace").strip() or "Docker exec create failed"
        raise RuntimeError(message)
    try:
        exec_id = json.loads(body.decode("utf-8"))["Id"]
    except (KeyError, json.JSONDecodeError):
        raise RuntimeError("Docker exec create returned no Id")
    start_body = json.dumps({"Detach": False, "Tty": False}).encode("utf-8")
    status, output = _docker_http_request("POST", f"/exec/{exec_id}/start", start_body)
    if status < 200 or status >= 300:
        message = output.decode("utf-8", errors="replace").strip() or "Docker exec start failed"
        raise RuntimeError(message)


def reload_nginx() -> None:
    if NGINX_RELOAD_CMD:
        _run_command(shlex.split(NGINX_RELOAD_CMD))
        return
    if NGINX_RELOAD_CONTAINER:
        if shutil.which("docker"):
            _run_command(["docker", "exec", NGINX_RELOAD_CONTAINER, "nginx", "-s", "reload"])
            return
        _docker_exec(NGINX_RELOAD_CONTAINER, ["nginx", "-s", "reload"])
        return
    _run_command(["nginx", "-s", "reload"])
