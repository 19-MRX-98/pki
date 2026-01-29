import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

NGINX_SITES_DIR = Path(os.environ.get("NGINX_SITES_DIR", "/etc/nginx/sites-enabled"))
NGINX_CERTS_DIR = Path(os.environ.get("NGINX_CERTS_DIR", "/etc/nginx/certs"))
NGINX_RELOAD_CONTAINER = os.environ.get("NGINX_RELOAD_CONTAINER", "")
NGINX_RELOAD_SERVICE = os.environ.get("NGINX_RELOAD_SERVICE", "")
NGINX_RELOAD_CMD = os.environ.get("NGINX_RELOAD_CMD", "")
NGINX_AGENT_URL = os.environ.get("NGINX_AGENT_URL", "")
NGINX_AGENT_TOKEN = os.environ.get("NGINX_AGENT_TOKEN", "")
DEFAULTS_PATH = Path(os.environ.get("NGINX_DEFAULTS_PATH", "/app/data/nginx_defaults.json"))

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


def load_defaults() -> dict[str, str | bool]:
    if DEFAULTS_PATH.exists():
        try:
            data = json.loads(DEFAULTS_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
    else:
        data = {}
    return {
        "upstream_url": str(data.get("upstream_url", "")),
        "redirect_http": bool(data.get("redirect_http", True)),
    }


def save_defaults(upstream_url: str, redirect_http: bool) -> None:
    DEFAULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {"upstream_url": upstream_url, "redirect_http": redirect_http}
    DEFAULTS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_cert_files(
    cert_path: Path, key_path: Path, cert_pem: str, key_pem: str, ca_pem: str | None
) -> None:
    fullchain = cert_pem.strip()
    if ca_pem:
        fullchain = f"{fullchain}\n{ca_pem.strip()}\n"
    else:
        fullchain = f"{fullchain}\n"
    cert_path.write_text(fullchain, encoding="utf-8")
    key_path.write_text(key_pem.strip() + "\n", encoding="utf-8")


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
    write_cert_files(cert_path, key_path, cert_pem, key_pem, ca_pem)

    vhost_path = NGINX_SITES_DIR / f"{domain_slug}.conf"
    vhost_path.write_text(
        build_vhost(server_names, upstream_url, cert_path, key_path, redirect_http),
        encoding="utf-8",
    )

    return vhost_path, cert_path, key_path


def write_vhost_only(
    vhost_path: Path,
    server_names: list[str],
    upstream_url: str,
    cert_path: Path,
    key_path: Path,
    redirect_http: bool,
) -> None:
    vhost_path.write_text(
        build_vhost(server_names, upstream_url, cert_path, key_path, redirect_http),
        encoding="utf-8",
    )


def parse_vhost(content: str) -> dict[str, str | list[str] | bool]:
    server_names = re.findall(r"server_name\\s+([^;]+);", content, flags=re.IGNORECASE)
    domains: list[str] = []
    for entry in server_names:
        domains.extend([item.strip() for item in entry.split() if item.strip()])
    proxy_pass = re.findall(r"proxy_pass\\s+([^;]+);", content)
    ssl_cert = re.findall(r"ssl_certificate\\s+([^;]+);", content)
    ssl_key = re.findall(r"ssl_certificate_key\\s+([^;]+);", content)
    redirect_http = "listen 80" in content and "return 301" in content
    return {
        "server_names": domains,
        "upstream_url": proxy_pass[0] if proxy_pass else "",
        "cert_path": ssl_cert[0] if ssl_cert else "",
        "key_path": ssl_key[0] if ssl_key else "",
        "redirect_http": redirect_http,
    }


def list_vhosts() -> list[dict[str, str | list[str] | bool]]:
    if not NGINX_SITES_DIR.exists():
        return []
    items = []
    for entry in sorted(NGINX_SITES_DIR.glob("*.conf")):
        try:
            content = entry.read_text(encoding="utf-8")
        except OSError:
            continue
        parsed = parse_vhost(content)
        items.append(
            {
                "name": entry.name,
                "path": str(entry),
                "server_names": parsed["server_names"],
                "upstream_url": parsed["upstream_url"],
                "cert_path": parsed["cert_path"],
                "key_path": parsed["key_path"],
                "redirect_http": parsed["redirect_http"],
                "raw_content": content,
            }
        )
    return items


def get_vhost(name: str) -> tuple[Path, dict[str, str | list[str] | bool] | None]:
    safe = Path(name).name
    if not safe.endswith(".conf"):
        safe = f"{safe}.conf"
    vhost_path = NGINX_SITES_DIR / safe
    if not vhost_path.exists():
        return vhost_path, None
    try:
        content = vhost_path.read_text(encoding="utf-8")
    except OSError:
        return vhost_path, None
    return vhost_path, parse_vhost(content)


def delete_vhost(name: str) -> None:
    vhost_path, _parsed = get_vhost(name)
    if vhost_path.exists():
        vhost_path.unlink()


def _run_command(command: list[str]) -> None:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "Unbekannter Fehler"
        raise RuntimeError(message)


def _docker_http_request(method: str, path: str, body: bytes | None) -> tuple[int, bytes]:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(1.5)
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


def _docker_find_container_by_service(service_name: str) -> str | None:
    payload = None
    if shutil.which("curl"):
        try:
            result = subprocess.run(
                [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--unix-socket",
                    "/var/run/docker.sock",
                    "http://localhost/containers/json?all=1",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0:
                payload = json.loads(result.stdout)
        except (subprocess.SubprocessError, json.JSONDecodeError):
            payload = None
    if payload is None:
        try:
            status, body = _docker_http_request("GET", "/containers/json?all=1", None)
        except (OSError, socket.timeout):
            return None
        if status < 200 or status >= 300:
            return None
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return None
    label_key = "com.docker.swarm.service.name"
    service_name = service_name.strip()
    for item in payload:
        labels = item.get("Labels", {}) or {}
        label_value = labels.get(label_key, "")
        if label_value == service_name:
            return item.get("Id")
        if label_value and label_value.endswith(f"_{service_name}"):
            return item.get("Id")
        names = [name.lstrip("/") for name in item.get("Names", []) if name]
        for name in names:
            if name == service_name or name.endswith(f".{service_name}") or service_name in name:
                return item.get("Id")
    return None


def list_local_containers() -> list[dict[str, str | list[dict[str, str]]]]:
    if NGINX_AGENT_URL:
        try:
            req = urllib.request.Request(
                f\"{NGINX_AGENT_URL.rstrip('/')}/containers\",
                headers={\"X-Reload-Token\": NGINX_AGENT_TOKEN} if NGINX_AGENT_TOKEN else {},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read().decode(\"utf-8\"))
            return data.get(\"containers\", [])
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
            pass
    payload = None
    if shutil.which("curl"):
        try:
            result = subprocess.run(
                [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--unix-socket",
                    "/var/run/docker.sock",
                    "http://localhost/containers/json?all=1",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0:
                payload = json.loads(result.stdout)
        except (subprocess.SubprocessError, json.JSONDecodeError):
            payload = None
    if payload is None:
        try:
            status, body = _docker_http_request("GET", "/containers/json?all=1", None)
        except (OSError, socket.timeout):
            return []
        if status < 200 or status >= 300:
            return []
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return []

    containers = []
    for item in payload:
        names = [name.lstrip("/") for name in item.get("Names", []) if name]
        name = names[0] if names else item.get("Id", "")[:12]
        ports = item.get("Ports", [])
        port_list = []
        for port in ports:
            private_port = str(port.get("PrivatePort", ""))
            public_port = port.get("PublicPort")
            port_list.append(
                {
                    "private": private_port,
                    "public": str(public_port) if public_port else "",
                    "type": str(port.get("Type", "")),
                }
            )
        containers.append(
            {
                "name": name,
                "image": item.get("Image", ""),
                "state": item.get("State", ""),
                "status": item.get("Status", ""),
                "ports": port_list,
            }
        )
    return containers


def reload_nginx() -> None:
    if NGINX_AGENT_URL:
        try:
            req = urllib.request.Request(
                f\"{NGINX_AGENT_URL.rstrip('/')}/reload\",
                method=\"POST\",
                headers={\"X-Reload-Token\": NGINX_AGENT_TOKEN} if NGINX_AGENT_TOKEN else {},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status >= 300:
                    raise RuntimeError(resp.read().decode(\"utf-8\").strip())
            return
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(str(exc))
    if NGINX_RELOAD_CMD:
        _run_command(shlex.split(NGINX_RELOAD_CMD))
        return
    if NGINX_RELOAD_CONTAINER:
        if shutil.which("docker"):
            _run_command(["docker", "exec", NGINX_RELOAD_CONTAINER, "nginx", "-s", "reload"])
            return
        _docker_exec(NGINX_RELOAD_CONTAINER, ["nginx", "-s", "reload"])
        return
    if NGINX_RELOAD_SERVICE:
        container_id = _docker_find_container_by_service(NGINX_RELOAD_SERVICE)
        if not container_id:
            raise RuntimeError(f"Kein Container für Service {NGINX_RELOAD_SERVICE} gefunden")
        _docker_exec(container_id, ["nginx", "-s", "reload"])
        return
    _run_command(["nginx", "-s", "reload"])
