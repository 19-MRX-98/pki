import json
import os
import socket
import subprocess
from http import HTTPStatus
from typing import Any

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
NGINX_RELOAD_CONTAINER = os.environ.get("NGINX_RELOAD_CONTAINER", "")
NGINX_RELOAD_SERVICE = os.environ.get("NGINX_RELOAD_SERVICE", "")


def _authorized() -> bool:
    if not AGENT_TOKEN:
        return True
    return request.headers.get("X-Reload-Token", "") == AGENT_TOKEN


def _docker_http_request(
    method: str,
    path: str,
    body: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    if body is None:
        body = b""
    headers = {
        "Host": "docker",
        "Connection": "close",
        "Content-Length": str(len(body)),
    }
    if body:
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect("/var/run/docker.sock")
        request_lines = [f"{method} {path} HTTP/1.0"]
        request_lines.extend(f"{key}: {value}" for key, value in headers.items())
        request_lines.append("\r\n")
        sock.sendall("\r\n".join(request_lines).encode("utf-8") + body)

        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except TimeoutError:
            sock.close()
            return 0, b""

        if b"\r\n\r\n" not in data:
            sock.close()
            return 0, b""
        header, rest = data.split(b"\r\n\r\n", 1)
        status_line = header.decode("utf-8", errors="replace").split("\r\n")[0]
        try:
            status_code = int(status_line.split(" ")[1])
        except (IndexError, ValueError):
            status_code = 0

        body_data = rest
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                body_data += chunk
        except TimeoutError:
            pass
        sock.close()
        return status_code, body_data
    except OSError:
        return 0, b""


def _docker_exec(container: str, cmd: list[str]) -> tuple[int, bytes]:
    create_body = json.dumps(
        {
            "AttachStdin": False,
            "AttachStdout": True,
            "AttachStderr": True,
            "Tty": False,
            "Cmd": cmd,
        }
    ).encode("utf-8")
    status, body = _docker_http_request(
        "POST",
        f"/containers/{container}/exec",
        create_body,
    )
    if status < 200 or status >= 300:
        return status, body
    try:
        exec_id = json.loads(body.decode("utf-8")).get("Id", "")
    except json.JSONDecodeError:
        return 0, b""
    if not exec_id:
        return 0, b""
    start_body = json.dumps({"Detach": False, "Tty": False}).encode("utf-8")
    return _docker_http_request(
        "POST",
        f"/exec/{exec_id}/start",
        start_body,
    )


def _docker_find_container_by_service(service_name: str) -> str | None:
    status, body = _docker_http_request("GET", "/containers/json?all=1")
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


def _list_containers() -> list[dict[str, Any]]:
    status, body = _docker_http_request("GET", "/containers/json?all=1")
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
                "labels": item.get("Labels", {}) or {},
            }
        )
    return containers


def _list_services() -> list[dict[str, Any]]:
    status, body = _docker_http_request("GET", "/services")
    if status < 200 or status >= 300:
        return []
    try:
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return []
    services = []
    for item in payload:
        spec = item.get("Spec", {}) or {}
        task_template = spec.get("TaskTemplate", {}) or {}
        container_spec = task_template.get("ContainerSpec", {}) or {}
        mode = "replicated"
        if "Global" in spec.get("Mode", {}):
            mode = "global"
        ports = []
        for port in (item.get("Endpoint", {}) or {}).get("Ports", []) or []:
            ports.append(
                {
                    "target": str(port.get("TargetPort", "")),
                    "published": str(port.get("PublishedPort", "")),
                    "protocol": str(port.get("Protocol", "")),
                }
            )
        services.append(
            {
                "name": spec.get("Name", ""),
                "image": container_spec.get("Image", ""),
                "mode": mode,
                "ports": ports,
            }
        )
    return services


@app.route("/health", methods=["GET"])
def health() -> Response:
    return Response("ok", status=HTTPStatus.OK)


@app.route("/containers", methods=["GET"])
def containers():
    if not _authorized():
        return Response("unauthorized", status=HTTPStatus.UNAUTHORIZED)
    return jsonify({"containers": _list_containers()})


@app.route("/services", methods=["GET"])
def services():
    if not _authorized():
        return Response("unauthorized", status=HTTPStatus.UNAUTHORIZED)
    return jsonify({"services": _list_services()})


@app.route("/reload", methods=["POST"])
def reload_nginx():
    if not _authorized():
        return Response("unauthorized", status=HTTPStatus.UNAUTHORIZED)
    target_container = NGINX_RELOAD_CONTAINER
    if not target_container and NGINX_RELOAD_SERVICE:
        target_container = _docker_find_container_by_service(NGINX_RELOAD_SERVICE) or ""
    if target_container:
        status, body = _docker_exec(target_container, ["nginx", "-s", "reload"])
        if status >= 200 and status < 300:
            return Response("reloaded", status=HTTPStatus.OK)
        message = body.decode("utf-8", errors="replace").strip() or "reload failed"
        return Response(message, status=HTTPStatus.BAD_REQUEST)

    result = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "reload failed"
        return Response(message, status=HTTPStatus.BAD_REQUEST)
    return Response("reloaded", status=HTTPStatus.OK)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
