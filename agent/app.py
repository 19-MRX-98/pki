import json
import os
import socket
import subprocess
from http import HTTPStatus
from typing import Any

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")


def _authorized() -> bool:
    if not AGENT_TOKEN:
        return True
    return request.headers.get("X-Reload-Token", "") == AGENT_TOKEN


def _docker_http_request(method: str, path: str) -> tuple[int, bytes]:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect("/var/run/docker.sock")
    headers = [
        f"{method} {path} HTTP/1.1",
        "Host: docker",
        "Content-Length: 0",
        "\r\n",
    ]
    sock.sendall("\r\n".join(headers).encode("utf-8"))

    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    header, rest = data.split(b"\r\n\r\n", 1)
    status_line = header.decode("utf-8", errors="replace").split("\r\n")[0]
    try:
        status_code = int(status_line.split(" ")[1])
    except (IndexError, ValueError):
        status_code = 0

    body = rest
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    sock.close()
    return status_code, body


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


@app.route("/health", methods=["GET"])
def health() -> Response:
    return Response("ok", status=HTTPStatus.OK)


@app.route("/containers", methods=["GET"])
def containers():
    if not _authorized():
        return Response("unauthorized", status=HTTPStatus.UNAUTHORIZED)
    return jsonify({"containers": _list_containers()})


@app.route("/reload", methods=["POST"])
def reload_nginx():
    if not _authorized():
        return Response("unauthorized", status=HTTPStatus.UNAUTHORIZED)
    result = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "reload failed"
        return Response(message, status=HTTPStatus.BAD_REQUEST)
    return Response("reloaded", status=HTTPStatus.OK)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
