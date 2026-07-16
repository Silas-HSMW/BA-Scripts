import json
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3


'''
stellt systemzeit fest
'''
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


'''
bestimmt Python Requests version
'''
def get_requests_version() -> str:
    return f"requests {requests.__version__} / python {sys.version.split()[0]}"


'''
prüft, ob der Hostname auf die erwartete Server-IP zeigt
'''
def check_hostname_resolution(SERVER_HOST: str, SERVER_IP: str) -> None:
    resolved_ip = socket.gethostbyname(SERVER_HOST)

    if resolved_ip != SERVER_IP:
        raise RuntimeError(
            f"{SERVER_HOST} resolves to {resolved_ip}, expected {SERVER_IP}"
        )


'''
holt Socket aus der Requests Response
'''
def get_response_socket(response) -> socket.socket:
    connection = getattr(response.raw, "_connection", None)
    sock = getattr(connection, "sock", None)

    if sock is not None:
        return sock

    try:
        return response.raw._fp.fp.raw._sock
    except AttributeError:
        raise RuntimeError("Could not access socket from requests response")


def custom_requests(
    SERVER_HOST: str,
    ENDPOINT: str,
    SERVER_IP: str,
    SERVER_PORT: int,
    CLIENT_ID: str,
    LOG_PATH: Path,
) -> dict:
    event_id = f"baseline-requests-{uuid.uuid4().hex[:12]}"
    url = f"https://{SERVER_HOST}{ENDPOINT}"

    requests_version = get_requests_version()

    record = {
        "event_id": event_id,
        "client_id": CLIENT_ID,
        "application": "python-requests",
        "application_version": requests_version,
        "target_host": SERVER_HOST,
        "target_ip": SERVER_IP,
        "target_port": SERVER_PORT,
        "url": url,
        "start_time": None,
        "command": ["python", "requests", url],
    }

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        check_hostname_resolution(SERVER_HOST, SERVER_IP)

        session = requests.Session()
        session.headers.update({
            "Connection": "close",
        })

        record["start_time"] = now_iso()
        start_perf = time.perf_counter()

        response = session.get(
            url,
            timeout=(10, 30),
            verify=False,
            stream=True,
        )

        sock = get_response_socket(response)

        local_ip, local_port = sock.getsockname()[:2]
        remote_ip, remote_port = sock.getpeername()[:2]

        body = response.content
        end_perf = time.perf_counter()

        record["end_time"] = now_iso()
        record["return_code"] = 0
        record["stderr"] = ""

        record["local_ip"] = local_ip
        record["local_port"] = int(local_port)
        record["remote_ip"] = remote_ip
        record["remote_port"] = int(remote_port)

        record["http_code"] = response.status_code
        record["time_total"] = end_perf - start_perf
        record["body_bytes_received"] = len(body)

        record["status"] = "ok"

        response.close()
        session.close()

    # Exeption logging bei Fehlern in verbindung
    except Exception as exc:
        record["end_time"] = now_iso()
        record["status"] = "exception"
        record["error"] = repr(exc)

    # Schreibt logfile
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record