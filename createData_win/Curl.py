import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path


'''
stellt systemzeit fest
'''
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

'''
bestimmt Curl version
'''
def get_curl_version() -> str:
    result = subprocess.run(
        ["curl", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.splitlines()[0]

'''
schlüsselt die zurückgegebenen CURL Metadaten werte auf und wie sauber ab
'''
def parse_curl_meta(stdout: str) -> dict:
    marker = "__CURL_META__"

    for line in stdout.splitlines():
        if line.startswith(marker):
            parts = line.removeprefix(marker).split("|")

            return {
                "local_ip": parts[0],
                "local_port": int(parts[1]),
                "remote_ip": parts[2],
                "remote_port": int(parts[3]),
                "http_code": int(parts[4]),
                "time_total": float(parts[5]),
                "ssl_verify_result": int(parts[6]),
            }

    raise RuntimeError(f"No curl metadata found in stdout: {stdout!r}")


def curl_request(
    SERVER_HOST: str,
    ENDPOINT: str,
    SERVER_IP: str,
    SERVER_PORT: int,
    CLIENT_ID: str,
    LOG_PATH: Path,
) -> dict:
    event_id = f"baseline-curl-{uuid.uuid4().hex[:12]}"
    url = f"https://{SERVER_HOST}{ENDPOINT}"

    curl_version = get_curl_version()

    cmd = [
        "curl",
        "--silent", # unterdrückt Fortschrittsinformaitonen von curl aber,
        "--show-error", # zeigt Fehler trotzdem an
        "--insecure", # verhindert abbruch durch zertifikatsfehler
        "--http1.1", # stellt sicher das immer eine neue verbindung aufgebaut wird
        "--resolve",
        f"{SERVER_HOST}:{SERVER_PORT}:{SERVER_IP}", # garantiert das Server IP immer Aufgelöst wird. sollte jedoch schon auf OS ebene gemacht werden!!
        "--connect-timeout", "10", # maximal zeit für verbindungsaufbau
        "--max-time", "30", # maximalzeit insgesamt
        "-H", "Connection: close", # Schließt verbindung anschließent
        "-w","__CURL_META__%{local_ip}|%{local_port}|%{remote_ip}|%{remote_port}|%{http_code}|%{time_total}|%{ssl_verify_result}\n", # gibt an Welche werte nach abgeschlossener verbindung angegeben werden sollen
        url,
    ]

    start_time = now_iso()

    record = {
        "event_id": event_id,
        "client_id": CLIENT_ID,
        "application": "curl",
        "application_version": curl_version,
        "target_host": SERVER_HOST,
        "target_ip": SERVER_IP,
        "target_port": SERVER_PORT,
        "url": url,
        "start_time": start_time,
        "command": cmd,
    }

    try:
        # start subprozess für cmd command. verbesserung der stabilität und einfachere multithread
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=40,
        )

        end_time = now_iso()
        record["end_time"] = end_time
        record["return_code"] = result.returncode
        record["stderr"] = result.stderr[-1000:] # speichert fehlermeldung, wenn leer keine probleme

        if result.returncode == 0:
            meta = parse_curl_meta(result.stdout)
            record.update(meta)
            record["status"] = "ok"
        else:
            record["status"] = "error"
            record["stdout"] = result.stdout[-1000:] # speichert fehlermeldung

    # Exeption logging bei Fehlern in verbindung
    except Exception as exc:
        record["end_time"] = now_iso()
        record["status"] = "exception"
        record["error"] = repr(exc)

    # Schreibt logfile
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record

