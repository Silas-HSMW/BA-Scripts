from __future__ import annotations

import json
# import os
# import platform
# import shutil
# import socket
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.firefox.options import Options


LOG_PATH = Path("client_events_browser.jsonl")

CAPTURE_PROVIDER = "dumpcap"

# Feste Pfade / Werte pro System anpassen
# mit folgendem Command rausfinden:
# & "C:\Program Files\Wireshark\dumpcap.exe" -D     (nur in powershell)
CAPTURE_INTERFACE = "4"

FIREFOX_BINARY = r"C:\Program Files\Mozilla Firefox\firefox.exe"
DUMPCAP_BINARY = r"C:\Program Files\Wireshark\dumpcap.exe"
TSHARK_BINARY = r"C:\Program Files\Wireshark\tshark.exe"

# Linux-Beispiele:
# CAPTURE_INTERFACE = "any"
# FIREFOX_BINARY = "/usr/bin/firefox"
# DUMPCAP_BINARY = "/usr/bin/dumpcap"
# TSHARK_BINARY = "/usr/bin/tshark"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# In Windows kann auch diese Abfrage hängen. Prozess wird nach Timeout beendet.
def get_firefox_version(firefox_binary: str, timeout_seconds: int = 2) -> str:
    proc = subprocess.Popen(
        [firefox_binary, "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
        version = (stdout or stderr).strip()

        if version:
            return version

        return "unknown"

    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

        version = (stdout or stderr).strip()

        if version:
            return version

        return "Get Firefox Version Timeout"


def start_capture(
    pcap_path: Path,
    server_ip: str,
    server_port: int,
) -> subprocess.Popen:
    cmd = [
        DUMPCAP_BINARY,
        "-i", CAPTURE_INTERFACE,
        "-f", f"tcp and host {server_ip} and port {server_port}",
        "-w", str(pcap_path),
        "-q",
    ]

    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def stop_capture(proc: subprocess.Popen) -> tuple[int | None, str]:
    proc.terminate()

    try:
        stdout, stderr = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate(timeout=5)

    return proc.returncode, (stdout + stderr)[-4000:]


def parse_flows_from_pcap(
    pcap_path: Path,
    server_ip: str,
    server_port: int,
) -> list[dict]:
    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        raise RuntimeError(f"Capture file is missing or empty: {pcap_path}")

    display_filter = (
        f"tcp.flags.syn == 1 "
        f"&& tcp.flags.ack == 0 "
        f"&& ip.dst == {server_ip} "
        f"&& tcp.dstport == {server_port}"
    )

    cmd = [
        TSHARK_BINARY,
        "-r", str(pcap_path),
        "-Y", display_filter,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "tcp.stream",
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "tshark failed while parsing capture.\n"
            f"STDOUT: {result.stdout[-1000:]}\n"
            f"STDERR: {result.stderr[-1000:]}"
        )

    flows = []
    seen = set()

    for line in result.stdout.splitlines():
        parts = line.split("\t")

        if len(parts) != 6:
            continue

        start_epoch, local_ip, local_port, remote_ip, remote_port, tcp_stream = parts
        key = (local_ip, local_port, remote_ip, remote_port)

        if key in seen:
            continue

        seen.add(key)

        flows.append({
            "flow_start_epoch": float(start_epoch),
            "local_ip": local_ip,
            "local_port": int(local_port),
            "remote_ip": remote_ip,
            "remote_port": int(remote_port),
            "tcp_stream": int(tcp_stream),
        })

    return flows


def write_jsonl(path: Path, record: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def firefox_request(
    server_host: str,
    endpoint: str,
    server_ip: str,
    server_port: int,
    client_id: str,
    log_path: Path | None = LOG_PATH,
) -> dict:
    event_id = f"firefox-{uuid.uuid4().hex[:12]}"
    url = f"https://{server_host}{endpoint}"

    firefox_binary = FIREFOX_BINARY
    firefox_version = get_firefox_version(firefox_binary)

    record = {
        "event_id": event_id,
        "client_id": client_id,
        "application": "firefox",
        "application_version": firefox_version,
        "target_host": server_host,
        "target_ip": server_ip,
        "target_port": server_port,
        "url": url,
        "start_time": None,
        "command": ["selenium", "firefox", url],
        "browser_binary": firefox_binary,
    }

    capture_proc = None

    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_path = Path(tmpdir) / f"{event_id}.pcap"

        try:
            # check_hostname_resolution(server_host, server_ip)

            capture_proc = start_capture(pcap_path, server_ip, server_port)
            time.sleep(1)

            record["start_time"] = now_iso()

            run_firefox(url, firefox_binary)

            record["end_time"] = now_iso()

            capture_return_code, capture_output = stop_capture(capture_proc)
            capture_proc = None

            record["capture_provider"] = CAPTURE_PROVIDER
            record["capture_return_code"] = capture_return_code

            if capture_output:
                record["capture_output"] = capture_output

            flows = parse_flows_from_pcap(pcap_path, server_ip, server_port)

            record["return_code"] = 0
            record["stderr"] = ""

            if len(flows) == 1:
                flow = flows[0]

                record["local_ip"] = flow["local_ip"]
                record["local_port"] = flow["local_port"]
                record["remote_ip"] = flow["remote_ip"]
                record["remote_port"] = flow["remote_port"]
                record["flow_start_epoch"] = flow["flow_start_epoch"]
                record["tcp_stream"] = flow["tcp_stream"]
                record["status"] = "ok"

            elif len(flows) == 0:
                record["status"] = "no_flow_found"

            else:
                record["status"] = "ambiguous_flows"
                record["flow_count"] = len(flows)
                record["flows_debug"] = flows

        except Exception as exc:
            record["end_time"] = now_iso()
            record["status"] = "exception"
            record["error"] = repr(exc)

            if capture_proc is not None:
                capture_return_code, capture_output = stop_capture(capture_proc)

                record["capture_provider"] = CAPTURE_PROVIDER
                record["capture_return_code"] = capture_return_code

                if capture_output:
                    record["capture_output"] = capture_output

    if log_path is not None:
        write_jsonl(Path(log_path), record)

    return record


def run_firefox(url: str, firefox_binary: str, wait_seconds: int = 5) -> None:
    options = Options()
    options.binary_location = firefox_binary

    options.add_argument("-headless")
    options.accept_insecure_certs = True
    options.page_load_strategy = "none"

    options.set_preference("network.trr.mode", 5)

    with tempfile.TemporaryDirectory(prefix="tlslab-firefox-profile-") as profile_dir:
        options.add_argument("-profile")
        options.add_argument(profile_dir)

        print("starting firefox")
        driver = webdriver.Firefox(options=options)
        driver.set_page_load_timeout(30)

        try:
            print(f"opening url: {url}")
            driver.get(url)
            print("driver.get returned")
            time.sleep(wait_seconds)
        finally:
            print("closing firefox")
            driver.quit()


if __name__ == "__main__":
    result = firefox_request(
        server_host="nginx.test",
        endpoint="",
        server_ip="192.168.178.139",
        server_port=443,
        client_id="linux-client-01",
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))