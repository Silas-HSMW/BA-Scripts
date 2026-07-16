import json
import os
import platform
import shutil
import socket
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
CAPTURE_INTERFACE = os.environ.get("TLSLAB_CAPTURE_IFACE")

FIREFOX_BINARY = os.environ.get("TLSLAB_FIREFOX_BINARY")
DUMPCAP_BINARY = os.environ.get("TLSLAB_DUMPCAP")
TSHARK_BINARY = os.environ.get("TLSLAB_TSHARK")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def find_executable(name: str, configured_path: str | None = None) -> str:
    if configured_path:
        path = Path(configured_path)

        if path.exists():
            return str(path)

        raise RuntimeError(f"Configured path for {name} does not exist: {configured_path}")

    path = shutil.which(name)

    if path is None:
        raise RuntimeError(f"Required executable not found: {name}")

    return path


def get_firefox_version(firefox_binary: str) -> str:
    result = subprocess.run(
        [firefox_binary, "--version"],
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout.strip()


def check_hostname_resolution(server_host: str, server_ip: str) -> None:
    resolved_ip = socket.gethostbyname(server_host)

    if resolved_ip != server_ip:
        raise RuntimeError(
            f"{server_host} resolves to {resolved_ip}, expected {server_ip}"
        )


def dumpcap_interfaces() -> str:
    dumpcap = find_executable("dumpcap", DUMPCAP_BINARY)

    result = subprocess.run(
        [dumpcap, "-D"],
        capture_output=True,
        text=True,
        check=False,
    )

    return result.stdout + result.stderr


def get_capture_interface() -> str:
    if CAPTURE_INTERFACE:
        return CAPTURE_INTERFACE

    if platform.system().lower() == "linux":
        return "any"

    raise RuntimeError(
        "No capture interface configured. Set TLSLAB_CAPTURE_IFACE.\n\n"
        f"Available dumpcap interfaces:\n{dumpcap_interfaces()}"
    )


def start_capture(pcap_path: Path, server_ip: str, server_port: int) -> subprocess.Popen:
    dumpcap = find_executable("dumpcap", DUMPCAP_BINARY)
    interface = get_capture_interface()

    cmd = [
        dumpcap,
        "-i", interface,
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

    output = (stdout + stderr)[-4000:]
    return proc.returncode, output


def parse_flows_from_pcap(
    pcap_path: Path,
    server_ip: str,
    server_port: int,
) -> list[dict]:
    tshark = find_executable("tshark", TSHARK_BINARY)

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        raise RuntimeError(f"Capture file is missing or empty: {pcap_path}")

    display_filter = (
        f"tcp.flags.syn == 1 "
        f"&& tcp.flags.ack == 0 "
        f"&& ip.dst == {server_ip} "
        f"&& tcp.dstport == {server_port}"
    )

    cmd = [
        tshark,
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

        flow_start_epoch, local_ip, local_port, remote_ip, remote_port, tcp_stream = parts
        key = (local_ip, local_port, remote_ip, remote_port)

        if key in seen:
            continue

        seen.add(key)

        flows.append({
            "flow_start_epoch": float(flow_start_epoch),
            "local_ip": local_ip,
            "local_port": int(local_port),
            "remote_ip": remote_ip,
            "remote_port": int(remote_port),
            "tcp_stream": int(tcp_stream),
        })

    return flows


def run_firefox(url: str, firefox_binary: str, wait_seconds: int = 5) -> None:
    options = Options()
    options.binary_location = firefox_binary
    options.add_argument("-headless")
    options.accept_insecure_certs = True

    driver = webdriver.Firefox(options=options)
    driver.set_page_load_timeout(30)

    try:
        driver.get(url)
        time.sleep(wait_seconds)
    finally:
        driver.quit()


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
    event_id = f"baseline-firefox-{uuid.uuid4().hex[:12]}"
    url = f"https://{server_host}{endpoint}"

    firefox_binary = find_executable("firefox", FIREFOX_BINARY)
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
            check_hostname_resolution(server_host, server_ip)

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

                record.update({
                    "local_ip": flow["local_ip"],
                    "local_port": flow["local_port"],
                    "remote_ip": flow["remote_ip"],
                    "remote_port": flow["remote_port"],
                    "flow_start_epoch": flow["flow_start_epoch"],
                    "tcp_stream": flow["tcp_stream"],
                    "status": "ok",
                })

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


if __name__ == "__main__":
    result = firefox_request(
        server_host="nginx.test",
        endpoint="",
        server_ip="192.168.178.139",
        server_port=443,
        client_id="linux-client-01",
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))