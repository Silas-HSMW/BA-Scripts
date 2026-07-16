import json
import random
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from Browser_Firefox import firefox_request
from Browser_Chrome import chrome_request
from Curl import curl_request
from custom_requests import custom_requests


CLIENT_ID = "linux-arch-client-01"

RUN_ID = f"run-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
LOG_PATH = Path("client_events.jsonl")

DURATION_SECONDS = 12 * 60 * 60
INTERVAL_SECONDS = 60


SERVERS = [
    {
        "name": "nginx",
        "host": "nginx.test",
        "ip": "192.168.178.139",
        "port": 443,
        "endpoints": {
            "browser": [
                "",
                "/heavy.html",
            ],
            "simple": [
                "",
                "/heavy.html",
                "/assets/img-small.bin",
                "/assets/img-large.bin",
            ],
        },
    },
    {
        "name": "apache",
        "host": "apache.test",
        "ip": "192.168.178.135",
        "port": 443,
        "endpoints": {
            "browser": [
                "",
                "/heavy.html",
            ],
            "simple": [
                "",
                "/heavy.html",
                "/assets/img-small.bin",
                "/assets/img-large.bin",
            ],
        },
    },
]


def run_curl(SERVER_HOST, ENDPOINT, SERVER_IP, SERVER_PORT, CLIENT_ID, LOG_PATH):
    return curl_request(
        SERVER_HOST=SERVER_HOST,
        ENDPOINT=ENDPOINT,
        SERVER_IP=SERVER_IP,
        SERVER_PORT=SERVER_PORT,
        CLIENT_ID=CLIENT_ID,
        LOG_PATH=LOG_PATH,
    )


def run_requests(SERVER_HOST, ENDPOINT, SERVER_IP, SERVER_PORT, CLIENT_ID, LOG_PATH):
    return custom_requests(
        SERVER_HOST=SERVER_HOST,
        ENDPOINT=ENDPOINT,
        SERVER_IP=SERVER_IP,
        SERVER_PORT=SERVER_PORT,
        CLIENT_ID=CLIENT_ID,
        LOG_PATH=LOG_PATH,
    )


def run_firefox(SERVER_HOST, ENDPOINT, SERVER_IP, SERVER_PORT, CLIENT_ID, LOG_PATH):
    return firefox_request(
        server_host=SERVER_HOST,
        endpoint=ENDPOINT,
        server_ip=SERVER_IP,
        server_port=SERVER_PORT,
        client_id=CLIENT_ID,
        log_path=LOG_PATH,
    )


def run_chrome(SERVER_HOST, ENDPOINT, SERVER_IP, SERVER_PORT, CLIENT_ID, LOG_PATH):
    return chrome_request(
        server_host=SERVER_HOST,
        endpoint=ENDPOINT,
        server_ip=SERVER_IP,
        server_port=SERVER_PORT,
        client_id=CLIENT_ID,
        log_path=LOG_PATH,
    )


GENERATORS = [
    {
        "name": "curl",
        "type": "simple",
        "function": run_curl,
    },
    {
        "name": "requests",
        "type": "simple",
        "function": run_requests,
    },
    {
        "name": "firefox",
        "type": "browser",
        "function": run_firefox,
    },
    {
        "name": "chrome",
        "type": "browser",
        "function": run_chrome,
    },
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_control_log(record: dict) -> None:
    path = Path("control_events.jsonl")

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def run_one_event() -> dict:
    server = random.choice(SERVERS)
    generator = random.choice(GENERATORS)
    endpoint = random.choice(server["endpoints"][generator["type"]])

    print(
        f"[{now_iso()}] "
        f"run_id={RUN_ID} "
        f"client_id={CLIENT_ID} "
        f"generator={generator['name']} "
        f"server={server['name']} "
        f"endpoint={endpoint}"
    )

    record = generator["function"](
        SERVER_HOST=server["host"],
        ENDPOINT=endpoint,
        SERVER_IP=server["ip"],
        SERVER_PORT=server["port"],
        CLIENT_ID=CLIENT_ID,
        LOG_PATH=LOG_PATH,
    )

    record["run_id"] = RUN_ID
    record["server_name"] = server["name"]
    record["selected_generator"] = generator["name"]
    record["selected_endpoint"] = endpoint
    record["control_time"] = now_iso()

    append_control_log(record)

    return record


def main() -> None:
    random.seed()

    start_time = time.time()
    end_time = start_time + DURATION_SECONDS

    print(f"Starting run {RUN_ID}")
    print(f"Client: {CLIENT_ID}")
    print(f"Duration: {DURATION_SECONDS} seconds")
    print(f"Interval: {INTERVAL_SECONDS} seconds")

    while time.time() < end_time:
        loop_start = time.time()

        try:
            record = run_one_event()
            print(f"status={record.get('status')}")
        except Exception as exc:
            error_record = {
                "run_id": RUN_ID,
                "client_id": CLIENT_ID,
                "control_time": now_iso(),
                "status": "control_exception",
                "error": repr(exc),
            }

            append_control_log(error_record)
            print(f"control_exception: {exc!r}")

        elapsed = time.time() - loop_start
        sleep_time = max(0, INTERVAL_SECONDS - elapsed)
        time.sleep(sleep_time)

    print(f"Finished run {RUN_ID}")


if __name__ == "__main__":
    main()