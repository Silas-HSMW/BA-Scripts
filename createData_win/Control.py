from Browser_Firefox import firefox_request
from Browser_Chrome import chrome_request
from pathlib import Path
from Curl import curl_request
from custom_requests import custom_requests

# urls: https://nginx.test/assets/img-small.bin https://nginx.test/assets/img-large.bin https://nginx.test https://nginx.test/heavy.html

firefox_request(
        server_host="nginx.test",
        endpoint="",
        server_ip="192.168.178.139",
        server_port=443,
        client_id="linux-client-01",
    )


chrome_request(
    server_host="nginx.test",
    endpoint="",
    server_ip="192.168.178.139",
    server_port=443,
    client_id="linux-client-01",
)

curl_request(
    SERVER_HOST="nginx.test",
    ENDPOINT="",
    SERVER_IP="192.168.178.139",
    SERVER_PORT=443,
    CLIENT_ID="linux-client-01",
    LOG_PATH=Path("client_events.jsonl"),
)

custom_requests(
    SERVER_HOST="nginx.test",
    ENDPOINT="",
    SERVER_IP="192.168.178.139",
    SERVER_PORT=443,
    CLIENT_ID="linux-client-01",
    LOG_PATH=Path("client_events.jsonl"),
)