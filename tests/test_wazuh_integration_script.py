import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "integrations" / "custom-alertmind"


def test_manager_integration_script_posts_alert_with_token(tmp_path: Path):
    received = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received["path"] = self.path
            received["token"] = self.headers.get("X-Wazuh-Token")
            length = int(self.headers["Content-Length"])
            received["payload"] = json.loads(self.rfile.read(length))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"duplicate":false}')

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    alert_path = tmp_path / "alert.json"
    payload = {"id": "test-alert", "rule": {"id": "5710"}}
    alert_path.write_text(json.dumps(payload), encoding="utf-8")
    endpoint = f"http://127.0.0.1:{server.server_port}/integrations/wazuh/alerts"

    try:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(alert_path), "test-token", endpoint],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result.returncode == 0, result.stderr
    assert received == {
        "path": "/integrations/wazuh/alerts",
        "token": "test-token",
        "payload": payload,
    }


def test_manager_integration_script_rejects_bad_arguments():
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 2
    assert "Usage:" in result.stderr
