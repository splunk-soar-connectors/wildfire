# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
import threading
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest
from soar_sdk.app import App
from soar_sdk.shims.phantom.encryption_helper import encryption_helper

from src.app import create_wildfire_connector_app


class VerdictHandler(BaseHTTPRequestHandler):
    response_status = 200
    response_body = b""
    requests: ClassVar[list[tuple[str, dict[str, str], bytes]]] = []

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        type(self).requests.append((self.path, dict(self.headers), body))
        self.send_response(type(self).response_status)
        self.send_header("Content-Type", "application/xml")
        self.end_headers()
        self.wfile.write(type(self).response_body)

    def log_message(self, _format: str, *args: object) -> None:
        del _format, args


@pytest.fixture
def verdict_server() -> Generator[tuple[str, type[VerdictHandler]]]:
    VerdictHandler.response_status = 200
    VerdictHandler.response_body = b""
    VerdictHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), VerdictHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", VerdictHandler
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def run_url_reputation(app: App, base_url: str, url: str) -> None:
    asset_id = "123"
    input_data = {
        "identifier": "get_url_reputation",
        "action": "url reputation",
        "asset_id": asset_id,
        "container_id": 456,
        "config": {
            "app_version": "4.0.0",
            "directory": ".",
            "main_module": "src.app:app",
            "base_url": base_url,
            "verify_server_cert": True,
            "api_key": encryption_helper.encrypt("test-api-key", salt=asset_id),
            "timeout": 10.0,
        },
        "parameters": [{"url": url}],
    }
    app.handle(json.dumps(input_data))


def test_url_reputation_preserves_request_and_verdict_contract(
    verdict_server: tuple[str, type[VerdictHandler]],
) -> None:
    base_url, handler = verdict_server
    handler.response_body = b"""<?xml version="1.0"?>
<wildfire><get-verdict-info><verdict>4</verdict><analysis_time>2026-09-18T00:00:00Z</analysis_time><url>https://example.test</url><valid>Yes</valid></get-verdict-info></wildfire>"""
    app = create_wildfire_connector_app()

    run_url_reputation(app, base_url, "https://example.test")

    result = app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    assert result.get_message() == "Success: True"
    assert result.get_summary() == {"success": True}
    assert result.get_data() == [
        {
            "verdict_analysis_time": "2026-09-18T00:00:00Z",
            "verdict_code": 4.0,
            "verdict_md5": None,
            "verdict_message": "phishing",
            "verdict_sha256": None,
            "verdict_url": "https://example.test",
            "verdict_valid": "Yes",
        }
    ]
    assert len(handler.requests) == 1
    path, headers, body = handler.requests[0]
    assert path == "/publicapi/get/verdict"
    assert headers["Content-Type"].startswith("multipart/form-data;")
    assert b'name="apikey"' in body
    assert b"test-api-key" in body
    assert b'name="url"' in body
    assert b'filename="' not in body
    assert b"https://example.test" in body


def test_url_reputation_rejects_incomplete_verdict(
    verdict_server: tuple[str, type[VerdictHandler]],
) -> None:
    base_url, handler = verdict_server
    handler.response_body = b"<wildfire><get-verdict-info><verdict>0</verdict></get-verdict-info></wildfire>"
    app = create_wildfire_connector_app()

    run_url_reputation(app, base_url, "https://example.test")

    result = app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert "Verdict could not be retrieved" in result.get_message()
