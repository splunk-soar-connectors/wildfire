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


class WildFireProbeHandler(BaseHTTPRequestHandler):
    response_status = 200
    response_body = b"<wildfire/>"
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
def wildfire_server() -> Generator[tuple[str, type[WildFireProbeHandler]]]:
    WildFireProbeHandler.response_status = 200
    WildFireProbeHandler.response_body = b"<wildfire/>"
    WildFireProbeHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), WildFireProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", WildFireProbeHandler
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def run_test_connectivity(app: App, base_url: str, api_key: str) -> None:
    asset_id = "123"
    input_data = {
        "identifier": "test_connectivity",
        "action": "test_connectivity",
        "asset_id": asset_id,
        "container_id": 456,
        "config": {
            "app_version": "4.0.0",
            "directory": ".",
            "main_module": "src.app:app",
            "base_url": base_url,
            "verify_server_cert": True,
            "api_key": encryption_helper.encrypt(api_key, salt=asset_id),
            "timeout": 10.0,
        },
        "parameters": [{}],
    }
    app.handle(json.dumps(input_data))


def test_connectivity_uploads_legacy_probe_with_api_key_in_body(
    wildfire_server: tuple[str, type[WildFireProbeHandler]],
) -> None:
    base_url, handler = wildfire_server
    app = create_wildfire_connector_app()

    run_test_connectivity(app, base_url, "test-api-key")

    result = app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    assert len(handler.requests) == 1
    path, headers, body = handler.requests[0]
    assert path == "/publicapi/submit/file"
    assert headers["Content-Type"].startswith("multipart/form-data;")
    assert b"test-api-key" in body
    assert b'name="apikey"' in body
    assert b'filename="wildfire_test_connectivity.pdf"' in body
    assert b"%PDF" in body


def test_connectivity_preserves_legacy_status_fallback(
    wildfire_server: tuple[str, type[WildFireProbeHandler]],
) -> None:
    base_url, handler = wildfire_server
    handler.response_status = 401
    handler.response_body = b""
    app = create_wildfire_connector_app()

    run_test_connectivity(app, base_url, "invalid-api-key")

    result = app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert (
        "REST Api Call returned error, status_code: 401, detail: API key invalid"
        in result.get_message()
    )
