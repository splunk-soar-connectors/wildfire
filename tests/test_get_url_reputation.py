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
from collections.abc import Callable
from typing import Any

import pytest
from soar_sdk.app import App
from soar_sdk.shims.phantom.encryption_helper import encryption_helper

from src.app import create_wildfire_connector_app


def test_url_reputation_rejects_invalid_url_before_request() -> None:
    app = create_wildfire_connector_app()
    asset_id = "wildfire-url-validation-test"
    app.handle(
        json.dumps(
            {
                "identifier": "get_url_reputation",
                "action": "url reputation",
                "asset_id": asset_id,
                "container_id": 456,
                "config": {
                    "app_version": "4.0.0",
                    "directory": ".",
                    "main_module": "src.app:app",
                    "base_url": "https://wildfire.invalid",
                    "verify_server_cert": True,
                    "api_key": encryption_helper.encrypt("unused", salt=asset_id),
                },
                "parameters": [{"url": "ftp://example.com"}],
            }
        )
    )

    result = app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert (
        result.get_message()
        == "Action failure in url reputation: Please provide a valid URL"
    )


@pytest.mark.live
def test_url_reputation_queries_real_wildfire_asset(
    wildfire_app: App,
    wildfire_action_input: Callable[[str, str, list[dict[str, Any]]], dict[str, Any]],
) -> None:
    wildfire_app.handle(
        json.dumps(
            wildfire_action_input(
                "get_url_reputation",
                "url reputation",
                [{"url": "https://www.google.com"}],
            )
        )
    )

    result = wildfire_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    assert result.get_message() == "Success: True"
    assert result.get_summary() == {"success": True}
    data = result.get_data()
    assert len(data) == 1
    assert data[0]["verdict_url"] == "https://www.google.com"
    assert data[0]["verdict_message"] in {
        "benign",
        "malware",
        "grayware",
        "phishing",
        "pending, the sample exists, but there is currently no verdict",
        "error",
        "unknown, cannot find sample record in the WildFire database",
        "invalid hash value",
        "unknown verdict code",
    }
