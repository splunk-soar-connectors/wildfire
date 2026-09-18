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
import os

import pytest
from dotenv import find_dotenv, load_dotenv
from soar_sdk.shims.phantom.encryption_helper import encryption_helper

from src.app import create_wildfire_connector_app


def _required_wildfire_environment() -> tuple[str, str, bool]:
    if not os.getenv("WILDFIRE_BASE_URL") or not os.getenv("WILDFIRE_API_KEY"):
        env_path = find_dotenv(usecwd=True)
        if env_path:
            load_dotenv(env_path, override=False)

    missing = [
        name
        for name in ("WILDFIRE_BASE_URL", "WILDFIRE_API_KEY")
        if not os.getenv(name)
    ]
    if missing:
        pytest.fail(
            "Missing required WildFire live-test environment variables: "
            + ", ".join(missing)
        )

    verify_value = os.getenv("WILDFIRE_VERIFY_SERVER_CERT", "true").strip().lower()
    if verify_value not in {"true", "false"}:
        pytest.fail("WILDFIRE_VERIFY_SERVER_CERT must be 'true' or 'false'")

    return (
        os.environ["WILDFIRE_BASE_URL"],
        os.environ["WILDFIRE_API_KEY"],
        verify_value == "true",
    )


@pytest.mark.live
def test_connectivity_uploads_bundled_probe_to_wildfire() -> None:
    base_url, api_key, verify_server_cert = _required_wildfire_environment()
    asset_id = "wildfire-live-test"
    app = create_wildfire_connector_app()
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
            "verify_server_cert": verify_server_cert,
            "api_key": encryption_helper.encrypt(api_key, salt=asset_id),
        },
        "parameters": [{}],
    }

    app.handle(json.dumps(input_data))

    result = app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
