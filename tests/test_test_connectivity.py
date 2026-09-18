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
from collections.abc import Mapping

import pytest
from soar_sdk.app import App
from soar_sdk.shims.phantom.encryption_helper import encryption_helper


@pytest.mark.live
def test_connectivity_uploads_bundled_probe_to_wildfire(
    wildfire_app: App, wildfire_asset_config: Mapping[str, str | bool]
) -> None:
    asset_id = "wildfire-live-test"
    input_data = {
        "identifier": "test_connectivity",
        "action": "test_connectivity",
        "asset_id": asset_id,
        "container_id": 456,
        "config": {
            "app_version": "4.0.0",
            "directory": ".",
            "main_module": "src.app:app",
            "base_url": wildfire_asset_config["base_url"],
            "verify_server_cert": wildfire_asset_config["verify_server_cert"],
            "api_key": encryption_helper.encrypt(
                wildfire_asset_config["api_key"], salt=asset_id
            ),
        },
        "parameters": [{}],
    }

    wildfire_app.handle(json.dumps(input_data))

    result = wildfire_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
