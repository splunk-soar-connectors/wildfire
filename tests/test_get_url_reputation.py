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
