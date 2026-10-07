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
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from soar_sdk.app import App


@pytest.mark.live
def test_get_report_returns_the_bundled_probe_report(
    wildfire_app: App,
    wildfire_action_input: Callable[[str, str, list[dict[str, Any]]], dict[str, Any]],
) -> None:
    probe_path = (
        Path(__file__).parents[1] / "templates" / "wildfire_test_connectivity.pdf"
    )
    probe_sha256 = hashlib.sha256(probe_path.read_bytes()).hexdigest()

    wildfire_app.handle(
        json.dumps(
            wildfire_action_input("get_report", "get report", [{"id": probe_sha256}])
        )
    )

    result = wildfire_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    assert (
        result.get_message()
        == "Verdict code: 0, Verdict: benign, Summary available: True"
    )
    assert result.get_summary() == {
        "verdict_code": 0,
        "verdict": "benign",
        "summary_available": True,
    }
    assert set(result.get_data()[0]) == {"file_info", "task_info", "version"}


@pytest.mark.live
def test_get_report_preserves_empty_data_row_when_no_report_is_available(
    wildfire_app: App,
    wildfire_action_input: Callable[[str, str, list[dict[str, Any]]], dict[str, Any]],
) -> None:
    wildfire_app.handle(
        json.dumps(
            wildfire_action_input(
                "get_report",
                "get report",
                [{"id": "0" * 64}],
            )
        )
    )

    result = wildfire_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    assert result.get_summary()["summary_available"] is False
    assert result.get_data() == [{}]
