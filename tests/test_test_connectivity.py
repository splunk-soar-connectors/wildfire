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
from typing import Any

import pytest
from soar_sdk.app import App

from src.actions.test_connectivity import TEST_PDF_PATH


def test_connectivity_probe_uses_packaged_resource_directory() -> None:
    assert TEST_PDF_PATH.parent.name == "templates"
    assert TEST_PDF_PATH.is_file()
    assert (
        hashlib.sha256(TEST_PDF_PATH.read_bytes()).hexdigest()
        == (
            "504a5350aceed0a0935fe4d670ebbea872cbf1fbd80d5922161bdff39b6f32f8"  # pragma: allowlist secret
        )
    )


@pytest.mark.live
def test_connectivity_uploads_bundled_probe_to_wildfire(
    wildfire_app: App,
    wildfire_action_input: Callable[[str, str, list[dict[str, Any]]], dict[str, Any]],
) -> None:
    wildfire_app.handle(
        json.dumps(
            wildfire_action_input("test_connectivity", "test_connectivity", [{}])
        )
    )

    result = wildfire_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
