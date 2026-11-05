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
import httpx
import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions.get_pcap import _error_detail, _get_platform_id, _platform_attempts


def test_platform_attempts_preserve_legacy_windows_xp_fallbacks() -> None:
    assert _platform_attempts(2) == (2, 60, 20)


def test_platform_attempts_preserve_legacy_windows_7_fallback() -> None:
    assert _platform_attempts(5) == (5, 61)


def test_platform_attempts_leave_other_platforms_unchanged() -> None:
    assert _platform_attempts(66) == (66,)
    assert _platform_attempts(None) == (None,)


def test_invalid_platform_raises_actionable_failure() -> None:
    with pytest.raises(ActionFailure, match="Please provide valid platform name"):
        _get_platform_id("Unsupported platform")


def test_get_pcap_error_detail_restores_legacy_status_message() -> None:
    assert _error_detail(httpx.Response(404)) == "The pcap was not found"


def test_get_pcap_error_detail_prefers_response_body() -> None:
    assert _error_detail(httpx.Response(404, text="Vendor detail")) == "Vendor detail"
