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

from src.utils import is_valid_http_url


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://example.com/path?query=value#fragment",
        "https://192.0.2.1:8443/path",
    ],
)
def test_http_url_validation_accepts_wildfire_urls(url: str) -> None:
    assert is_valid_http_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://",
        "ftp://example.com",
        "https://user:password@example.com",  # pragma: allowlist secret
        "https://example.com/path with spaces",
        "https://example.com/\ncontrol",
        "https://example.com:invalid-port",
    ],
)
def test_http_url_validation_rejects_malformed_urls(url: str) -> None:
    assert not is_valid_http_url(url)


@pytest.mark.live
def test_detonate_url_queries_real_wildfire_asset(
    wildfire_app: App,
    wildfire_action_input: Callable[[str, str, list[dict[str, Any]]], dict[str, Any]],
) -> None:
    wildfire_app.handle(
        json.dumps(
            wildfire_action_input(
                "detonate_url",
                "detonate url",
                [{"url": "https://example.com", "is_file": False}],
            )
        )
    )

    result = wildfire_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    summary = result.get_summary()
    assert set(summary) == {"verdict_code", "verdict", "summary_available"}
    assert summary["summary_available"] is (summary["verdict_code"] >= 0)
    assert result.get_message() == (
        f"Verdict code: {summary['verdict_code']}, Verdict: {summary['verdict']}, "
        f"Summary available: {summary['summary_available']}"
    )
    assert len(result.get_data()) == 1
    if summary["summary_available"]:
        report = result.get_data()[0]["result"]["report"]
        maec_packages = report["maec_packages"]
        assert maec_packages
        assert "observable_objects" in maec_packages[0]
        assert all(key.isdigit() for key in maec_packages[0]["observable_objects"])
