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

import httpx
import pytest
from soar_sdk.app import App
from soar_sdk.exceptions import ActionFailure

from src.actions.make_request import (
    _json_object,
    _query_parameters,
    _relative_endpoint,
)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://example.com/publicapi/get/report",
        "http://example.com/publicapi/get/report",
        "//example.com/publicapi/get/report",
    ],
)
def test_make_request_rejects_endpoints_that_can_escape_the_asset_host(
    endpoint: str,
) -> None:
    with pytest.raises(ActionFailure, match="Do not include the base URL"):
        _relative_endpoint(endpoint)


@pytest.mark.parametrize("endpoint", ["publicapi/get/report", "/publicapi/get/report"])
def test_make_request_rejects_duplicate_publicapi_prefix(endpoint: str) -> None:
    with pytest.raises(ActionFailure, match="Do not include '/publicapi'"):
        _relative_endpoint(endpoint)


def test_make_request_accepts_relative_endpoint_and_query() -> None:
    assert _relative_endpoint("/get/report?format=xml") == "get/report?format=xml"


@pytest.mark.parametrize(
    "endpoint",
    [
        "../rest/version",
        "get/../../rest/version",
        "./get/report",
        "get/./report",
        "get/..",
        "%2e%2e/rest/version",
        "%2E%2E/rest/version",
        ".%2e/rest/version",
        "%2e./rest/version",
        "%252e%252e/rest/version",
        "%25252e%25252e/rest/version",
        "get%2f..%2f..%2frest/version",
        "get%252f..%252f..%252frest/version",
        "get\\report",
        "%5c..%5crest/version",
        "get%255creport",
    ],
)
def test_make_request_rejects_traversal_and_backslashes(endpoint: str) -> None:
    with pytest.raises(ActionFailure, match="dot path segments or backslashes"):
        _relative_endpoint(endpoint)


@pytest.mark.parametrize(
    "endpoint",
    [
        "get/report?format=xml&format=json",
        "get/report?value=../outside&encoded=%2e%2e%2f",
        "get/report?value=%255c",
        "get/report%20name?value=with%20spaces",
        "get/report.json",
        "get/report..json",
    ],
)
def test_make_request_valid_endpoints_keep_encoding_query_and_publicapi_scope(
    endpoint: str,
) -> None:
    validated = _relative_endpoint(endpoint)
    with httpx.Client(base_url="https://example.invalid/publicapi/") as client:
        request = client.build_request("POST", validated)

    assert validated == endpoint
    assert str(request.url) == f"https://example.invalid/publicapi/{endpoint}"


@pytest.mark.parametrize("value", ["[]", '"value"', "1", "null"])
def test_make_request_requires_json_objects(value: str) -> None:
    with pytest.raises(ActionFailure, match="must be a JSON object"):
        _json_object(value, "body")


def test_make_request_accepts_json_and_raw_query_parameters() -> None:
    assert (
        _query_parameters('{"format": "xml"}', "get/report") == "get/report?format=xml"
    )
    assert _query_parameters("?format=xml", "get/report") == "get/report?format=xml"


@pytest.mark.parametrize("query", ['{"format": "xml"}', "?format=xml"])
def test_make_request_preserves_endpoint_query_and_duplicate_keys(query: str) -> None:
    endpoint = _query_parameters(query, "get/report?hash=sample&format=json")
    with httpx.Client(base_url="https://example.invalid/publicapi/") as client:
        request = client.build_request("POST", endpoint)

    assert request.url.params.multi_items() == [
        ("hash", "sample"),
        ("format", "json"),
        ("format", "xml"),
    ]


def test_make_request_empty_json_query_preserves_endpoint_query() -> None:
    assert _query_parameters("{}", "get/report?hash=sample") == "get/report?hash=sample"


@pytest.mark.live
def test_make_request_queries_real_wildfire_asset(
    wildfire_app: App,
    wildfire_action_input: Callable[[str, str, list[dict[str, object]]], dict],
) -> None:
    probe_path = (
        Path(__file__).parents[1] / "templates" / "wildfire_test_connectivity.pdf"
    )
    probe_sha256 = hashlib.sha256(probe_path.read_bytes()).hexdigest()

    wildfire_app.handle(
        json.dumps(
            wildfire_action_input(
                "make_request",
                "make request",
                [
                    {
                        "http_method": "POST",
                        "endpoint": "get/report",
                        "headers": "",
                        "query_parameters": "",
                        "body": json.dumps({"hash": probe_sha256, "format": "xml"}),
                        "timeout": 30,
                    }
                ],
            )
        )
    )

    result = wildfire_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    assert result.get_data()[0]["status_code"] == 200
    assert "<wildfire>" in result.get_data()[0]["response_body"]
