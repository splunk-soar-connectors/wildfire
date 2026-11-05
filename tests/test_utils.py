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
from copy import deepcopy

import httpx
import pytest

from src.utils import (
    WILDFIRE_HTTP_TIMEOUT,
    get_error_detail,
    has_file_report,
    normalize_wildfire_report_response,
    parse_wildfire_xml,
)


@pytest.mark.parametrize(
    "content_type, body, expected",
    [
        (
            "application/xml",
            "<error><error-message>Vendor rejected sample</error-message></error>",
            "Vendor rejected sample",
        ),
        ("text/xml", "<error><error-message/></error>", "API key invalid"),
        ("application/xml", "<error", "API key invalid"),
        ("application/xml", "<response>Unexpected</response>", "API key invalid"),
        (
            "text/html",
            (
                "<html><style>hidden style</style><script>hidden script</script>"
                "<nav>Navigation</nav><body><h1>Access denied</h1>\n<p>Details</p>"
                "<footer>Footer</footer></body></html>"
            ),
            "Access denied",
        ),
        (
            "text/html",
            "<html><script>hidden</script></html>",
            "Cannot parse error details",
        ),
        ("text/plain", " Vendor detail ", "Vendor detail"),
        ("text/plain", "", "API key invalid"),
        ("application/json", '{"error":"denied"}', '{"error":"denied"}'),
    ],
)
def test_error_details_preserve_legacy_extraction_and_fallbacks(
    content_type: str, body: str, expected: str
) -> None:
    response = httpx.Response(401, text=body, headers={"Content-Type": content_type})

    assert get_error_detail(response, {401: "API key invalid"}) == expected


def test_error_detail_without_vendor_message_or_status_mapping() -> None:
    assert get_error_detail(httpx.Response(599)) == "N/A"


@pytest.mark.parametrize(
    "section, ready",
    [
        ("<version>1</version>", False),
        ("<task_info/>", False),
        ("<task_info><status>pending</status></task_info>", False),
        ("<task_info><report/></task_info>", False),
        ("<task_info><report><platform>Windows</platform></report></task_info>", True),
        (
            (
                "<task_info><report><platform>Windows</platform></report>"
                "<report><platform>Android</platform></report></task_info>"
            ),
            True,
        ),
    ],
)
def test_file_report_readiness_from_parsed_xml(section: str, ready: bool) -> None:
    response = httpx.Response(200, text=f"<wildfire>{section}</wildfire>")
    payload = parse_wildfire_xml(response)
    original = deepcopy(payload)

    assert has_file_report(payload) is ready
    assert payload == original


@pytest.mark.parametrize("report", [None, {}, [], ""])
def test_empty_file_reports_are_not_ready(report: object) -> None:
    assert not has_file_report({"task_info": {"report": report}})


def test_wildfire_http_timeout_is_bounded() -> None:
    assert WILDFIRE_HTTP_TIMEOUT.connect == 10.0
    assert WILDFIRE_HTTP_TIMEOUT.read == 60.0
    assert WILDFIRE_HTTP_TIMEOUT.write == 60.0
    assert WILDFIRE_HTTP_TIMEOUT.pool == 10.0


def test_report_response_normalizes_legacy_singleton_collections() -> None:
    response = {
        "task_info": {
            "report": {
                "network": {"TCP": {"@ip": "192.0.2.1"}},
                "timeline": {"entry": {"@seq": "1"}},
                "process_created": {"entry": {"@pid": "7"}},
                "process_tree": {"@pid": "7"},
                "process_list": {
                    "process": {
                        "@pid": "7",
                        "mutex": {"CreateMutex": {"@name": "sample-mutex"}},
                        "registry": {"Set": {"@key": "sample-key"}},
                        "file": {"Create": {"@name": "sample.exe"}},
                        "service": {"Create": {"@name": "sample-service"}},
                    }
                },
                "summary": {"entry": "Observed behavior"},
                "registry": {"SetValueKey": {"@key": "sample-key"}},
                "file": {"Create": {"@name": "sample.exe"}},
            }
        }
    }

    normalized = normalize_wildfire_report_response(response)
    reports = normalized["task_info"]["report"]
    report = reports[0]

    assert isinstance(reports, list)
    assert report["network"]["tcp"] == [{"@ip": "192.0.2.1"}]
    assert report["timeline"]["entry"] == [{"@seq": "1"}]
    assert report["process"]["entry"] == [{"@pid": "7"}]
    assert report["process_tree"] == [{"@pid": "7"}]
    assert report["process_list"]["process"][0]["mutex"]["createmutex"] == [
        {"@name": "sample-mutex"}
    ]
    assert report["summary"]["entry"] == [
        {
            "#text": "Observed behavior",
            "@details": "N/A",
            "@score": "N/A",
            "@id": "N/A",
        }
    ]
    assert report["registry"]["setvaluekey"] == [{"@key": "sample-key"}]
    assert report["file"]["create"] == [{"@name": "sample.exe"}]
