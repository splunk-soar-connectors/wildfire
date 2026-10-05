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
from src.utils import WILDFIRE_HTTP_TIMEOUT, normalize_wildfire_report_response


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
