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

from src.actions.detonate_file import (
    FILE_UPLOAD_ERRORS as DETONATE_FILE_UPLOAD_ERRORS,
)
from src.actions.detonate_file import (
    GET_REPORT_ERRORS as DETONATE_FILE_REPORT_ERRORS,
)
from src.actions.detonate_file import (
    _file_upload_error_detail as detonate_file_upload_error_detail,
)
from src.actions.detonate_file import (
    _report_error_detail as detonate_file_report_error_detail,
)
from src.actions.detonate_url import (
    FILE_UPLOAD_ERRORS as DETONATE_URL_UPLOAD_ERRORS,
)
from src.actions.detonate_url import GET_REPORT_ERRORS as DETONATE_URL_REPORT_ERRORS
from src.actions.detonate_url import (
    _file_upload_error_detail as detonate_url_upload_error_detail,
)
from src.actions.detonate_url import (
    _report_error_detail as detonate_url_report_error_detail,
)


LEGACY_FILE_UPLOAD_ERRORS = {
    401: "API key invalid",
    405: "HTTP method Not Allowed",
    413: "Sample file size over max limit",
    418: "Sample file type is not supported",
    419: "Max number of uploads per day exceeded",
    422: "URL download error",
    500: "Internal error",
    513: "File upload failed",
}
LEGACY_GET_REPORT_ERRORS = {
    401: "API key invalid",
    404: "The report was not found",
    405: "HTTP method Not Allowed",
    419: "Request report quota exceeded",
    420: "Insufficient arguments",
    421: "Invalid arguments",
    500: "Internal error",
}


def test_detonation_actions_preserve_legacy_error_maps() -> None:
    assert DETONATE_FILE_UPLOAD_ERRORS == LEGACY_FILE_UPLOAD_ERRORS
    assert DETONATE_URL_UPLOAD_ERRORS == LEGACY_FILE_UPLOAD_ERRORS
    assert DETONATE_FILE_REPORT_ERRORS == LEGACY_GET_REPORT_ERRORS
    assert DETONATE_URL_REPORT_ERRORS == LEGACY_GET_REPORT_ERRORS


def test_detonation_actions_use_legacy_empty_body_fallbacks() -> None:
    upload_response = httpx.Response(418)
    report_response = httpx.Response(404)

    assert detonate_file_upload_error_detail(upload_response) == (
        "Sample file type is not supported"
    )
    assert detonate_url_upload_error_detail(upload_response) == (
        "Sample file type is not supported"
    )
    assert detonate_file_report_error_detail(report_response) == (
        "The report was not found"
    )
    assert detonate_url_report_error_detail(report_response) == (
        "The report was not found"
    )


def test_detonation_actions_prefer_vendor_error_details() -> None:
    response = httpx.Response(500, text="vendor detail")

    assert detonate_file_upload_error_detail(response) == "vendor detail"
    assert detonate_file_report_error_detail(response) == "vendor detail"
    assert detonate_url_upload_error_detail(response) == "vendor detail"
    assert detonate_url_report_error_detail(response) == "vendor detail"
