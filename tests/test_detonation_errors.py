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
from src.actions.detonate_file import (
    FILE_UPLOAD_ERRORS as DETONATE_FILE_UPLOAD_ERRORS,
)
from src.actions.detonate_file import (
    GET_REPORT_ERRORS as DETONATE_FILE_REPORT_ERRORS,
)
from src.actions.detonate_url import (
    FILE_UPLOAD_ERRORS as DETONATE_URL_UPLOAD_ERRORS,
)
from src.actions.detonate_url import GET_REPORT_ERRORS as DETONATE_URL_REPORT_ERRORS
from src.actions.detonate_url import VERDICT_MESSAGES as DETONATE_URL_VERDICTS
from src.actions.get_report import GET_REPORT_ERRORS as GET_REPORT_ERRORS_USED
from src.actions.get_report import VERDICT_MESSAGES as GET_REPORT_VERDICTS
from src.actions.get_url_reputation import (
    FILE_UPLOAD_ERRORS as URL_REPUTATION_UPLOAD_ERRORS,
)
from src.actions.get_url_reputation import VERDICT_MESSAGES as URL_REPUTATION_VERDICTS
from src.test_connectivity import FILE_UPLOAD_ERRORS as CONNECTIVITY_UPLOAD_ERRORS
from src.utils import FILE_UPLOAD_ERRORS, GET_REPORT_ERRORS, VERDICT_MESSAGES


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


def test_actions_share_error_and_verdict_mappings() -> None:
    assert DETONATE_FILE_UPLOAD_ERRORS is FILE_UPLOAD_ERRORS
    assert DETONATE_URL_UPLOAD_ERRORS is FILE_UPLOAD_ERRORS
    assert URL_REPUTATION_UPLOAD_ERRORS is FILE_UPLOAD_ERRORS
    assert CONNECTIVITY_UPLOAD_ERRORS is FILE_UPLOAD_ERRORS
    assert DETONATE_FILE_REPORT_ERRORS is GET_REPORT_ERRORS
    assert DETONATE_URL_REPORT_ERRORS is GET_REPORT_ERRORS
    assert GET_REPORT_ERRORS_USED is GET_REPORT_ERRORS
    assert DETONATE_URL_VERDICTS is VERDICT_MESSAGES
    assert GET_REPORT_VERDICTS is VERDICT_MESSAGES
    assert URL_REPUTATION_VERDICTS is VERDICT_MESSAGES
