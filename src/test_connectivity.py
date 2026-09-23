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
from pathlib import Path

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .asset import Asset
from .utils import parse_wildfire_xml

__test__ = False

logger = getLogger()
TEST_PDF_NAME = "wildfire_test_connectivity.pdf"
TEST_PDF_PATH = Path(__file__).parents[1] / "templates" / TEST_PDF_NAME
FILE_UPLOAD_ERRORS = {
    401: "API key invalid",
    405: "HTTP method Not Allowed",
    413: "Sample file size over max limit",
    418: "Sample file type is not supported",
    419: "Max number of uploads per day exceeded",
    422: "URL download error",
    500: "Internal error",
    513: "File upload failed",
}


def _error_detail(response: httpx.Response) -> str:
    detail = response.text.strip()
    if detail:
        return detail
    return FILE_UPLOAD_ERRORS.get(response.status_code, "N/A")


def run_test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Upload the bundled test PDF to verify WildFire connectivity."""
    del soar

    if not TEST_PDF_PATH.is_file():
        raise ActionFailure(f'Test pdf file not found at "{TEST_PDF_PATH}"')

    logger.progress("Detonating test pdf file for checking connectivity")
    verify = asset.verify_server_cert if asset.verify_server_cert is not None else True
    base_url = f"{asset.base_url.rstrip('/')}/publicapi/"
    timeout = httpx.Timeout(None)

    try:
        with (
            TEST_PDF_PATH.open("rb") as payload,
            httpx.Client(base_url=base_url, verify=verify, timeout=timeout) as client,
        ):
            response = client.post(
                "submit/file",
                data={"apikey": asset.api_key},
                files={"file": (TEST_PDF_NAME, payload)},
            )
    except httpx.HTTPError as exc:
        raise ActionFailure(f"REST Api to server failed: {exc}") from exc
    except OSError as exc:
        raise ActionFailure(
            f'Unable to open test pdf file at "{TEST_PDF_PATH}": {exc}'
        ) from exc

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        detail = _error_detail(response)
        raise ActionFailure(
            "REST Api Call returned error, "
            f"status_code: {response.status_code}, detail: {detail}"
        ) from exc

    parse_wildfire_xml(response)
    logger.progress("Test Connectivity Passed")
