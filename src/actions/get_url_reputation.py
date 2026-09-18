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
import xmltodict
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset

logger = getLogger()
VERDICT_MESSAGES = {
    0: "benign",
    1: "malware",
    2: "grayware",
    4: "phishing",
    -100: "pending, the sample exists, but there is currently no verdict",
    -101: "error",
    -102: "unknown, cannot find sample record in the WildFire database",
    -103: "invalid hash value",
}
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


class UrlReputationParams(Params):
    url: str = Param(
        description="URL to query. Starts with http:// or https://",
        primary=True,
        cef_types=["url"],
    )


class UrlReputationOutput(ActionOutput):
    verdict_analysis_time: str = OutputField(example_values=["2021-05-16T15:17:49Z"])
    verdict_code: float = OutputField(example_values=[-102])
    verdict_md5: str = OutputField(cef_types=["md5"])
    verdict_message: str = OutputField(
        example_values=["unknown, cannot find sample record in the WildFire database"]
    )
    verdict_sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "14a74b84361079e3c7c927629520d45e836de7b34f23efdcfef4294d010bc03f"
        ],
    )
    verdict_url: str = OutputField(example_values=["https://www.google.com"])
    verdict_valid: str = OutputField(example_values=["Yes"])


class UrlReputationSummary(ActionOutput):
    success: bool = OutputField(example_values=[True])


def _parse_verdict_response(response: httpx.Response) -> dict[str, object]:
    try:
        parsed = xmltodict.parse(response.text)
    except Exception as exc:
        raise ActionFailure(f"Unable to parse reply from device: {exc}") from exc

    wildfire = parsed.get("wildfire")
    if not isinstance(wildfire, dict):
        raise ActionFailure("None 'wildfire' missing in reply from device")

    verdict_info = wildfire.get("get-verdict-info")
    if not isinstance(verdict_info, dict):
        raise ActionFailure("Verdict could not be retrieved")

    try:
        verdict_code = int(verdict_info["verdict"])
        analysis_time = str(verdict_info["analysis_time"])
        verdict_url = str(verdict_info["url"])
        valid = str(verdict_info["valid"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ActionFailure("Verdict could not be retrieved") from exc

    return {
        "verdict_analysis_time": analysis_time,
        "verdict_code": verdict_code,
        "verdict_message": VERDICT_MESSAGES.get(verdict_code, "unknown verdict code"),
        "verdict_url": verdict_url,
        "verdict_valid": valid,
    }


def get_url_reputation(
    params: UrlReputationParams, soar: SOARClient, asset: Asset
) -> UrlReputationOutput:
    """Retrieve the WildFire verdict for a URL."""
    logger.progress("Getting verdict for: %s", params.url)
    verify = asset.verify_server_cert if asset.verify_server_cert is not None else True
    base_url = f"{asset.base_url.rstrip('/')}/publicapi/"
    timeout = httpx.Timeout(None)

    try:
        with httpx.Client(base_url=base_url, verify=verify, timeout=timeout) as client:
            response = client.post(
                "get/verdict",
                data={"apikey": asset.api_key},
                files={"url": ("", params.url)},
            )
    except httpx.HTTPError as exc:
        raise ActionFailure(f"REST Api to server failed: {exc}") from exc

    if response.status_code != httpx.codes.OK:
        detail = response.text.strip() or FILE_UPLOAD_ERRORS.get(
            response.status_code, "N/A"
        )
        raise ActionFailure(
            "REST Api Call returned error, "
            f"status_code: {response.status_code}, detail: {detail}"
        )

    output = UrlReputationOutput.model_validate(_parse_verdict_response(response))
    soar.set_summary(UrlReputationSummary(success=True))
    soar.set_message("Success: True")
    return output
