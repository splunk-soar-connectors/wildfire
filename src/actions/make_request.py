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
from typing import Any
from urllib.parse import urlsplit

import httpx
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams, Param

from ..asset import Asset
from ..utils import WILDFIRE_HTTP_TIMEOUT


class WildFireMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            "WildFire public API endpoint appended to the asset base URL, such as "
            "'get/report'. Do not include the base URL or '/publicapi'."
        ),
        required=True,
    )
    body: str = Param(
        description=(
            "Request form fields as a JSON object. The configured WildFire API key "
            "is added automatically. File uploads are not supported."
        ),
        required=False,
    )


def _relative_endpoint(endpoint: str) -> str:
    endpoint = endpoint.strip()
    if not endpoint:
        raise ActionFailure("The endpoint parameter is required")

    parsed = urlsplit(endpoint)
    if parsed.scheme or parsed.netloc or endpoint.startswith("//"):
        raise ActionFailure(
            "Do not include the base URL in the endpoint; provide only a WildFire "
            "public API path such as 'get/report'"
        )
    if parsed.fragment:
        raise ActionFailure("The endpoint must not include a URL fragment")

    path = parsed.path.lstrip("/")
    if path == "publicapi" or path.startswith("publicapi/"):
        raise ActionFailure(
            "Do not include '/publicapi' in the endpoint; it is added automatically"
        )
    if not path:
        raise ActionFailure("The endpoint parameter is required")

    return path + (f"?{parsed.query}" if parsed.query else "")


def _json_object(value: str, parameter_name: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ActionFailure(f"Invalid JSON in the {parameter_name} parameter") from exc
    if not isinstance(parsed, dict):
        raise ActionFailure(f"The {parameter_name} parameter must be a JSON object")
    return parsed


def _query_parameters(value: str, endpoint: str) -> str:
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        query_string = value.split("#", 1)[0].lstrip("?")
    else:
        if not isinstance(parsed, dict):
            raise ActionFailure(
                "The query_parameters parameter must be a JSON object or query string"
            )
        query_string = str(httpx.QueryParams(parsed))
    if not query_string:
        return endpoint
    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{query_string}"


def make_request(params: WildFireMakeRequestParams, asset: Asset) -> MakeRequestOutput:
    """Make an authenticated request to a WildFire public API endpoint."""
    endpoint = _relative_endpoint(params.endpoint)
    headers = _json_object(params.headers, "headers") if params.headers else {}
    body = _json_object(params.body, "body") if params.body else {}
    body["apikey"] = asset.api_key

    if params.query_parameters:
        endpoint = _query_parameters(params.query_parameters, endpoint)

    timeout: httpx.Timeout | int = WILDFIRE_HTTP_TIMEOUT
    if params.timeout is not None:
        if params.timeout <= 0:
            raise ActionFailure("The timeout parameter must be greater than zero")
        timeout = params.timeout

    base_url = f"{asset.base_url.rstrip('/')}/publicapi/"
    try:
        with httpx.Client(
            base_url=base_url,
            verify=params.verify_ssl,
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            response = client.request(
                params.http_method,
                endpoint,
                headers=headers,
                data=body,
            )
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text.strip() or "N/A"
        raise ActionFailure(
            "REST Api Call returned error, "
            f"status_code: {exc.response.status_code}, detail: {detail}"
        ) from exc
    except httpx.HTTPError as exc:
        raise ActionFailure(f"REST Api to server failed: {exc}") from exc

    return MakeRequestOutput(
        status_code=response.status_code,
        response_body=response.text,
    )
