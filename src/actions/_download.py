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
from __future__ import annotations

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure

from ..asset import Asset


def download_to_vault(
    *,
    soar: SOARClient,
    asset: Asset,
    endpoint: str,
    data: dict[str, str | int],
    file_name: str,
    contains: str,
) -> str:
    """Download one WildFire artifact and attach it to the executing vault."""
    verify = asset.verify_server_cert if asset.verify_server_cert is not None else True
    try:
        with httpx.Client(
            base_url=f"{asset.base_url.rstrip('/')}/publicapi/",
            verify=verify,
            timeout=httpx.Timeout(None),
        ) as client:
            response = client.post(endpoint, data={"apikey": asset.api_key, **data})
    except httpx.HTTPError as exc:
        raise ActionFailure(f"REST Api to server failed: {exc}") from exc

    if response.status_code != httpx.codes.OK:
        detail = response.text.strip() or "N/A"
        raise ActionFailure(
            "REST Api Call returned error, "
            f"status_code: {response.status_code}, detail: {detail}"
        )

    try:
        return soar.vault.create_attachment(
            soar.get_executing_container_id(),
            response.content,
            file_name,
            metadata={"contains": contains},
        )
    except Exception as exc:
        raise ActionFailure(
            f"Unable to add downloaded file to the vault: {exc}"
        ) from exc
