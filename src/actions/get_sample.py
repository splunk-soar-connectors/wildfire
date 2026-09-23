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
from soar_sdk.abstract import SOARClient
import httpx
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset


class GetFileParams(Params):
    hash: str = Param(
        description="Hash of file/sample to download",
        primary=True,
        cef_types=["md5", "sha256", "wildfire task id"],
    )


class GetFileOutput(ActionOutput):
    name: str
    vault_id: str = OutputField(cef_types=["vault id"])


class GetFileSummary(ActionOutput):
    name: str = OutputField(column_name="File Name")
    hash: str = OutputField(column_name="Hash")
    file_type: str = OutputField(column_name="File Type")
    vault_id: str = OutputField(cef_types=["vault id"], column_name="Vault ID")


def _classify_sample(content: bytes) -> tuple[str, str]:
    signatures = (
        ((b"MZ",), ".exe", "pe file"),
        ((b"%PDF-",), ".pdf", "pdf"),
        ((b"MDMP",), ".dmp", "process dump"),
        ((b"FWS", b"CWS", b"ZWS"), ".flv", "flash"),
        (
            (
                b"\xd4\xc3\xb2\xa1",
                b"\xa1\xb2\xc3\xd4",
                b"\x4d\x3c\xb2\xa1",
                b"\xa1\xb2\x3c\x4d",
            ),
            ".pcap",
            "pcap",
        ),
    )
    for prefixes, extension, file_type in signatures:
        if content.startswith(prefixes):
            return extension, file_type
    return "", ""


def get_sample(params: GetFileParams, soar: SOARClient, asset: Asset) -> GetFileOutput:
    verify = asset.verify_server_cert if asset.verify_server_cert is not None else True
    try:
        response = httpx.post(
            f"{asset.base_url.rstrip('/')}/publicapi/get/sample",
            data={"apikey": asset.api_key, "hash": params.hash},
            verify=verify,
            timeout=httpx.Timeout(None),
        )
    except httpx.HTTPError as exc:
        raise ActionFailure(f"REST Api to server failed: {exc}") from exc

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        detail = response.text.strip() or "N/A"
        raise ActionFailure(
            "REST Api Call returned error, "
            f"status_code: {response.status_code}, detail: {detail}"
        ) from exc

    extension, file_type = _classify_sample(response.content)
    name = f"{params.hash}{extension}"
    try:
        vault_id = soar.vault.create_attachment(
            soar.get_executing_container_id(),
            response.content,
            name,
            metadata={"contains": [file_type] if file_type else []},  # type: ignore[dict-item]
        )
    except Exception as exc:
        raise ActionFailure(
            f"Unable to add downloaded file to the vault: {exc}"
        ) from exc

    result = ActionResult(
        True,
        f"Vault id: {vault_id}, Name: {name}, File type: {file_type}",
        params.model_dump(),
    )
    result.add_data({"name": name, "vault_id": vault_id})
    result.set_summary(
        {
            "name": name,
            "hash": params.hash,
            "file_type": file_type,
            "vault_id": vault_id,
        }
    )
    return result  # type: ignore[return-value]
