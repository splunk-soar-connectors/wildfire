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
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..utils import add_bytes_to_vault

PLATFORM_IDS = {
    "Default": None,
    "Windows XP, Adobe Reader 9.3.3, Office 2003": 1,
    "Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007": 2,
    "Windows XP, Adobe Reader 11, Flash 11, Office 2010": 3,
    "Windows 7 32-bit, Adobe Reader 11, Flash11, Office 2010": 4,
    "Windows 7 64-bit, Adobe Reader 11, Flash 11, Office 2010": 5,
    "Android 2.3, API 10, avd2.3.1": 201,
    "PDF Static Analyzer": 100,
    "DOC/CDF Static Analyzer": 101,
    "Java/Jar Static Analyzer": 102,
    "Office 2007 Open XML Static Analyzer": 103,
    "Adobe Flash Static Analyzer": 104,
    "PE Static Analyzer": 204,
    "Archives (RAR and 7-Zip files)": 800,
    "Windows XP, Internet Explorer 8, Flash 11": 6,
    "Windows 7, Flash 11, Office 2010": 21,
    "Mac OSX Mountain Lion": 50,
    "Windows 10 64-bit, Adobe Reader 11, Flash 22, Office 2010": 66,
    "RTF Static Analyzer": 105,
    "Max OSX Static Analyzer": 110,
    "APK Static Analyzer": 200,
    "Android 4.1, API 16, avd4.1.1 X86": 202,
    "Android 4.1, API 16, avd4.1.1 ARM": 203,
    "Phishing Static Analyzer": 205,
    "Android 4.3, API 18, avd4.3 ARM": 206,
    "Script Static Analyzer": 207,
    "Windows XP, Internet Explorer 8, Flash 13.0.0.281, Flash 16.0.0.305, Elink Analyzer": 300,
    "Windows 7, Internet Explorer 9, Flash 13.0.0.281, Flash 17.0.0.169, Elink Analyzer": 301,
    "Windows 7, Internet Explorer 10, Flash 16.0.0.305, Flash 17.0.0.169, Elink Analyzer": 302,
    "Windows 7, Internet Explorer 11, Flash 16.0.0.305, Flash 17.0.0.169, Elink Analyzer": 303,
    "Linux (ELF Files)": 400,
    "Linux Script Dynamic Analyzer": 403,
    "Linux Script Static Analyzer": 404,
    "BareMetal Windows 7 x64, Adobe Reader 11, Flash 11, Office 2010": 501,
}


class GetPcapParams(Params):
    hash: str = Param(
        description="Hash of file/sample to download pcap of",
        primary=True,
        cef_types=["md5", "sha256", "wildfire task id"],
    )
    platform: str = Param(
        description="Platform of file/sample to download pcap of",
        value_list=[
            "Default",
            "Windows XP, Adobe Reader 9.3.3, Office 2003",
            "Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007",
            "Windows XP, Adobe Reader 11, Flash 11, Office 2010",
            "Windows 7 32-bit, Adobe Reader 11, Flash11, Office 2010",
            "Windows 7 64-bit, Adobe Reader 11, Flash 11, Office 2010",
            "Android 2.3, API 10, avd2.3.1",
            "PDF Static Analyzer",
            "DOC/CDF Static Analyzer",
            "Java/Jar Static Analyzer",
            "Office 2007 Open XML Static Analyzer",
            "Adobe Flash Static Analyzer",
            "PE Static Analyzer",
            "Archives (RAR and 7-Zip files)",
            "Windows XP, Internet Explorer 8, Flash 11",
            "Windows 7, Flash 11, Office 2010",
            "Mac OSX Mountain Lion",
            "Windows 10 64-bit, Adobe Reader 11, Flash 22, Office 2010",
            "RTF Static Analyzer",
            "Max OSX Static Analyzer",
            "APK Static Analyzer",
            "Android 4.1, API 16, avd4.1.1 X86",
            "Android 4.1, API 16, avd4.1.1 ARM",
            "Phishing Static Analyzer",
            "Android 4.3, API 18, avd4.3 ARM",
            "Script Static Analyzer",
            "Windows XP, Internet Explorer 8, Flash 13.0.0.281, Flash 16.0.0.305, Elink Analyzer",
            "Windows 7, Internet Explorer 9, Flash 13.0.0.281, Flash 17.0.0.169, Elink Analyzer",
            "Windows 7, Internet Explorer 10, Flash 16.0.0.305, Flash 17.0.0.169, Elink Analyzer",
            "Windows 7, Internet Explorer 11, Flash 16.0.0.305, Flash 17.0.0.169, Elink Analyzer",
            "Linux (ELF Files)",
            "Linux Script Dynamic Analyzer",
            "Linux Script Static Analyzer",
            "BareMetal Windows 7 x64, Adobe Reader 11, Flash 11, Office 2010",
        ],
    )


class GetPcapOutput(ActionOutput):
    name: str
    vault_id: str = OutputField(cef_types=["vault id"])


class GetPcapSummary(ActionOutput):
    name: str = OutputField(column_name="File Name")
    vault_id: str = OutputField(cef_types=["vault id"], column_name="Vault ID")
    file_type: str = OutputField(column_name="File Type")


def _platform_attempts(platform_id: int | None) -> tuple[int | None, ...]:
    if platform_id == 2:
        return 2, 60, 20
    if platform_id == 5:
        return 5, 61
    return (platform_id,)


def _download_pcap(asset: Asset, sample_hash: str, platform_id: int | None) -> bytes:
    verify = asset.verify_server_cert if asset.verify_server_cert is not None else True
    last_error: ActionFailure | None = None

    for candidate_id in _platform_attempts(platform_id):
        data: dict[str, str | int] = {
            "apikey": asset.api_key,
            "hash": sample_hash,
        }
        if candidate_id is not None:
            data["platform"] = candidate_id

        try:
            response = httpx.post(
                f"{asset.base_url.rstrip('/')}/publicapi/get/pcap",
                data=data,
                verify=verify,
                timeout=httpx.Timeout(None),
            )
        except httpx.HTTPError as exc:
            last_error = ActionFailure(f"REST Api to server failed: {exc}")
            continue

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError:
            detail = response.text.strip() or "N/A"
            last_error = ActionFailure(
                "REST Api Call returned error, "
                f"status_code: {response.status_code}, detail: {detail}"
            )
            continue
        return response.content

    if last_error is not None:
        raise last_error
    raise ActionFailure("Unable to download pcap from WildFire")


def get_pcap(params: GetPcapParams, soar: SOARClient, asset: Asset) -> GetPcapOutput:
    if params.platform not in PLATFORM_IDS:
        raise ValueError("Please provide valid platform name")
    platform_id = PLATFORM_IDS[params.platform]
    name = f"{params.hash}.pcap"
    content = _download_pcap(asset, params.hash, platform_id)
    vault_id = add_bytes_to_vault(soar, content, name, contains=["pcap"])
    result = ActionResult(
        True,
        f"Vault id: {vault_id}, Name: {name}, File type: pcap",
        params.model_dump(),
    )
    result.add_data({"name": name, "vault_id": vault_id})
    result.set_summary({"name": name, "vault_id": vault_id, "file_type": "pcap"})
    return result  # type: ignore[return-value]
