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
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset
from ._download import download_to_vault


class SaveReportParams(Params):
    id: str = Param(
        description="File MD5 or Sha256 to get the results of",
        primary=True,
        cef_types=["md5", "sha256", "wildfire task id"],
    )


class SaveReportOutput(ActionOutput):
    name: str
    vault_id: str = OutputField(cef_types=["vault id"])


class SaveReportSummary(ActionOutput):
    name: str = OutputField(column_name="File Name")
    vault_id: str = OutputField(cef_types=["vault id"], column_name="Vault ID")
    file_type: str


def save_report(
    params: SaveReportParams, soar: SOARClient, asset: Asset
) -> SaveReportOutput:
    name = f"{params.id}.pdf"
    vault_id = download_to_vault(
        soar=soar,
        asset=asset,
        endpoint="get/report",
        data={"hash": params.id, "format": "pdf"},
        file_name=name,
        contains="pdf",
    )
    result = ActionResult(
        True,
        f"Vault id: {vault_id}, Name: {name}, File type: pdf",
        params.model_dump(),
    )
    result.add_data({"name": name, "vault_id": vault_id})
    result.set_summary({"name": name, "vault_id": vault_id, "file_type": "pdf"})
    return result  # type: ignore[return-value]
