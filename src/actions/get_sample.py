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
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset
from ._download import download_to_vault


class GetFileParams(Params):
    hash: str = Param(
        description="Hash of file/sample to download",
        primary=True,
        cef_types=["md5", "sha256", "wildfire task id"],
    )


class GetFileOutput(ActionOutput):
    name: str
    vault_id: str = OutputField(cef_types=["vault id"])


def get_sample(params: GetFileParams, soar: SOARClient, asset: Asset) -> GetFileOutput:
    name = f"{params.hash}.bin"
    vault_id = download_to_vault(
        soar=soar,
        asset=asset,
        endpoint="get/sample",
        data={"hash": params.hash},
        file_name=name,
        contains="file",
    )
    return GetFileOutput(name=name, vault_id=vault_id)
