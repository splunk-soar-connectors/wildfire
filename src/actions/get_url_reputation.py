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


def get_url_reputation(
    params: UrlReputationParams, soar: SOARClient, asset: Asset
) -> UrlReputationOutput:
    raise NotImplementedError()
