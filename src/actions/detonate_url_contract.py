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

from ..asset import Asset
from .detonate_url import (
    DetonateUrlOutput,
    DetonateUrlParams,
    MaecObjectsOutput,
    ReportOutput,
    ResultOutput,
    detonate_url,
)


class StableMaecPackageOutput(ActionOutput):
    """Stable MAEC package fields published by the detonate URL action."""

    id: str = OutputField(
        example_values=["package--639659c2-6125-4089-8d17-e947f570893a"]
    )
    maec_objects: list[MaecObjectsOutput]
    schema_version: str = OutputField(example_values=["5.0"])
    type: str = OutputField(example_values=["package"])


class StableReportOutput(ReportOutput):
    """Generated report fields plus stable MAEC package metadata."""

    maec_packages: list[StableMaecPackageOutput]


class StableResultOutput(ResultOutput):
    """Detonate URL result with the stable report contract."""

    report: StableReportOutput


class DetonateUrlContractOutput(DetonateUrlOutput):
    """Manifest-only output contract for detonate URL."""

    result: StableResultOutput


def detonate_url_with_contract(
    params: DetonateUrlParams, soar: SOARClient, asset: Asset
) -> DetonateUrlContractOutput:
    """Publish the stable contract while preserving the raw ActionResult at runtime."""
    return detonate_url(params, soar, asset)  # type: ignore[return-value]
