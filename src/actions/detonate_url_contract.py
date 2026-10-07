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
import itertools
from collections.abc import Iterator

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import (
    ActionOutput,
    OutputField,
    OutputFieldSpecification,
)

from ..asset import Asset
from .detonate_url import (
    DetonateUrlOutput,
    DetonateUrlParams,
    MaecObjectsOutput,
    ReportOutput,
    ResultOutput,
    Submit_Link_InfoOutput,
    detonate_url,
)
from .output_contract import LegacyOutputField, append_legacy_fields


_LEGACY_OUTPUT_FIELDS = (
    LegacyOutputField(
        "result.report.da_packages",
        example_values=("package--37192805-9038-40ee-e0ee-2eb1c05cd94d",),
    ),
    LegacyOutputField(
        "result.report.detection_reasons.*.artifacts.*.object_id", example_values=("1",)
    ),
    LegacyOutputField(
        "result.report.detection_reasons.*.artifacts.*.package",
        example_values=("package--c5e1f03a-f162-4792-ced8-102cd8f6d80a",),
    ),
    LegacyOutputField(
        "result.report.detection_reasons.*.artifacts.*.type",
        example_values=("artifact-ref",),
    ),
    LegacyOutputField(
        "result.report.detection_reasons.*.description",
        example_values=("Previously identified as malicious",),
    ),
    LegacyOutputField(
        "result.report.detection_reasons.*.name",
        example_values=("known_as_malicious_by_historical_reasons",),
    ),
    LegacyOutputField(
        "result.report.detection_reasons.*.type", example_values=("detection-reason",)
    ),
    LegacyOutputField(
        "result.report.detection_reasons.*.verdict", example_values=("malware",)
    ),
    LegacyOutputField(
        "result.report.sa_package",
        example_values=("package--c5e1f03a-f162-4792-ced8-102cd8f6d80a",),
    ),
    LegacyOutputField("result.report.schema_version", example_values=("1.0",)),
    LegacyOutputField("result.report.type", example_values=("wf-report",)),
    LegacyOutputField("result.report.verdict", example_values=("malware",)),
    LegacyOutputField(
        "task_info.report.*.evidence.file.entry.*.#text",
        contains=("file path", "file name"),
        example_values=(
            "C:\\Documents and Settings\\<USER>\\Local Settings\\Temp\\is-DNEQE.tmp\\_isetup\\_shfoldr.dll",
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.evidence.file.entry.*.@behavior_id", example_values=("35",)
    ),
    LegacyOutputField(
        "task_info.report.*.evidence.file.entry.*.@md5",
        contains=("md5",),
        example_values=(
            "92dc6ef532fbb4a5c3201469a5b5eb63",  # pragma: allowlist secret
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.evidence.file.entry.*.@sha1",
        contains=("sha1",),
        example_values=(
            "3e89ff837147c16b4e41c30d6c796374e0b8e62c",  # pragma: allowlist secret
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.evidence.file.entry.*.@sha256",
        contains=("sha256",),
        example_values=(
            "9884e9d1b4f8a873ccbd81f8ad0ae257776d2348d027d811a56475e028360d87",  # pragma: allowlist secret
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.@command",
        contains=("file path", "file name"),
        example_values=(
            '"C:\\DOCUME~1\\ADMINI~1\\LOCALS~1\\Temp\\is-PCLT8.tmp\\sample.tmp" /SL5="$A00B4 541248 56832 c:\\documents and settings\\administrator\\sample.exe"',
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.file.create.*.@md5",
        contains=("md5",),
        example_values=(
            "92dc6ef532fbb4a5c3201469a5b5eb63",  # pragma: allowlist secret
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.file.create.*.@name",
        contains=("file path", "file name"),
        example_values=(
            "C:\\Documents and Settings\\Administrator\\Local Settings\\Temp\\is-DNEQE.tmp\\_isetup\\_shfoldr.dll",
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.file.create.*.@sha1",
        contains=("sha1",),
        example_values=(
            "3e89ff837147c16b4e41c30d6c796374e0b8e62c",  # pragma: allowlist secret
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.file.create.*.@sha256",
        contains=("sha256",),
        example_values=(
            "9884e9d1b4f8a873ccbd81f8ad0ae257776d2348d027d811a56475e028360d87",  # pragma: allowlist secret
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.file.create.*.@size",
        example_values=("23312",),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.file.create.*.@type",
        example_values=("dll",),
    ),
    LegacyOutputField("task_info.report.*.process_list.process.*.java_api"),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.mutex.createmutex.*.@name",
        example_values=("Local\\RstrMgr3887CAB8-533F-4C85-B0DC-3E5639F8D511",),
    ),
    LegacyOutputField("task_info.report.*.process_list.process.*.process_activity"),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.process_activity.Create.@child_pid",
        example_values=("140",),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.process_activity.Create.@child_process_image",
        example_values=(
            '"C:\\DOCUME~1\\ADMINI~1\\LOCALS~1\\Temp\\is-PCLT8.tmp\\sample.tmp" /SL5="$A00B4 541248 56832 c:\\documents and settings\\administrator\\sample.exe"',
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.process_activity.Create.@command",
        example_values=(
            '"C:\\DOCUME~1\\ADMINI~1\\LOCALS~1\\Temp\\is-PCLT8.tmp\\sample.tmp" /SL5="$A00B4 541248 56832 c:\\documents and settings\\administrator\\sample.exe"',
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.registry.create.*.@key",
        example_values=("HKEY_LOCAL_MACHINE",),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.registry.create.*.@subkey",
        example_values=("SOFTWARE\\5da059a482fd494db3f252126fbc3d5b",),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.registry.set.*.@data",
        contains=("file path", "md5"),
        example_values=("1?",),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.registry.set.*.@key",
        example_values=(
            "\\REGISTRY\\MACHINE\\SOFTWARE\\5da059a482fd494db3f252126fbc3egs",  # pragma: allowlist secret
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.registry.set.*.@subkey",
        example_values=("FX",),
    ),
    LegacyOutputField(
        "task_info.report.*.summary.entry.*.@details",
        example_values=(
            "Entropy is a measurement of the randomness in data. Overlays with high entropy indicate encoded or encrypted data.",
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.summary.entry.*.@id", example_values=("3030",)
    ),
    LegacyOutputField(
        "task_info.report.*.summary.entry.*.@score", example_values=("0.0",)
    ),
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
    submit_link_info: Submit_Link_InfoOutput = OutputField(alias="submit-link-info")

    @classmethod
    def _to_json_schema(
        cls,
        parent_datapath: str = "action_result.data.*",
        column_order_counter: itertools.count | None = None,
    ) -> Iterator[OutputFieldSpecification]:
        return append_legacy_fields(
            super()._to_json_schema(parent_datapath, column_order_counter),
            parent_datapath,
            _LEGACY_OUTPUT_FIELDS,
        )


def detonate_url_with_contract(
    params: DetonateUrlParams, soar: SOARClient, asset: Asset
) -> DetonateUrlContractOutput:
    """Publish the stable contract while preserving the raw ActionResult at runtime."""
    return detonate_url(params, soar, asset)  # type: ignore[return-value]
