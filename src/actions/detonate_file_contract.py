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
from soar_sdk.action_results import OutputField, OutputFieldSpecification

from ..asset import Asset
from .detonate_file import (
    DetonateFileOutput,
    DetonateFileParams,
    Upload_File_InfoOutput,
    detonate_file,
)
from .output_contract import LegacyOutputField, append_legacy_fields


_LEGACY_OUTPUT_FIELDS = (
    LegacyOutputField("file_info.file_signer", example_values=("None",)),
    LegacyOutputField("file_info.filetype"),
    LegacyOutputField("file_info.malware"),
    LegacyOutputField("file_info.md5", contains=("md5", "hash")),
    LegacyOutputField("file_info.sha1", contains=("sha1", "hash")),
    LegacyOutputField("file_info.sha256", contains=("sha256", "hash")),
    LegacyOutputField("file_info.size"),
    LegacyOutputField(
        "task_info.report.*.elf_info.suspicious.entry.*.@behavior",
        example_values=("elf_sa_matched_ssdeep",),
    ),
    LegacyOutputField(
        "task_info.report.*.elf_info.suspicious.entry.*.@behavior_id",
        example_values=("7094",),
    ),
    LegacyOutputField(
        "task_info.report.*.elf_info.suspicious.entry.*.@description",
        example_values=(
            "Sample was identified to a known malware family via fuzzy hash",
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.elf_info.suspicious.entry.*.@family",
        example_values=("unknown",),
    ),
    LegacyOutputField(
        "task_info.report.*.elf_info.suspicious.entry.*.@matched_ioc_hash"
    ),
    LegacyOutputField("task_info.report.*.evidence"),
    LegacyOutputField("task_info.report.*.evidence.file"),
    LegacyOutputField("task_info.report.*.evidence.file.entry.*.@behavior_id"),
    LegacyOutputField(
        "task_info.report.*.evidence.file.entry.*.@md5", contains=("md5", "hash")
    ),
    LegacyOutputField("task_info.report.*.evidence.file.entry.@behavior_id"),
    LegacyOutputField(
        "task_info.report.*.evidence.file.entry.@md5", contains=("md5", "hash")
    ),
    LegacyOutputField(
        "task_info.report.*.extracted_urls.entry.*.@url",
        example_values=(
            "accounts.google.com/signoutoptions?hl=en-gb&continue=https://www.google.com%3fhl%3den-gb",
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.extracted_urls.entry.*.@verdict",
        example_values=("unknown",),
    ),
    LegacyOutputField(
        "task_info.report.*.extracted_urls.entry.@url",
        example_values=(
            "www.virustotal.com/#/file/0d6c7e4e3c3e22b50283248ed6e9663743720e998a5bfafcaef0b819cc7c8fcf/detection",
        ),
    ),
    LegacyOutputField(
        "task_info.report.*.extracted_urls.entry.@verdict", example_values=("unknown",)
    ),
    LegacyOutputField("task_info.report.*.file.file_deleted.*.@deleted_file"),
    LegacyOutputField("task_info.report.*.file.file_written.*.@written_file"),
    LegacyOutputField("task_info.report.*.process_list.process.*.@command"),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.file.create.*.@md5",
        contains=("md5", "hash"),
    ),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.file.create.*.@name",
        contains=("file path",),
    ),
    LegacyOutputField("task_info.report.*.process_list.process.*.file.create.*.@size"),
    LegacyOutputField("task_info.report.*.process_list.process.*.file.create.*.@type"),
    LegacyOutputField("task_info.report.*.process_list.process.*.java_api"),
    LegacyOutputField(
        "task_info.report.*.process_list.process.*.mutex.createmutex.*.@name"
    ),
    LegacyOutputField("task_info.report.*.process_list.process.*.process_activity"),
    LegacyOutputField("task_info.report.*.process_list.process.*.registry.set.*.@data"),
    LegacyOutputField(
        "task_info.report.*.process_tree.*.process.*.@name", example_values=("sample",)
    ),
    LegacyOutputField(
        "task_info.report.*.process_tree.*.process.*.@text",
        example_values=("%HOME/Downloads/sample",),
    ),
    LegacyOutputField(
        "task_info.report.*.summary.entry.*.@behavior",
        example_values=("elf_sa_em_x86_64",),
    ),
    LegacyOutputField("task_info.report.*.summary.entry.*.@details"),
    LegacyOutputField("task_info.report.*.summary.entry.*.@id"),
    LegacyOutputField("task_info.report.*.summary.entry.*.@score"),
)


class DetonateFileContractOutput(DetonateFileOutput):
    """Publish stable legacy paths while preserving the generated model."""

    upload_file_info: Upload_File_InfoOutput = OutputField(alias="upload-file-info")

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


def detonate_file_with_contract(
    params: DetonateFileParams, soar: SOARClient, asset: Asset
) -> DetonateFileContractOutput:
    """Publish the legacy manifest contract without validating the raw response."""
    return detonate_file(params, soar, asset)  # type: ignore[return-value]
