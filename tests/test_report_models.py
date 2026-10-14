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
from importlib import import_module
import json
from pathlib import Path
from typing import Any, get_args, get_type_hints

import pytest
from soar_sdk.action_results import PermissiveActionOutput
from soar_sdk.app import App

from src.actions.detonate_file import DetonateFileOutput
from src.actions.detonate_url import DetonateUrlOutput
from src.actions.get_report import GetReportOutput
from src.app import create_wildfire_connector_app


@pytest.mark.parametrize(
    ("action_name", "output_name"),
    [
        ("get_report", "GetReportOutput"),
        ("detonate_file", "DetonateFileOutput"),
        ("detonate_url", "DetonateUrlOutput"),
    ],
)
def test_native_common_file_information_matches_legacy_contract(
    action_name: str, output_name: str
) -> None:
    module = import_module(f"src.actions.{action_name}")
    output = getattr(module, output_name)
    fields = {field["data_path"]: field for field in output._to_json_schema()}
    prefix = "action_result.data.*.file_info."
    fixture = json.loads(
        (
            Path(__file__).parent / "fixtures" / "legacy_stable_output_contract.json"
        ).read_text()
    )
    legacy_fields = {
        field["data_path"]: field
        for field in fixture["actions"][action_name]
        if field["data_path"].startswith(prefix)
    }
    assert {path for path in fields if path.startswith(prefix)} == set(legacy_fields)
    for path, legacy_field in legacy_fields.items():
        assert fields[path]["data_type"] == legacy_field["data_type"]
        assert set(fields[path].get("contains", [])) == set(
            legacy_field.get("contains", [])
        )

    if action_name != "detonate_url":
        common_annotation = output.model_fields["file_info"].annotation
        common_types = get_args(common_annotation) or (common_annotation,)
        assert module.CommonFileInfoOutput in common_types

        apk_annotation = module.ReportOutput.model_fields["file_info"].annotation
        apk_types = get_args(apk_annotation) or (apk_annotation,)
        assert module.ApkFileInfoOutput in apk_types
        assert f"{prefix}APK_Package_Name" not in fields
        assert (
            "action_result.data.*.task_info.report.*.file_info.APK_Package_Name"
            in fields
        )


@pytest.mark.parametrize("action_name", ["get_report", "detonate_file"])
def test_common_and_apk_information_remain_at_original_runtime_paths(
    action_name: str,
) -> None:
    module = import_module(f"src.actions.{action_name}")
    output_class = (
        module.GetReportOutput
        if action_name == "get_report"
        else module.DetonateFileOutput
    )
    data = {
        "file_info": {
            "sha256": "sample-hash",
            "filetype": "APK",
            "size": "42",
            "malware": "yes",
            "vendor_extension": None,
        },
        "task_info": {
            "report": [
                {
                    "file_info": {
                        "APK_Package_Name": "com.example.app",
                        "APK_Version": "1.0",
                        "future_field": False,
                    }
                }
            ]
        },
        "version": "2.0",
    }
    assert output_class(**data).model_dump(by_alias=True) == data


@pytest.mark.parametrize(
    ("action_name", "output_name", "summary_fields", "extracted_entry"),
    [
        ("get_report", "GetReportOutput", ["details", "id", "score"], "entry.*"),
        (
            "detonate_file",
            "DetonateFileOutput",
            ["behavior", "details", "id", "score"],
            "entry.*",
        ),
        ("detonate_url", "DetonateUrlOutput", ["details", "id", "score"], None),
    ],
)
def test_native_report_models_declare_distinct_entry_contracts(
    action_name, output_name, summary_fields, extracted_entry
) -> None:
    module = import_module(f"src.actions.{action_name}")
    output = getattr(module, output_name)
    assert issubclass(output, PermissiveActionOutput)
    assert get_type_hints(getattr(module, action_name))["return"] is output
    fields = {field["data_path"]: field for field in output._to_json_schema()}
    prefix = "action_result.data.*.task_info.report.*."
    for name in summary_fields:
        assert fields[f"{prefix}summary.entry.*.@{name}"]["data_type"] == "string"
    assert f"{prefix}summary.entry.*.@seq" not in fields
    assert f"{prefix}timeline.entry.*.@seq" in fields
    if action_name == "detonate_url":
        assert fields[f"{prefix}summary.entry.*.#text"]["data_type"] == "string"

    if extracted_entry:
        for name in ("url", "verdict"):
            assert (
                fields[f"{prefix}extracted_urls.{extracted_entry}.@{name}"]["data_type"]
                == "string"
            )
        assert f"{prefix}extracted_urls.{extracted_entry}.@seq" not in fields

    if action_name == "detonate_file":
        for name in (
            "behavior",
            "behavior_id",
            "description",
            "family",
            "matched_ioc_hash",
        ):
            assert (
                fields[f"{prefix}elf_info.suspicious.entry.*.@{name}"]["data_type"]
                == "string"
            )
        assert f"{prefix}elf_info.suspicious.entry.*.@seq" not in fields


@pytest.mark.parametrize(
    ("output_class", "field_name", "alias"),
    [
        (DetonateFileOutput, "upload_file_info", "upload-file-info"),
        (DetonateUrlOutput, "submit_link_info", "submit-link-info"),
    ],
)
def test_submission_aliases_are_declared_on_native_output_model(
    output_class, field_name, alias
) -> None:
    assert output_class.model_fields[field_name].alias == alias
    paths = {field["data_path"] for field in output_class._to_json_schema()}
    for name in ("md5", "sha256", "url"):
        assert f"action_result.data.*.{alias}.{name}" in paths
        assert f"action_result.data.*.{field_name}.{name}" not in paths


@pytest.mark.parametrize("output_class", [DetonateFileOutput, DetonateUrlOutput])
@pytest.mark.parametrize(
    "data",
    [
        {},
        {"upload-file-info": {"sha256": "sample-hash", "md5": "sample-md5"}},
        {
            "submit-link-info": {"url": "https://example.test"},
            "result": {
                "report": {
                    "maec_packages": [
                        {"observable_objects": {"007": {"values": [False, 0, None]}}}
                    ]
                }
            },
        },
    ],
)
def test_named_detonation_outputs_preserve_full_raw_payload(
    output_class, data: dict[str, Any]
) -> None:
    output = output_class(**data)
    assert output.model_dump(by_alias=True) == data
    app = create_wildfire_connector_app()
    assert App._adapt_action_result(output, app.actions_manager)
    assert app.actions_manager.get_results()[-1].get_data() == [data]


@pytest.mark.parametrize(
    ("output_class", "data"),
    [
        (
            DetonateFileOutput,
            {
                "task_info": {
                    "report": [
                        {
                            "evidence": "legacy scalar evidence",
                            "extracted_urls": {
                                "entry": {
                                    "@url": "https://example.test",
                                    "@verdict": "unknown",
                                }
                            },
                            "process_tree": {
                                "process": [{"@name": "sample", "@text": "/tmp/sample"}]
                            },
                        }
                    ]
                }
            },
        ),
        (
            DetonateUrlOutput,
            {
                "task_info": {
                    "report": [
                        {
                            "process_list": {
                                "process": [
                                    {"process_activity": "legacy scalar activity"}
                                ]
                            }
                        }
                    ]
                }
            },
        ),
        (
            GetReportOutput,
            {
                "task_info": {
                    "report": [
                        {
                            "evidence": {"file": "legacy scalar file evidence"},
                            "process_tree": {
                                "process": [{"@name": "sample", "@text": "/tmp/sample"}]
                            },
                        }
                    ]
                }
            },
        ),
    ],
)
def test_permissive_outputs_preserve_unrepresentable_legacy_shapes(
    output_class, data: dict[str, Any]
) -> None:
    assert output_class(**data).model_dump(by_alias=True) == data


@pytest.mark.parametrize(
    "output_class",
    [DetonateFileOutput, DetonateUrlOutput, GetReportOutput],
)
def test_dynamic_report_outputs_preserve_explicit_null_sections(output_class) -> None:
    data = {
        "task_info": {
            "report": [
                {
                    "evidence": None,
                    "file": None,
                    "metadata": None,
                    "network": None,
                    "process_list": None,
                    "process_tree": None,
                    "summary": None,
                    "timeline": None,
                }
            ]
        }
    }

    assert output_class(**data).model_dump(by_alias=True) == data


@pytest.mark.parametrize("output_class", [DetonateFileOutput, GetReportOutput])
def test_xml_report_outputs_preserve_plural_process_tree_nodes(output_class) -> None:
    data = {
        "task_info": {
            "report": [
                {
                    "process_tree": [
                        {
                            "process": [
                                {"@name": "parent", "@text": "/tmp/parent"},
                                {"@name": "child", "@text": "/tmp/child"},
                            ]
                        }
                    ]
                }
            ]
        }
    }

    assert output_class(**data).model_dump(by_alias=True) == data
