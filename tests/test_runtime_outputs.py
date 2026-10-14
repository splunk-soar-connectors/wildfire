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
from typing import get_type_hints

import pytest
from pydantic import ValidationError
from soar_sdk.action_results import ActionOutput, ActionResult, PermissiveActionOutput
from soar_sdk.app import App

from src.actions.detonate_file import (
    DetonateFileOutput,
    DetonateFileParams,
    detonate_file,
)
from src.actions.get_pcap import GetPcapOutput, GetPcapParams, GetPcapSummary, get_pcap
from src.actions.get_sample import (
    GetFileOutput,
    GetFileParams,
    GetFileSummary,
    get_sample,
)
from src.actions.save_report import (
    SaveReportOutput,
    SaveReportParams,
    SaveReportSummary,
    save_report,
)
from src.app import create_wildfire_connector_app


@pytest.mark.parametrize(
    ("identifier", "handler", "output_class", "params", "summary"),
    [
        (
            "get_sample",
            get_sample,
            GetFileOutput,
            GetFileParams(hash="sample-hash"),
            GetFileSummary(
                name="sample-hash",
                hash="sample-hash",
                file_type="",
                vault_id="vault-id",
            ),
        ),
        (
            "get_pcap",
            get_pcap,
            GetPcapOutput,
            GetPcapParams(hash="sample-hash", platform="Default"),
            GetPcapSummary(
                name="sample-hash.pcap", file_type="pcap", vault_id="vault-id"
            ),
        ),
        (
            "save_report",
            save_report,
            SaveReportOutput,
            SaveReportParams(id="sample-hash"),
            SaveReportSummary(
                name="sample-hash.pdf", file_type="pdf", vault_id="vault-id"
            ),
        ),
    ],
)
def test_fixed_outputs_preserve_sdk_result_envelope(
    identifier, handler, output_class, params, summary
) -> None:
    app = create_wildfire_connector_app()
    action = app.actions_manager.get_action(identifier)
    assert action.meta.output is output_class
    assert get_type_hints(handler)["return"] is output_class

    data = {"name": summary.name, "vault_id": summary.vault_id}
    message = f"Vault id: {summary.vault_id}, Name: {summary.name}, File type: {summary.file_type}"
    legacy = ActionResult(True, message, params.model_dump())
    legacy.add_data(data)
    legacy.set_summary(summary.model_dump())

    assert App._adapt_action_result(
        output_class(**data), app.actions_manager, params, message, summary
    )
    result = app.actions_manager.get_results()[-1]
    assert result.get_status() == legacy.get_status()
    assert result.get_message() == legacy.get_message()
    assert result.get_param() == legacy.get_param()
    assert result.get_summary() == legacy.get_summary()
    assert result.get_data() == legacy.get_data()

    with pytest.raises(ValidationError):
        output_class(vault_id=summary.vault_id)
    with pytest.raises(ValidationError):
        output_class(name=summary.name, vault_id=None)


@pytest.mark.parametrize("malware", ["yes", "no", None])
def test_file_detonation_preserves_dynamic_data_and_manifest_contract(malware) -> None:
    app = create_wildfire_connector_app()
    action = app.actions_manager.get_action("detonate_file")
    assert action.meta.output is DetonateFileOutput
    assert get_type_hints(detonate_file)["return"] is DetonateFileOutput

    data = {
        "upload-file-info": {"sha256": "sample-hash", "md5": "sample-md5"},
        "file_info": {"malware": malware, "vendor_extension": None},
        "task_info": {
            "report": [
                {"process": {"entry": []}, "new_section": {"007": [False, 0, None]}}
            ]
        },
    }
    params = DetonateFileParams(vault_id="vault-id")
    summary = PermissiveActionOutput(malware=malware)
    message = f"Malware: {malware}"
    legacy = ActionResult(True, message, params.model_dump())
    legacy.add_data(data)
    legacy.set_summary({"malware": malware})

    output = DetonateFileOutput(**data)
    assert isinstance(output, ActionOutput)
    assert App._adapt_action_result(
        output, app.actions_manager, params, message, summary
    )
    result = app.actions_manager.get_results()[-1]
    assert result.get_status() == legacy.get_status()
    assert result.get_message() == legacy.get_message()
    assert result.get_param() == legacy.get_param()
    assert result.get_summary() == legacy.get_summary()
    assert result.get_data() == legacy.get_data()
