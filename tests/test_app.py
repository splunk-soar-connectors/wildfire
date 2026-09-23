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
from soar_sdk.app import App

from src.app import create_wildfire_connector_app


EXPECTED_ACTIONS = [
    "test_connectivity",
    "detonate_file",
    "detonate_url",
    "get_url_reputation",
    "get_report",
    "get_sample",
    "get_pcap",
    "save_report",
]


def test_factory_registers_all_generated_actions() -> None:
    app = create_wildfire_connector_app()

    assert isinstance(app, App)
    actions = app.actions_manager.get_actions_meta_list()
    assert [action.identifier for action in actions] == EXPECTED_ACTIONS
    assert next(
        action for action in actions if action.identifier == "get_sample"
    ).action == ("get file")


def test_generated_action_models_build_json_schemas() -> None:
    app = create_wildfire_connector_app()

    for action in app.actions_manager.get_actions_meta_list():
        action.parameters.model_json_schema()
        action.output.model_json_schema()


def test_all_actions_preserve_legacy_read_only_metadata() -> None:
    app = create_wildfire_connector_app()

    for action in app.actions_manager.get_actions_meta_list():
        assert action.read_only is True, action.identifier


def test_detonation_actions_publish_runtime_summary_contracts() -> None:
    app = create_wildfire_connector_app()

    expected_summary_paths = {
        "detonate_file": {"action_result.summary.malware"},
        "detonate_url": {
            "action_result.summary.verdict_code",
            "action_result.summary.verdict",
            "action_result.summary.summary_available",
        },
    }
    for identifier, expected_paths in expected_summary_paths.items():
        action = app.actions_manager.get_action(identifier).meta.model_dump()
        actual_paths = {
            field["data_path"]
            for field in action["output"]
            if field["data_path"].startswith("action_result.summary.")
        }
        assert actual_paths == expected_paths


def test_get_file_preserves_legacy_table_contract() -> None:
    app = create_wildfire_connector_app()
    action = app.actions_manager.get_action("get_sample").meta.model_dump()

    assert action["render"] == {"type": "table"}
    columns = {
        field["column_name"] for field in action["output"] if "column_name" in field
    }
    assert columns == {"File Name", "Hash", "File Type", "Vault ID"}


def test_save_report_preserves_legacy_table_contract() -> None:
    app = create_wildfire_connector_app()
    action = app.actions_manager.get_action("save_report").meta.model_dump()

    assert action["render"] == {"type": "table"}
    columns = {
        field["column_name"] for field in action["output"] if "column_name" in field
    }
    assert columns == {"File Name", "Vault ID"}


def test_get_pcap_preserves_legacy_table_contract() -> None:
    app = create_wildfire_connector_app()
    action = app.actions_manager.get_action("get_pcap").meta.model_dump()

    assert action["render"] == {"type": "table"}
    columns = {
        field["column_name"] for field in action["output"] if "column_name" in field
    }
    assert columns == {"File Name", "Vault ID", "File Type"}


def test_url_reputation_preserves_legacy_table_contract() -> None:
    app = create_wildfire_connector_app()
    action = app.actions_manager.get_action("get_url_reputation").meta.model_dump()

    assert action["render"] == {"type": "table"}
    columns = {
        field["column_name"] for field in action["output"] if "column_name" in field
    }
    assert columns == {"Verdict Code", "Message"}
