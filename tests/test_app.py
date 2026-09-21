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
