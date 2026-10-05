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
import os
import subprocess
import sys

from soar_sdk.app import App
from soar_sdk.input_spec import EnvironmentVariable

from src.app import _apply_soar_proxy_environment, create_wildfire_connector_app


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

STABLE_DETONATE_URL_MAEC_PATHS = {
    "action_result.data.*.result.report.maec_packages.*.id",
    "action_result.data.*.result.report.maec_packages.*.maec_objects.*.analysis_metadata.*.analysis_type",
    "action_result.data.*.result.report.maec_packages.*.maec_objects.*.analysis_metadata.*.conclusion",
    "action_result.data.*.result.report.maec_packages.*.maec_objects.*.analysis_metadata.*.description",
    "action_result.data.*.result.report.maec_packages.*.maec_objects.*.analysis_metadata.*.end_time",
    "action_result.data.*.result.report.maec_packages.*.maec_objects.*.analysis_metadata.*.is_automated",
    "action_result.data.*.result.report.maec_packages.*.maec_objects.*.analysis_metadata.*.start_time",
    "action_result.data.*.result.report.maec_packages.*.maec_objects.*.analysis_metadata.*.tool_refs",
    "action_result.data.*.result.report.maec_packages.*.maec_objects.*.id",
    "action_result.data.*.result.report.maec_packages.*.maec_objects.*.instance_object_refs",
    "action_result.data.*.result.report.maec_packages.*.maec_objects.*.type",
    "action_result.data.*.result.report.maec_packages.*.schema_version",
    "action_result.data.*.result.report.maec_packages.*.type",
}

LEGACY_COMPATIBILITY_PATHS = {
    "detonate_file": set(
        """\
action_result.data.*.file_info.file_signer
action_result.data.*.file_info.filetype
action_result.data.*.file_info.malware
action_result.data.*.file_info.md5
action_result.data.*.file_info.sha1
action_result.data.*.file_info.sha256
action_result.data.*.file_info.size
action_result.data.*.task_info.report.*.elf_info.suspicious.entry.*.@behavior
action_result.data.*.task_info.report.*.elf_info.suspicious.entry.*.@behavior_id
action_result.data.*.task_info.report.*.elf_info.suspicious.entry.*.@description
action_result.data.*.task_info.report.*.elf_info.suspicious.entry.*.@family
action_result.data.*.task_info.report.*.elf_info.suspicious.entry.*.@matched_ioc_hash
action_result.data.*.task_info.report.*.evidence
action_result.data.*.task_info.report.*.evidence.file
action_result.data.*.task_info.report.*.evidence.file.entry.*.@behavior_id
action_result.data.*.task_info.report.*.evidence.file.entry.*.@md5
action_result.data.*.task_info.report.*.evidence.file.entry.@behavior_id
action_result.data.*.task_info.report.*.evidence.file.entry.@md5
action_result.data.*.task_info.report.*.extracted_urls.entry.*.@url
action_result.data.*.task_info.report.*.extracted_urls.entry.*.@verdict
action_result.data.*.task_info.report.*.extracted_urls.entry.@url
action_result.data.*.task_info.report.*.extracted_urls.entry.@verdict
action_result.data.*.task_info.report.*.file.file_deleted.*.@deleted_file
action_result.data.*.task_info.report.*.file.file_written.*.@written_file
action_result.data.*.task_info.report.*.process_list.process.*.@command
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@md5
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@name
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@size
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@type
action_result.data.*.task_info.report.*.process_list.process.*.java_api
action_result.data.*.task_info.report.*.process_list.process.*.mutex.createmutex.*.@name
action_result.data.*.task_info.report.*.process_list.process.*.process_activity
action_result.data.*.task_info.report.*.process_list.process.*.registry.set.*.@data
action_result.data.*.task_info.report.*.process_tree.*.process.*.@name
action_result.data.*.task_info.report.*.process_tree.*.process.*.@text
action_result.data.*.task_info.report.*.summary.entry.*.@behavior
action_result.data.*.task_info.report.*.summary.entry.*.@details
action_result.data.*.task_info.report.*.summary.entry.*.@id
action_result.data.*.task_info.report.*.summary.entry.*.@score
action_result.data.*.upload-file-info.filename
action_result.data.*.upload-file-info.filetype
action_result.data.*.upload-file-info.md5
action_result.data.*.upload-file-info.sha256
action_result.data.*.upload-file-info.size
action_result.data.*.upload-file-info.url
""".splitlines()
    ),
    "detonate_url": set(
        """\
action_result.data.*.result.report.da_packages
action_result.data.*.result.report.detection_reasons.*.artifacts.*.object_id
action_result.data.*.result.report.detection_reasons.*.artifacts.*.package
action_result.data.*.result.report.detection_reasons.*.artifacts.*.type
action_result.data.*.result.report.detection_reasons.*.description
action_result.data.*.result.report.detection_reasons.*.name
action_result.data.*.result.report.detection_reasons.*.type
action_result.data.*.result.report.detection_reasons.*.verdict
action_result.data.*.result.report.sa_package
action_result.data.*.result.report.schema_version
action_result.data.*.result.report.type
action_result.data.*.result.report.verdict
action_result.data.*.submit-link-info.md5
action_result.data.*.submit-link-info.sha256
action_result.data.*.submit-link-info.url
action_result.data.*.task_info.report.*.evidence.file.entry.*.#text
action_result.data.*.task_info.report.*.evidence.file.entry.*.@behavior_id
action_result.data.*.task_info.report.*.evidence.file.entry.*.@md5
action_result.data.*.task_info.report.*.evidence.file.entry.*.@sha1
action_result.data.*.task_info.report.*.evidence.file.entry.*.@sha256
action_result.data.*.task_info.report.*.process_list.process.*.@command
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@md5
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@name
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@sha1
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@sha256
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@size
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@type
action_result.data.*.task_info.report.*.process_list.process.*.java_api
action_result.data.*.task_info.report.*.process_list.process.*.mutex.createmutex.*.@name
action_result.data.*.task_info.report.*.process_list.process.*.process_activity
action_result.data.*.task_info.report.*.process_list.process.*.process_activity.Create.@child_pid
action_result.data.*.task_info.report.*.process_list.process.*.process_activity.Create.@child_process_image
action_result.data.*.task_info.report.*.process_list.process.*.process_activity.Create.@command
action_result.data.*.task_info.report.*.process_list.process.*.registry.create.*.@key
action_result.data.*.task_info.report.*.process_list.process.*.registry.create.*.@subkey
action_result.data.*.task_info.report.*.process_list.process.*.registry.set.*.@data
action_result.data.*.task_info.report.*.process_list.process.*.registry.set.*.@key
action_result.data.*.task_info.report.*.process_list.process.*.registry.set.*.@subkey
action_result.data.*.task_info.report.*.summary.entry.*.@details
action_result.data.*.task_info.report.*.summary.entry.*.@id
action_result.data.*.task_info.report.*.summary.entry.*.@score
""".splitlines()
    ),
    "get_report": set(
        """\
action_result.data.*.file_info.file_signer
action_result.data.*.file_info.filetype
action_result.data.*.file_info.malware
action_result.data.*.file_info.md5
action_result.data.*.file_info.sha1
action_result.data.*.file_info.sha256
action_result.data.*.file_info.size
action_result.data.*.task_info.report.*.@md5
action_result.data.*.task_info.report.*.@sha256
action_result.data.*.task_info.report.*.evidence
action_result.data.*.task_info.report.*.evidence.file
action_result.data.*.task_info.report.*.evidence.file.entry.*.@behavior_id
action_result.data.*.task_info.report.*.evidence.file.entry.@behavior_id
action_result.data.*.task_info.report.*.extracted_urls.entry.*.@url
action_result.data.*.task_info.report.*.extracted_urls.entry.*.@verdict
action_result.data.*.task_info.report.*.file.file_deleted.*.@deleted_file
action_result.data.*.task_info.report.*.file.file_written.*.@written_file
action_result.data.*.task_info.report.*.process_list.process.*.@command
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@md5
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@name
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@sha1
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@sha256
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@size
action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@type
action_result.data.*.task_info.report.*.process_list.process.*.java_api
action_result.data.*.task_info.report.*.process_list.process.*.mutex.createmutex.*.@name
action_result.data.*.task_info.report.*.process_list.process.*.process_activity
action_result.data.*.task_info.report.*.process_list.process.*.registry.set.*.@data
action_result.data.*.task_info.report.*.process_tree.*.process.*.@name
action_result.data.*.task_info.report.*.process_tree.*.process.*.@text
action_result.data.*.task_info.report.*.summary.entry.*.@details
action_result.data.*.task_info.report.*.summary.entry.*.@id
action_result.data.*.task_info.report.*.summary.entry.*.@score
""".splitlines()
    ),
}


def test_soar_proxy_environment_is_scoped_to_the_action_run() -> None:
    previous_http_proxy = os.environ.get("HTTP_PROXY")
    previous_https_proxy = os.environ.get("HTTPS_PROXY")
    environment_variables = {
        "HTTP_PROXY": EnvironmentVariable(
            type="string", value="http://proxy.example.test:8080"
        ),
        "HTTPS_PROXY": EnvironmentVariable(
            type="string", value="http://secure-proxy.example.test:8443"
        ),
    }

    with _apply_soar_proxy_environment(environment_variables):
        assert os.environ["HTTP_PROXY"] == "http://proxy.example.test:8080"
        assert os.environ["HTTPS_PROXY"] == "http://secure-proxy.example.test:8443"

    assert os.environ.get("HTTP_PROXY") == previous_http_proxy
    assert os.environ.get("HTTPS_PROXY") == previous_https_proxy


def test_factory_registers_all_generated_actions() -> None:
    app = create_wildfire_connector_app()

    assert isinstance(app, App)
    actions = app.actions_manager.get_actions_meta_list()
    assert [action.identifier for action in actions] == EXPECTED_ACTIONS
    assert next(
        action for action in actions if action.identifier == "get_sample"
    ).action == ("get file")


def test_module_cli_resolves_every_registered_action() -> None:
    for identifier in EXPECTED_ACTIONS:
        result = subprocess.run(
            [sys.executable, "-m", "src.app", "action", identifier, "--help"],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0, result.stderr
        assert f"action {identifier}" in result.stdout


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


def test_detonate_url_publishes_only_stable_maec_paths() -> None:
    app = create_wildfire_connector_app()
    action = app.actions_manager.get_action("detonate_url").meta.model_dump()

    maec_paths = {
        field["data_path"]
        for field in action["output"]
        if ".maec_packages." in field["data_path"]
    }

    assert maec_paths == STABLE_DETONATE_URL_MAEC_PATHS
    assert not any(".observable_objects." in path for path in maec_paths)


def test_detonation_actions_publish_stable_legacy_datapaths() -> None:
    app = create_wildfire_connector_app()

    for identifier, expected_paths in LEGACY_COMPATIBILITY_PATHS.items():
        action = app.actions_manager.get_action(identifier).meta.model_dump()
        actual_paths = {field["data_path"] for field in action["output"]}

        assert expected_paths <= actual_paths

    detonate_file_paths = {
        field["data_path"]
        for field in app.actions_manager.get_action("detonate_file").meta.model_dump()[
            "output"
        ]
    }
    detonate_url_paths = {
        field["data_path"]
        for field in app.actions_manager.get_action("detonate_url").meta.model_dump()[
            "output"
        ]
    }
    assert not any(".upload_file_info." in path for path in detonate_file_paths)
    assert not any(".submit_link_info." in path for path in detonate_url_paths)


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


def test_download_actions_preserve_legacy_per_hash_locks() -> None:
    app = create_wildfire_connector_app()

    for identifier in ("get_sample", "get_pcap"):
        action = app.actions_manager.get_action(identifier).meta.model_dump()
        assert action["lock"] == {
            "enabled": True,
            "concurrency": False,
            "data_path": "parameters.hash",
        }


def test_url_reputation_preserves_legacy_table_contract() -> None:
    app = create_wildfire_connector_app()
    action = app.actions_manager.get_action("get_url_reputation").meta.model_dump()

    assert action["render"] == {"type": "table"}
    columns = {
        field["column_name"] for field in action["output"] if "column_name" in field
    }
    assert columns == {"Verdict Code", "Message"}


def test_url_reputation_describes_direct_url_lookup() -> None:
    app = create_wildfire_connector_app()
    action = app.actions_manager.get_action("get_url_reputation").meta.model_dump()

    assert "queried directly" in action["verbose"]
    assert "returns a hash" not in action["verbose"]
