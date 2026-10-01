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
import importlib
from pathlib import Path
from typing import Any

from soar_sdk.action_results import ActionOutput, ActionResult
from soar_sdk.models.view import ViewContext
from soar_sdk.views.template_renderer import get_template_renderer

from src.app import create_wildfire_connector_app
from src.views.report import build_report_context


class FileReportOutput(ActionOutput):
    file_info: dict[str, Any]
    task_info: dict[str, Any]


class UrlReportOutput(ActionOutput):
    result: dict[str, Any]


class UrlFileReportOutput(ActionOutput):
    file_info: dict[str, Any]
    task_info: dict[str, Any]


def _view_context() -> ViewContext:
    return ViewContext(
        QS={},
        container=123,
        app=456,
        no_connection=False,
        google_maps_key=False,
    )


def test_report_template_extends_widget_before_emitting_content() -> None:
    template = Path(__file__).parents[1] / "templates" / "wildfire_display_report.html"

    assert template.read_text().startswith(
        "{% extends 'widgets/widget_template.html' %}"
    )


def test_report_actions_register_sdk_custom_view() -> None:
    app = create_wildfire_connector_app()

    for identifier in ("detonate_file", "detonate_url", "get_report"):
        action = app.actions_manager.get_action(identifier)
        assert action.meta.render_as == "custom"
        assert action.meta.view_handler is not None


def test_manifest_view_paths_resolve_through_action_modules() -> None:
    app = create_wildfire_connector_app()

    for identifier in ("detonate_file", "detonate_url", "get_report"):
        action = app.actions_manager.get_action(identifier)
        view_handler = action.meta.view_handler
        assert view_handler is not None

        view_path = f"{view_handler.__module__}.{view_handler.__name__}"
        path_parts = view_path.split(".")
        resolved: Any = importlib.import_module(path_parts[0])
        for path_part in path_parts[1:]:
            resolved = getattr(resolved, path_part)

        assert resolved is view_handler


def test_report_handlers_render_raw_action_results() -> None:
    app = create_wildfire_connector_app()

    def null_optional_report() -> dict[str, Any]:
        return {
            "sha256": "file-sha256",
            "software": "PE Static Analyzer",
            "network": None,
            "timeline": None,
            "process_list": None,
            "process": None,
            "registry": None,
            "file": None,
            "summary": None,
        }

    fixtures = {
        "detonate_file": {
            "file_info": {
                "sha256": "file-sha256",
                "md5": "file-md5",
                "size": "42",
                "filetype": "PDF",
                "malware": "no",
            },
            "task_info": {"report": null_optional_report()},
            "version": "2.0",
        },
        "detonate_url": {
            "result": {
                "analysis_time": "2026-09-21T00:00:00Z",
                "url_type": "original",
                "report": {
                    "sha256": "url-sha256",
                    "software": "Web Browser",
                    "verdict": "benign",
                },
            },
            "version": "2.0",
        },
        "get_report": {
            "file_info": {
                "sha256": "report-sha256",
                "md5": "report-md5",
                "size": "42",
                "filetype": "PDF",
                "malware": "no",
            },
            "task_info": {"report": null_optional_report()},
            "version": "2.0",
        },
    }

    for identifier, data in fixtures.items():
        action_result = ActionResult(True, "Success", {})
        action_result.add_data(data)
        view_handler = app.actions_manager.get_action(identifier).meta.view_handler
        assert view_handler is not None

        html = view_handler(
            identifier,
            [
                (
                    {"total_objects": 1, "total_objects_successful": 1},
                    [action_result],
                )
            ],
            _view_context().model_dump(),
        )

        assert 'class="wildfire-display-report"' in html
        assert "View Function Error" not in html


def test_file_report_context_renders_legacy_information() -> None:
    output = FileReportOutput(
        file_info={
            "sha256": "sample-sha256",
            "md5": "sample-md5",
            "size": "42",
            "filetype": "PE",
            "malware": "no",
        },
        task_info={
            "report": [
                {
                    "sha256": "sample-sha256",
                    "software": "PE Static Analyzer",
                    "malware": "no",
                    "network": {
                        "url": [
                            {
                                "@host": "example.test",
                                "@uri": "/payload",
                                "@method": "GET",
                            }
                        ]
                    },
                    "process_list": {
                        "process": [
                            {"@name": "sample.exe", "@pid": "7", "@command": "run"}
                        ]
                    },
                    "timeline": {"entry": [{"@seq": "1", "#text": "started"}]},
                    "summary": {
                        "entry": [
                            {
                                "#text": "Observed behavior",
                                "@details": "details",
                                "@score": "1",
                                "@id": "behavior-1",
                            }
                        ]
                    },
                }
            ]
        },
    )
    template_context = build_report_context(_view_context(), [output], is_url=False)
    renderer = get_template_renderer(
        "jinja", str(Path(__file__).parents[1] / "templates")
    )

    html = renderer.render_template("wildfire_display_report.html", template_context)

    assert 'class="wildfire-display-report"' in html
    assert "sample-sha256" in html
    assert "sample-md5" in html
    assert "Filetype" in html
    assert "Clean" in html
    assert "Network Activity" in html
    assert "http://example.test/payload" in html
    assert "Processes" in html
    assert "Timeline" in html
    assert "Behavioral Summary" in html
    assert "Complete Report Data" in html


def test_file_report_context_normalizes_singleton_xml_collections() -> None:
    output = FileReportOutput(
        file_info={"sha256": "sample-sha256"},
        task_info={
            "report": {
                "software": "WildFire Dynamic Analyzer",
                "network": {
                    "tcp": {"@ip": "192.0.2.1", "@port": "443"},
                    "dns": {"@query": "example.test", "@response": "192.0.2.1"},
                },
                "process_list": {
                    "process": {
                        "@name": "sample.exe",
                        "service": {"entry": {"@name": "sample-service"}},
                    }
                },
                "timeline": {"entry": {"@seq": "1", "#text": "started"}},
                "summary": {"entry": "Observed behavior"},
            }
        },
    )

    template_context = build_report_context(_view_context(), [output], is_url=False)
    report = template_context["results"][0]["reports"][0]

    assert report["network"]["tcp"] == [{"@ip": "192.0.2.1", "@port": "443"}]
    assert report["network"]["dns"] == [
        {"@query": "example.test", "@response": "192.0.2.1"}
    ]
    assert report["timeline"]["entry"] == [{"@seq": "1", "#text": "started"}]
    assert report["process_list"]["process"][0]["@name"] == "sample.exe"
    assert report["process_list"]["process"][0]["service"]["entry"] == [
        {"@name": "sample-service"}
    ]
    assert report["summary"]["entry"] == [
        {
            "#text": "Observed behavior",
            "@details": "N/A",
            "@score": "N/A",
            "@id": "N/A",
        }
    ]


def test_url_report_context_renders_legacy_information() -> None:
    output = UrlReportOutput(
        result={
            "analysis_time": "2026-09-21T00:00:00Z",
            "url_type": "original",
            "report": {
                "sha256": "url-sha256",
                "software": "Web Browser",
                "verdict": "benign",
            },
        }
    )
    template_context = build_report_context(_view_context(), [output], is_url=True)
    renderer = get_template_renderer(
        "jinja", str(Path(__file__).parents[1] / "templates")
    )

    html = renderer.render_template("wildfire_display_report.html", template_context)

    assert "url-sha256" in html
    assert "URLtype" in html
    assert "original" in html
    assert "Analysis Time" in html
    assert "Clean" in html


def test_url_file_report_context_reads_task_info_report() -> None:
    output = UrlFileReportOutput(
        file_info={"sha256": "url-file-sha256"},
        task_info={
            "report": {
                "sha256": "url-file-sha256",
                "software": "WildFire Dynamic Analyzer",
                "verdict": "malware",
            }
        },
    )

    template_context = build_report_context(_view_context(), [output], is_url=True)
    renderer = get_template_renderer(
        "jinja", str(Path(__file__).parents[1] / "templates")
    )

    assert template_context["results"][0]["param"]["is_file"] is True
    assert template_context["results"][0]["reports"][0]["sha256"] == ("url-file-sha256")
    html = renderer.render_template("wildfire_display_report.html", template_context)
    assert "url-file-sha256" in html
    assert "No report data found" not in html
