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


def _view_context() -> ViewContext:
    return ViewContext(
        QS={},
        container=123,
        app=456,
        no_connection=False,
        google_maps_key=False,
    )


def test_report_actions_register_sdk_custom_view() -> None:
    app = create_wildfire_connector_app()

    for identifier in ("detonate_file", "detonate_url", "get_report"):
        action = app.actions_manager.get_action(identifier)
        assert action.meta.render_as == "custom"
        assert action.meta.view_handler is not None


def test_report_handlers_render_raw_action_results() -> None:
    app = create_wildfire_connector_app()
    fixtures = {
        "detonate_file": {
            "file_info": {
                "sha256": "file-sha256",
                "md5": "file-md5",
                "size": "42",
                "filetype": "PDF",
                "malware": "no",
            },
            "task_info": {"report": []},
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
            "task_info": {"report": []},
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
