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
from collections.abc import Sequence
from typing import Any

from pydantic import ConfigDict
from soar_sdk.action_results import ActionOutput
from soar_sdk.models.view import ViewContext


class WildFireReportViewOutput(ActionOutput):
    """Minimal permissive schema for report data consumed by custom views."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")


def _add_http_urls(report: dict[str, Any]) -> None:
    connections = report.get("network", {}).get("url", [])
    if isinstance(connections, dict):
        connections = [connections]

    for connection in connections:
        host = connection.get("@host", "")
        if host and "://" not in host:
            host = f"http://{host}"
        host = host.rstrip("/")
        uri = connection.get("@uri", "").lstrip("/")
        connection["url"] = f"{host}/{uri}" if uri else host


def _add_template_defaults(report: dict[str, Any]) -> None:
    """Supply empty collections where the legacy template traverses nested keys."""
    for key, children in {
        "network": ("url", "tcp", "udp", "dns"),
        "timeline": ("entry",),
        "process_list": ("process",),
        "process": ("process_created", "process_terminated"),
        "registry": ("createvaluekey", "setvaluekey", "deletevaluekey"),
        "file": ("file_deleted", "file_written"),
        "summary": ("entry",),
    }.items():
        section = report.get(key)
        if not isinstance(section, dict):
            section = {}
            report[key] = section
        for child in children:
            if section.get(child) is None:
                section[child] = []


def build_report_context(
    context: ViewContext,
    outputs: Sequence[ActionOutput],
    *,
    is_url: bool,
) -> dict[str, Any]:
    """Adapt SDK output models to the legacy WildFire report template."""
    results: list[dict[str, Any]] = []

    for output in outputs:
        data = output.model_dump(by_alias=True, exclude_none=True)
        result: dict[str, Any] = {
            "file_info": data.get("file_info") or data.get("upload-file-info") or {},
            "param": {"is_file": not is_url},
            "reports": [],
        }

        if is_url:
            url_result = data.get("result", {})
            reports = url_result.get("report")
            result["url_type"] = url_result.get("url_type")
            result["analysis_time"] = url_result.get("analysis_time")
        else:
            reports = data.get("task_info", {}).get("report")

        if isinstance(reports, dict):
            reports = [reports]
        if not reports:
            results.append(result)
            continue

        static_count = 1
        dynamic_count = 1
        for report in reports:
            software = report.get("software") or (
                "Not specified, probably running Win XP SP2"
            )
            report["software"] = software
            if "Static Analyzer" in software:
                report["type"] = "static"
                report["name"] = f"Static Analysis {static_count}"
                static_count += 1
            else:
                report["type"] = "dynamic"
                report["name"] = f"Dynamic Analysis {dynamic_count}"
                dynamic_count += 1
            _add_template_defaults(report)
            _add_http_urls(report)

        result["reports"] = reports
        results.append(result)

    return {"container": {"id": context.container}, "results": results}
