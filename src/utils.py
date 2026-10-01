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
from typing import Any

import httpx
import xmltodict
from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure


WILDFIRE_HTTP_TIMEOUT = httpx.Timeout(
    connect=10.0,
    read=60.0,
    write=60.0,
    pool=10.0,
)


def parse_wildfire_xml(response: httpx.Response) -> dict[str, object]:
    """Parse a WildFire XML response and return its payload."""
    try:
        parsed = xmltodict.parse(response.text)
    except Exception as exc:
        raise ActionFailure(f"Unable to parse reply from device: {exc}") from exc

    wildfire = parsed.get("wildfire")
    if not isinstance(wildfire, dict):
        raise ActionFailure("None 'wildfire' missing in reply from device")
    return wildfire


def _normalize_children_into_lists(value: object) -> dict[str, list[Any]]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key).lower(): child if isinstance(child, list) else [child]
        for key, child in value.items()
    }


def normalize_wildfire_report(report: dict[str, Any]) -> None:
    """Normalize existing XML collections declared as lists by output contracts."""
    for key in ("network", "timeline", "summary", "process_list", "registry", "file"):
        if isinstance(report.get(key), dict):
            report[key] = _normalize_children_into_lists(report[key])

    process_tree = report.get("process_tree")
    if process_tree is not None and not isinstance(process_tree, list):
        report["process_tree"] = [process_tree]

    process_list = report.get("process_list", {})
    if not isinstance(process_list, dict):
        process_list = {}
    for process in process_list.get("process", []):
        if not isinstance(process, dict):
            continue
        for key in ("service", "registry", "file", "mutex"):
            if isinstance(process.get(key), dict):
                process[key] = _normalize_children_into_lists(process[key])

    summary = report.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    for index, entry in enumerate(summary.get("entry", [])):
        if not isinstance(entry, dict):
            summary["entry"][index] = {
                "#text": entry,
                "@details": "N/A",
                "@score": "N/A",
                "@id": "N/A",
            }


def normalize_wildfire_report_response(
    response: dict[str, Any],
) -> dict[str, Any]:
    """Normalize parsed XML report collections before adding action data."""
    task_info = response.get("task_info")
    if not isinstance(task_info, dict):
        return response

    reports = task_info.get("report")
    if isinstance(reports, dict):
        reports = [reports]
        task_info["report"] = reports
    if not isinstance(reports, list):
        return response

    for report in reports:
        if isinstance(report, dict):
            normalize_wildfire_report(report)
    return response


def add_bytes_to_vault(
    soar: SOARClient,
    content: bytes,
    file_name: str,
    *,
    contains: list[str],
) -> str:
    """Attach downloaded bytes to the executing container's vault."""
    try:
        return soar.vault.create_attachment(
            soar.get_executing_container_id(),
            content,
            file_name,
            metadata={"contains": contains},  # type: ignore[dict-item]
        )
    except Exception as exc:
        raise ActionFailure(
            f"Unable to add downloaded file to the vault: {exc}"
        ) from exc
