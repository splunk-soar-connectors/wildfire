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
from soar_sdk.abstract import SOARClient
import math
import time

import httpx
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.models.view import ViewContext
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..utils import (
    GET_REPORT_ERRORS,
    VERDICT_MESSAGES,
    WILDFIRE_HTTP_TIMEOUT,
    normalize_wildfire_report_response,
    parse_wildfire_xml,
)
from ..views.report import WildFireReportViewOutput, build_report_context

logger = getLogger()
POLL_INTERVAL_SECONDS = 5


class GetReportParams(Params):
    id: str = Param(
        description="File MD5 or Sha256 to get the results of",
        primary=True,
        cef_types=["md5", "sha256", "wildfire task id"],
    )


class CommonFileInfoOutput(ActionOutput):
    file_signer: str | None = OutputField(example_values=["None"])
    filetype: str | None = OutputField()
    malware: str | None = OutputField()
    md5: str | None = OutputField(cef_types=["md5", "hash"])
    sha1: str | None = OutputField(cef_types=["sha1", "hash"])
    sha256: str | None = OutputField(cef_types=["sha256", "hash"])
    size: str | None = OutputField()


class ApkFileInfoOutput(ActionOutput):
    APK_Certificate: str = OutputField(
        example_values=["E579936D9FCA68C394F3AE8C604EBB4C"]
    )
    APK_Package_Name: str = OutputField(
        example_values=["com.ibm.android.analyzer.test"]
    )
    APK_Signer: str = OutputField(example_values=["CN=Android Debug, O=Android, C=US"])
    APK_Version: str = OutputField(example_values=["1.0"])
    App_Icon: str = OutputField(example_values=["res/drawable-ldpi-v4/icon.png"])
    App_Name: str = OutputField(example_values=["com.ibm.android.analyzer.test"])
    File_Type: str = OutputField(example_values=["APK"])
    Max_SDK_Requirement: str
    Min_SDK_Requirement: str = OutputField(example_values=["11"])
    Repackaged: str = OutputField(example_values=["False"])
    Target_SDK: str = OutputField(example_values=["11"])


class CertFileOutput(ActionOutput):
    Format: str = OutputField(example_values=["certificate"], alias="@Format")
    Issuer: str = OutputField(
        example_values=["CN=Android Debug, O=Android, C=US"], alias="@Issuer"
    )
    MD5: str = OutputField(
        example_values=["E579936D9FCA68C394F3AE8C604EBB4C"], alias="@MD5"
    )
    Owner: str = OutputField(
        example_values=["CN=Android Debug, O=Android, C=US"], alias="@Owner"
    )
    SHA1: str = OutputField(
        example_values=["7BD81368B868225BDE96FC1A3FEE59A8EA06296A"], alias="@SHA1"
    )
    SHA256: str = OutputField(
        example_values=[
            "5D3820107210AA11007A7E1BDCA9590916F2C8C52B132CD53A9C83373805C280"
        ],
        alias="@SHA256",
    )


class EmbeddedUrlsOutput(ActionOutput):
    Known_Malicious_URL: str = OutputField(alias="@Known_Malicious_URL")
    URL: str = OutputField(
        example_values=["https://1.www.s81c.com/i/v17/t/ibm_logo_print.png?s3"],
        alias="@URL",
    )


class InternalFileOutput(ActionOutput):
    Format: str = OutputField(example_values=["xml"], alias="@Format")
    SHA256: str = OutputField(
        example_values=[
            "F9A42AF08FEE0695E3E3825DD4D27011078E6C9FFE237F8990876E6BBE31EA2B"
        ],
        alias="@SHA256",
    )


class SuspiciousApiCallsOutput(ActionOutput):
    API_Calls: str = OutputField(
        example_values=["android/telephony/TelephonyManager;->getDeviceId"],
        alias="@API_Calls",
    )
    Description: str = OutputField(
        example_values=["APK file invokes sensitive APIs"], alias="@Description"
    )


class SuspiciousActionMonitoredOutput(ActionOutput):
    Action: str = OutputField(
        example_values=["APK file displayed a float window"], alias="@Action"
    )
    Details: str = OutputField(
        example_values=[
            "{'flags': 8454400, 'format': -1, 'height': -1, 'type': 1, 'width': -1}"
        ],
        alias="@Details",
    )


class SuspiciousBehaviorOutput(ActionOutput):
    Behavior: str = OutputField(
        example_values=["APK file can send an SMS message"], alias="@Behavior"
    )
    Description: str = OutputField(alias="@Description")
    Target: str = OutputField(example_values=["+49 1234"], alias="@Target")


class SuspiciousFilesOutput(ActionOutput):
    File_Type: str = OutputField(example_values=["ELF"], alias="@File_Type")
    Reason: str = OutputField(
        example_values=["APK file contains native code"], alias="@Reason"
    )


class SuspiciousPatternOutput(ActionOutput):
    Description: str = OutputField(
        example_values=[
            "APK file uses java reflection technique;String:\\n|createSubprocess|waitFor|data|android.os.Exec"
        ],
        alias="@Description",
    )
    Feature: str = OutputField(example_values=["java reflection"], alias="@Feature")


class SuspiciousStringsOutput(ActionOutput):
    Description: str = OutputField(
        example_values=["APK file contains shell command strings"], alias="@Description"
    )
    String: str = OutputField(example_values=["/system/bin/sh"], alias="@String")


class EntryOutput(ActionOutput):
    seq: str = OutputField(alias="@seq")


class FileDeletedOutput(ActionOutput):
    deleted_file: str = OutputField(alias="@deleted_file")


class FileWrittenOutput(ActionOutput):
    written_file: str = OutputField(alias="@written_file")


class SectionOutput(ActionOutput):
    name: str = OutputField(example_values=[".text"], alias="@name")
    raw_size: str = OutputField(example_values=["36864"], alias="@raw_size")
    virtual_addr: str = OutputField(example_values=["4096"], alias="@virtual_addr")
    virtual_size: str = OutputField(example_values=["36378"], alias="@virtual_size")


class DnsOutput(ActionOutput):
    query: str = OutputField(alias="@query")
    response: str = OutputField(alias="@response")
    type: str = OutputField(alias="@type")


class TcpOutput(ActionOutput):
    country: str = OutputField(alias="@country")
    ip: str = OutputField(cef_types=["ip"], alias="@ip")
    ja3: str = OutputField(alias="@ja3")
    ja3s: str = OutputField(alias="@ja3s")
    port: str = OutputField(alias="@port")


class UdpOutput(ActionOutput):
    country: str = OutputField(alias="@country")
    ip: str = OutputField(alias="@ip")
    port: str = OutputField(alias="@port")


class UrlOutput(ActionOutput):
    host: str = OutputField(alias="@host")
    method: str = OutputField(alias="@method")
    uri: str = OutputField(alias="@uri")
    user_agent: str = OutputField(alias="@user_agent")


class ProcessFileCreatedOutput(ActionOutput):
    md5: str = OutputField(cef_types=["md5", "hash"], alias="@md5")
    name: str = OutputField(cef_types=["file path"], alias="@name")
    sha1: str = OutputField(cef_types=["sha1", "hash"], alias="@sha1")
    sha256: str = OutputField(cef_types=["sha256", "hash"], alias="@sha256")
    size: str = OutputField(alias="@size")
    type: str = OutputField(alias="@type")


class CreatemutexOutput(ActionOutput):
    name: str = OutputField(alias="@name")


class SetOutput(ActionOutput):
    data: str = OutputField(alias="@data")


class ProcessTreeNodeOutput(ActionOutput):
    name: str | None = OutputField(cef_types=["process name"], alias="@name")
    text: str | None = OutputField(alias="@text")


class StaticAnalysisOutput(ActionOutput):
    Defined_Receivers: str
    Defined_Sensors: str
    Defined_Services: str
    Embedded_Libraries: str
    Requested_Permissions: str
    Sensitive_API_Calls_Performed: str


class ApkApiOutput(ActionOutput):
    Cert_File: CertFileOutput
    Embedded_URLs: list[EmbeddedUrlsOutput]
    Internal_File: list[InternalFileOutput]
    Suspicious_API_Calls: list[SuspiciousApiCallsOutput]
    Suspicious_Action_Monitored: list[SuspiciousActionMonitoredOutput]
    Suspicious_Behavior: SuspiciousBehaviorOutput
    Suspicious_Files: list[SuspiciousFilesOutput]
    Suspicious_Pattern: list[SuspiciousPatternOutput]
    Suspicious_Strings: list[SuspiciousStringsOutput]


class ProcessFileActivityOutput(ActionOutput):
    create: list[ProcessFileCreatedOutput]


class ReportFileActivityOutput(ActionOutput):
    file_deleted: list[FileDeletedOutput]
    file_written: list[FileWrittenOutput]


class EvidenceEntryOutput(ActionOutput):
    behavior_id: str | None = OutputField(alias="@behavior_id")


class EvidenceFileOutput(ActionOutput):
    entry: list[EvidenceEntryOutput]


class ExtractedUrlEntryOutput(ActionOutput):
    url: str | None = OutputField(
        alias="@url",
        example_values=["www.google.com.hk/imghp?hl=en&tab=ri&authuser=0&ogbl"],
    )
    verdict: str | None = OutputField(alias="@verdict", example_values=["unknown"])


class ExtractedUrlsOutput(ActionOutput):
    entry: list[ExtractedUrlEntryOutput]


class SectionsOutput(ActionOutput):
    section: list[SectionOutput]


class NetworkOutput(ActionOutput):
    dns: list[DnsOutput]
    tcp: list[TcpOutput]
    udp: list[UdpOutput]
    url: list[UrlOutput]


class ProcessMutexOutput(ActionOutput):
    createmutex: list[CreatemutexOutput]


class ProcessRegistryOutput(ActionOutput):
    set: list[SetOutput]


class ProcessRecordOutput(ActionOutput):
    command: str | None = OutputField(alias="@command")
    name: str | None = OutputField(cef_types=["process name"], alias="@name")
    file: ProcessFileActivityOutput | None
    java_api: str | None
    mutex: ProcessMutexOutput | None
    process_activity: str | None
    registry: ProcessRegistryOutput | None


class ProcessListOutput(ActionOutput):
    process: list[ProcessRecordOutput]


class ProcessTreeEntryOutput(ActionOutput):
    process: list[ProcessTreeNodeOutput] | None


class SummaryEntryOutput(ActionOutput):
    details: str | None = OutputField(alias="@details")
    id: str | None = OutputField(alias="@id")
    score: str | None = OutputField(alias="@score")


class SummaryOutput(ActionOutput):
    entry: list[SummaryEntryOutput]


class TimelineOutput(ActionOutput):
    entry: list[EntryOutput]


class EvidenceOutput(ActionOutput):
    file: EvidenceFileOutput | None
    mutex: str
    process: str
    registry: str


class MetadataOutput(ActionOutput):
    compilation_timestamp: str = OutputField(example_values=["2012-12-20 19:14:11"])
    sections: SectionsOutput


class ReportOutput(ActionOutput):
    text: str = OutputField(alias="#text")
    File_Location: str = OutputField(
        example_values=["META-INF/CERT.RSA"], alias="@File_Location"
    )
    SDK: str = OutputField(alias="@SDK")
    SDK_Status: str = OutputField(alias="@SDK_Status")
    key: str = OutputField(alias="@key")
    attribute_md5: str | None = OutputField(cef_types=["md5", "hash"], alias="@md5")
    md5: str = OutputField(cef_types=["md5", "hash"])
    pid: str = OutputField(cef_types=["pid"], alias="@pid")
    process_image: str = OutputField(cef_types=["process name"], alias="@process_image")
    reg_key: str = OutputField(alias="@reg_key")
    sha1: str = OutputField(cef_types=["sha1", "hash"], alias="@sha1")
    attribute_sha256: str | None = OutputField(
        cef_types=["sha256", "hash"], alias="@sha256"
    )
    sha256: str = OutputField(cef_types=["sha256", "hash"])
    subkey: str = OutputField(alias="@subkey")
    apk_api: ApkApiOutput | None
    doc_embedded_files: str
    embedded_files: str
    embedded_urls: str
    entry: str = OutputField(example_values=["com.panw.panwapktest.MainActivity"])
    evidence: EvidenceOutput | None
    extracted_urls: ExtractedUrlsOutput | None
    file: ReportFileActivityOutput | None
    file_info: ApkFileInfoOutput | None
    malware: str
    metadata: MetadataOutput | None
    network: NetworkOutput | None
    platform: str
    process_list: ProcessListOutput | None
    process_tree: list[ProcessTreeEntryOutput] | None
    size: str
    software: str
    static_analysis: StaticAnalysisOutput | None
    summary: SummaryOutput | None
    task: str
    timeline: TimelineOutput | None


class TaskInfoOutput(ActionOutput):
    report: list[ReportOutput]


class GetReportOutput(PermissiveActionOutput):
    file_info: CommonFileInfoOutput
    task_info: TaskInfoOutput
    version: str


class GetReportSummary(ActionOutput):
    verdict_code: float
    verdict: str
    summary_available: bool
    malware: str | None


def display_get_report(
    context: ViewContext,
    action: str,
    outputs: list[WildFireReportViewOutput],
) -> dict:
    del action
    return build_report_context(context, outputs, is_url=False)


def get_report(
    params: GetReportParams, soar: SOARClient, asset: Asset
) -> GetReportOutput:
    """Retrieve a WildFire report for an existing sample hash."""
    verify = asset.verify_server_cert if asset.verify_server_cert is not None else True
    base_url = f"{asset.base_url.rstrip('/')}/publicapi/"
    try:
        with httpx.Client(
            base_url=base_url, verify=verify, timeout=WILDFIRE_HTTP_TIMEOUT
        ) as client:
            logger.progress("Getting verdict for: %s", params.id)
            verdict_response = client.post(
                "get/verdict",
                data={"apikey": asset.api_key},
                files={"hash": ("", params.id)},
            )
            try:
                verdict_response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                detail = verdict_response.text.strip() or GET_REPORT_ERRORS.get(
                    verdict_response.status_code, "N/A"
                )
                raise ActionFailure(
                    "REST Api Call returned error, "
                    f"status_code: {verdict_response.status_code}, detail: {detail}"
                ) from exc
            verdict_info = parse_wildfire_xml(verdict_response).get("get-verdict-info")
            if not isinstance(verdict_info, dict):
                raise ActionFailure("Verdict could not be retrieved")

            try:
                verdict_code = int(verdict_info["verdict"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ActionFailure("Verdict could not be retrieved") from exc

            verdict = VERDICT_MESSAGES.get(verdict_code, "unknown verdict code")
            summary = {
                "verdict_code": verdict_code,
                "verdict": verdict,
                "summary_available": verdict_code >= 0,
            }
            message = (
                f"Verdict code: {verdict_code}, Verdict: {verdict}, "
                f"Summary available: {verdict_code >= 0}"
            )
            soar.set_message(message)
            soar.set_summary(PermissiveActionOutput(**summary))
            if verdict_code < 0:
                return GetReportOutput()

            max_attempts = math.ceil(asset.timeout * 60 / POLL_INTERVAL_SECONDS)
            for attempt in range(1, max_attempts + 1):
                logger.progress("Polling attempt %s of %s", attempt, max_attempts)
                report_response = client.post(
                    "get/report",
                    data={
                        "apikey": asset.api_key,
                        "format": "xml",
                        "hash": params.id,
                    },
                )
                if report_response.status_code == httpx.codes.NOT_FOUND:
                    time.sleep(POLL_INTERVAL_SECONDS)
                    continue
                try:
                    report_response.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    detail = report_response.text.strip() or GET_REPORT_ERRORS.get(
                        report_response.status_code, "N/A"
                    )
                    raise ActionFailure(
                        "REST Api Call returned error, "
                        f"status_code: {report_response.status_code}, detail: {detail}"
                    ) from exc
                report_data = normalize_wildfire_report_response(
                    parse_wildfire_xml(report_response)
                )
                return GetReportOutput(**report_data)
    except httpx.HTTPError as exc:
        raise ActionFailure(f"REST Api to server failed: {exc}") from exc

    raise ActionFailure("Reached max polling attempts.")
