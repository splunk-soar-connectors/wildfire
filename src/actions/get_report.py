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
import xmltodict
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.models.view import ViewContext
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..views.report import WildFireReportViewOutput, build_report_context

logger = getLogger()
VERDICT_MESSAGES = {
    0: "benign",
    1: "malware",
    2: "grayware",
    4: "phishing",
    -100: "pending, the sample exists, but there is currently no verdict",
    -101: "error",
    -102: "unknown, cannot find sample record in the WildFire database",
    -103: "invalid hash value",
}
GET_REPORT_ERRORS = {
    401: "API key invalid",
    404: "The report was not found",
    405: "HTTP method Not Allowed",
    419: "Request report quota exceeded",
    420: "Insufficient arguments",
    421: "Invalid arguments",
    500: "Internal error",
}
POLL_INTERVAL_SECONDS = 5


class GetReportParams(Params):
    id: str = Param(
        description="File MD5 or Sha256 to get the results of",
        primary=True,
        cef_types=["md5", "sha256", "wildfire task id"],
    )


class FileInfoOutput(ActionOutput):
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


class CreateOutput(ActionOutput):
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


class ProcessOutput(ActionOutput):
    name: str = OutputField(cef_types=["process name"], alias="@name")


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


class FileOutput(ActionOutput):
    create: list[CreateOutput]


class ExtractedUrlsOutput(ActionOutput):
    entry: list[EntryOutput]


class SectionsOutput(ActionOutput):
    section: list[SectionOutput]


class NetworkOutput(ActionOutput):
    dns: list[DnsOutput]
    tcp: list[TcpOutput]
    udp: list[UdpOutput]
    url: list[UrlOutput]


class MutexOutput(ActionOutput):
    createmutex: list[CreatemutexOutput]


class RegistryOutput(ActionOutput):
    set: list[SetOutput]


class ProcessListOutput(ActionOutput):
    process: list[ProcessOutput]


class ProcessTreeOutput(ActionOutput):
    process: ProcessOutput


class SummaryOutput(ActionOutput):
    entry: list[EntryOutput]


class TimelineOutput(ActionOutput):
    entry: list[EntryOutput]


class EvidenceOutput(ActionOutput):
    file: FileOutput
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
    md5: str = OutputField(cef_types=["md5", "hash"])
    pid: str = OutputField(cef_types=["pid"], alias="@pid")
    process_image: str = OutputField(cef_types=["process name"], alias="@process_image")
    reg_key: str = OutputField(alias="@reg_key")
    sha1: str = OutputField(cef_types=["sha1", "hash"], alias="@sha1")
    sha256: str = OutputField(cef_types=["sha256", "hash"])
    subkey: str = OutputField(alias="@subkey")
    apk_api: ApkApiOutput
    doc_embedded_files: str
    embedded_files: str
    embedded_urls: str
    entry: str = OutputField(example_values=["com.panw.panwapktest.MainActivity"])
    evidence: EvidenceOutput
    extracted_urls: ExtractedUrlsOutput
    file: FileOutput
    file_info: FileInfoOutput
    malware: str
    metadata: MetadataOutput
    network: NetworkOutput
    platform: str
    process_list: ProcessListOutput
    process_tree: list[ProcessTreeOutput]
    size: str
    software: str
    static_analysis: StaticAnalysisOutput
    summary: SummaryOutput
    task: str
    timeline: TimelineOutput


class TaskInfoOutput(ActionOutput):
    report: list[ReportOutput]


class GetReportOutput(ActionOutput):
    file_info: FileInfoOutput
    task_info: TaskInfoOutput
    version: str


class GetReportSummary(ActionOutput):
    verdict_code: float
    verdict: str
    summary_available: bool


def display_get_report(
    context: ViewContext,
    action: str,
    outputs: list[WildFireReportViewOutput],
) -> dict:
    del action
    return build_report_context(context, outputs, is_url=False)


def _parse_wildfire_xml(response: httpx.Response) -> dict[str, object]:
    try:
        parsed = xmltodict.parse(response.text)
    except Exception as exc:
        raise ActionFailure(f"Unable to parse reply from device: {exc}") from exc

    wildfire = parsed.get("wildfire")
    if not isinstance(wildfire, dict):
        raise ActionFailure("None 'wildfire' missing in reply from device")
    return wildfire


def _raise_for_error(response: httpx.Response) -> None:
    if response.status_code == httpx.codes.OK:
        return
    detail = response.text.strip() or GET_REPORT_ERRORS.get(response.status_code, "N/A")
    raise ActionFailure(
        "REST Api Call returned error, "
        f"status_code: {response.status_code}, detail: {detail}"
    )


def get_report(
    params: GetReportParams, soar: SOARClient, asset: Asset
) -> GetReportOutput:
    """Retrieve a WildFire report for an existing sample hash."""
    del soar
    verify = asset.verify_server_cert if asset.verify_server_cert is not None else True
    base_url = f"{asset.base_url.rstrip('/')}/publicapi/"
    timeout = httpx.Timeout(None)

    try:
        with httpx.Client(base_url=base_url, verify=verify, timeout=timeout) as client:
            logger.progress("Getting verdict for: %s", params.id)
            verdict_response = client.post(
                "get/verdict",
                data={"apikey": asset.api_key},
                files={"hash": ("", params.id)},
            )
            _raise_for_error(verdict_response)
            verdict_info = _parse_wildfire_xml(verdict_response).get("get-verdict-info")
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
            result = ActionResult(
                True,
                (
                    f"Verdict code: {verdict_code}, Verdict: {verdict}, "
                    f"Summary available: {verdict_code >= 0}"
                ),
                params.model_dump(),
            )
            result.set_summary(summary)
            if verdict_code < 0:
                return result  # type: ignore[return-value]

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
                _raise_for_error(report_response)
                result.add_data(_parse_wildfire_xml(report_response))
                return result  # type: ignore[return-value]
    except httpx.HTTPError as exc:
        raise ActionFailure(f"REST Api to server failed: {exc}") from exc

    raise ActionFailure("Reached max polling attempts.")
