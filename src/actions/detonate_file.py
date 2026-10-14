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
import math
import time

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.models.view import ViewContext
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..utils import (
    FILE_UPLOAD_ERRORS,
    GET_REPORT_ERRORS,
    WILDFIRE_HTTP_TIMEOUT,
    normalize_wildfire_report_response,
    parse_wildfire_xml,
)
from ..views.report import WildFireReportViewOutput, build_report_context

logger = getLogger()
POLL_INTERVAL_SECONDS = 5


class DetonateFileParams(Params):
    vault_id: str = Param(
        description="Vault ID of file to detonate",
        primary=True,
        cef_types=["pe file", "pdf", "flash", "apk", "jar", "doc", "xls", "ppt"],
    )
    file_name: str | None = Param(
        description="Filename to use", primary=True, cef_types=["file name"]
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


class EmbeddedUrlsOutput(ActionOutput):
    Known_Malicious_URL: str = OutputField(alias="@Known_Malicious_URL")
    URL: str = OutputField(
        example_values=["https://1.www.s81c.com/i/v17/t/ibm_logo_print.png?s3"],
        alias="@URL",
    )


class InternalFileOutput(ActionOutput):
    Format: str = OutputField(example_values=["xml"], alias="@Format")


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


class ShellCommandsOutput(ActionOutput):
    entry: str = OutputField(example_values=["/bin/cp /tmp/panwtest /usr/bin/ps"])


class EntryOutput(ActionOutput):
    seq: str = OutputField(alias="@seq")


class SummaryEntryOutput(ActionOutput):
    behavior: str | None = OutputField(
        alias="@behavior", example_values=["elf_sa_em_x86_64"]
    )
    details: str | None = OutputField(alias="@details")
    id: str | None = OutputField(alias="@id")
    score: str | None = OutputField(alias="@score")


class ExtractedUrlEntryOutput(ActionOutput):
    url: str | None = OutputField(
        alias="@url",
        example_values=[
            "www.virustotal.com/#/file/0d6c7e4e3c3e22b50283248ed6e9663743720e998a5bfafcaef0b819cc7c8fcf/detection"
        ],
    )
    verdict: str | None = OutputField(alias="@verdict", example_values=["unknown"])


class ElfSuspiciousEntryOutput(ActionOutput):
    behavior: str | None = OutputField(
        alias="@behavior", example_values=["elf_sa_matched_ssdeep"]
    )
    behavior_id: str | None = OutputField(alias="@behavior_id", example_values=["7094"])
    description: str | None = OutputField(
        alias="@description",
        example_values=[
            "Sample was identified to a known malware family via fuzzy hash"
        ],
    )
    family: str | None = OutputField(alias="@family", example_values=["unknown"])
    matched_ioc_hash: str | None = OutputField(alias="@matched_ioc_hash")


class SyscallFileOutput(ActionOutput):
    action: str = OutputField(example_values=["read"], alias="@action")
    path: str = OutputField(example_values=["/lib64/helper64.so"], alias="@path")


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


class UdpOutput(ActionOutput):
    country: str = OutputField(alias="@country")


class UrlOutput(ActionOutput):
    host: str = OutputField(alias="@host")
    method: str = OutputField(alias="@method")
    uri: str = OutputField(alias="@uri")
    user_agent: str = OutputField(alias="@user_agent")


class ProcessFileCreatedOutput(ActionOutput):
    md5: str = OutputField(cef_types=["md5", "hash"], alias="@md5")
    name: str = OutputField(cef_types=["file path"], alias="@name")
    size: str = OutputField(alias="@size")
    type: str = OutputField(alias="@type")


class CreatemutexOutput(ActionOutput):
    name: str = OutputField(alias="@name")


class SetOutput(ActionOutput):
    data: str = OutputField(alias="@data")


class ProcessTreeNodeOutput(ActionOutput):
    name: str | None = OutputField(cef_types=["process name"], alias="@name")
    text: str | None = OutputField(alias="@text")


class DefinedReceiversOutput(ActionOutput):
    entry: str = OutputField(
        example_values=[
            "com.ibm.android.analyzer.test.sqlinjection.SqlInjectionReceiver"
        ]
    )


class DefinedSensorsOutput(ActionOutput):
    entry: str = OutputField(example_values=["Receive sensor readings from gps"])


class Upload_File_InfoOutput(ActionOutput):
    filename: str = OutputField(example_values=["Test"])
    filetype: str = OutputField(example_values=["Adobe PDF document"])
    md5: str = OutputField(example_values=["735539f0d18befd6dd13aadd95038c39"])
    sha256: str = OutputField(
        example_values=[
            "79bc86e0e4134a0883655deadda46ce1a8d8e6e98faf8eab17f14d47b8dfbcc2"
        ]
    )
    size: str = OutputField(example_values=["77756"])
    url: str


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


class SuspiciousOutput(ActionOutput):
    entry: list[ElfSuspiciousEntryOutput]


class EvidenceEntryOutput(ActionOutput):
    behavior_id: str | None = OutputField(alias="@behavior_id")
    md5: str | None = OutputField(alias="@md5", cef_types=["md5", "hash"])


class EvidenceFileOutput(ActionOutput):
    entry: list[EvidenceEntryOutput]


class EvidenceOutput(ActionOutput):
    file: EvidenceFileOutput
    mutex: str
    process: str
    registry: str


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


class ProcessFileActivityOutput(ActionOutput):
    create: list[ProcessFileCreatedOutput]


class ProcessRecordOutput(ActionOutput):
    command: str | None = OutputField(alias="@command")
    name: str | None = OutputField(cef_types=["process name"], alias="@name")
    text: str | None = OutputField(alias="@text")
    file: ProcessFileActivityOutput | None
    java_api: str | None
    mutex: ProcessMutexOutput | None
    process_activity: str | None
    registry: ProcessRegistryOutput | None


class ProcessListOutput(ActionOutput):
    process: list[ProcessRecordOutput]


class ProcessTreeEntryOutput(ActionOutput):
    process: ProcessTreeNodeOutput


class StaticAnalysisOutput(ActionOutput):
    Defined_Receivers: DefinedReceiversOutput
    Defined_Sensors: DefinedSensorsOutput
    Embedded_Libraries: str


class SummaryOutput(ActionOutput):
    entry: list[SummaryEntryOutput]


class SyscallOutput(ActionOutput):
    file: list[SyscallFileOutput]


class ReportFileActivityOutput(ActionOutput):
    file_deleted: list[FileDeletedOutput]
    file_written: list[FileWrittenOutput]


class TimelineOutput(ActionOutput):
    entry: list[EntryOutput]


class ElfInfoOutput(ActionOutput):
    Domains: str
    IP_Addresses: str
    Shell_Commands: ShellCommandsOutput
    URLs: str
    suspicious: SuspiciousOutput


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
    SHA1: str = OutputField(
        example_values=["7BD81368B868225BDE96FC1A3FEE59A8EA06296A"], alias="@SHA1"
    )
    SHA256: str = OutputField(
        example_values=[
            "5D3820107210AA11007A7E1BDCA9590916F2C8C52B132CD53A9C83373805C280"
        ],
        alias="@SHA256",
    )
    ip: str = OutputField(cef_types=["ip"], alias="@ip")
    key: str = OutputField(alias="@key")
    pid: str = OutputField(cef_types=["pid"], alias="@pid")
    port: str = OutputField(alias="@port")
    process_image: str = OutputField(cef_types=["process name"], alias="@process_image")
    reg_key: str = OutputField(alias="@reg_key")
    subkey: str = OutputField(alias="@subkey")
    apk_api: ApkApiOutput
    doc_embedded_files: str
    elf_api: str
    elf_info: ElfInfoOutput
    embedded_files: str
    embedded_urls: str
    evidence: EvidenceOutput
    extracted_urls: ExtractedUrlsOutput
    file: ReportFileActivityOutput
    file_info: ApkFileInfoOutput
    malware: str
    md5: str = OutputField(cef_types=["md5", "hash"])
    metadata: MetadataOutput
    network: NetworkOutput
    platform: str
    process_list: ProcessListOutput
    process_tree: list[ProcessTreeEntryOutput]
    sha256: str = OutputField(cef_types=["sha256", "hash"])
    size: str
    software: str
    static_analysis: StaticAnalysisOutput
    summary: SummaryOutput
    syscall: SyscallOutput
    task: str
    timeline: TimelineOutput
    version: str


class TaskInfoOutput(ActionOutput):
    report: list[ReportOutput]


class DetonateFileOutput(PermissiveActionOutput):
    file_info: CommonFileInfoOutput
    task_info: TaskInfoOutput
    upload_file_info: Upload_File_InfoOutput = OutputField(alias="upload-file-info")
    version: str


class DetonateFileSummary(ActionOutput):
    malware: str


def display_detonate_file_report(
    context: ViewContext,
    action: str,
    outputs: list[WildFireReportViewOutput],
) -> dict:
    del action
    return build_report_context(context, outputs, is_url=False)


def _poll_report(client: httpx.Client, asset: Asset, task_id: str) -> dict[str, object]:
    max_attempts = math.ceil(asset.timeout * 60 / POLL_INTERVAL_SECONDS)
    for attempt in range(1, max_attempts + 1):
        logger.progress("Polling attempt %s of %s", attempt, max_attempts)
        response = client.post(
            "get/report",
            data={
                "apikey": asset.api_key,
                "format": "xml",
                "hash": task_id,
            },
        )
        if response.status_code == httpx.codes.NOT_FOUND:
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = response.text.strip() or GET_REPORT_ERRORS.get(
                response.status_code, "N/A"
            )
            raise ActionFailure(
                "REST Api Call returned error, "
                f"status_code: {response.status_code}, "
                f"detail: {detail}"
            ) from exc
        return parse_wildfire_xml(response)
    raise ActionFailure("Reached max polling attempts.")


def detonate_file(
    params: DetonateFileParams, soar: SOARClient, asset: Asset
) -> DetonateFileOutput:
    attachments = soar.vault.get_attachment(
        vault_id=params.vault_id, container_id=soar.get_executing_container_id()
    )
    if not attachments:
        raise ActionFailure("Vault file could not be found with supplied Vault ID")
    attachment = attachments[0]
    file_name = params.file_name or attachment.name
    sha256 = attachment.metadata.get("sha256") or attachment.hash
    if not sha256:
        raise ActionFailure("Unable to get meta info of vault file")
    verify = asset.verify_server_cert if asset.verify_server_cert is not None else True
    base_url = f"{asset.base_url.rstrip('/')}/publicapi/"
    try:
        with httpx.Client(
            base_url=base_url, verify=verify, timeout=WILDFIRE_HTTP_TIMEOUT
        ) as client:
            logger.progress("Checking for prior detonations")
            report_response = client.post(
                "get/report",
                data={
                    "apikey": asset.api_key,
                    "format": "xml",
                    "hash": sha256,
                },
            )
            upload_data: dict[str, object] = {}
            if report_response.status_code == httpx.codes.OK:
                report_data = parse_wildfire_xml(report_response)
            elif report_response.status_code == httpx.codes.NOT_FOUND:
                logger.progress("Uploading the file")
                with attachment.open("rb") as payload:
                    upload_response = client.post(
                        "submit/file",
                        data={"apikey": asset.api_key},
                        files={"file": (file_name, payload)},
                    )
                try:
                    upload_response.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    detail = upload_response.text.strip() or FILE_UPLOAD_ERRORS.get(
                        upload_response.status_code, "N/A"
                    )
                    raise ActionFailure(
                        "REST Api Call returned error, "
                        f"status_code: {upload_response.status_code}, "
                        f"detail: {detail}"
                    ) from exc
                upload_data = parse_wildfire_xml(upload_response)
                upload_info = upload_data.get("upload-file-info")
                if not isinstance(upload_info, dict):
                    raise ActionFailure("Task id not part of response, can't continue")
                task_id = upload_info.get("sha256") or upload_info.get("md5")
                if not isinstance(task_id, str):
                    raise ActionFailure("Task id not part of response, can't continue")
                report_data = _poll_report(client, asset, task_id)
            else:
                try:
                    report_response.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    detail = report_response.text.strip() or GET_REPORT_ERRORS.get(
                        report_response.status_code, "N/A"
                    )
                    raise ActionFailure(
                        "REST Api Call returned error, "
                        f"status_code: {report_response.status_code}, "
                        f"detail: {detail}"
                    ) from exc
                raise ActionFailure("Unable to retrieve prior detonation report")
    except (OSError, httpx.HTTPError) as exc:
        raise ActionFailure(f"REST Api to server failed: {exc}") from exc

    data = normalize_wildfire_report_response({**upload_data, **report_data})
    file_info = report_data.get("file_info")
    malware = file_info.get("malware", "no") if isinstance(file_info, dict) else "no"
    soar.set_message(f"Malware: {malware}")
    soar.set_summary(PermissiveActionOutput(malware=malware))
    return DetonateFileOutput(**data)
