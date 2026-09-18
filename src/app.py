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
from soar_sdk.app import App
from soar_sdk.params import Param, Params
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.asset import BaseAsset, AssetField
from soar_sdk.logging import getLogger

logger = getLogger()


class Asset(BaseAsset):
    base_url: str = AssetField(
        description="Base URL to WildFire service",
        default="https://wildfire.paloaltonetworks.com",
    )
    verify_server_cert: bool | None = AssetField(
        description="Verify server certificate", default=True
    )
    api_key: str = AssetField(description="API Key")
    timeout: float = AssetField(description="Detonate timeout in mins", default=10.0)


app = App(
    name="wildfire-sdkfied",
    app_type="sandbox",
    logo="logo_paloaltonetworks.svg",
    logo_dark="logo_paloaltonetworks_dark.svg",
    product_vendor="Palo Alto Networks",
    product_name="WildFire",
    publisher="Splunk",
    appid="c5aa8f59-6a3e-4031-b321-69068c725c68",
    fips_compliant=True,
    encrypt_cache_state=True,
    encrypt_ingest_state=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    raise NotImplementedError()


class DetonateFileParams(Params):
    vault_id: str = Param(
        description="Vault ID of file to detonate",
        primary=True,
        cef_types=["pe file", "pdf", "flash", "apk", "jar", "doc", "xls", "ppt"],
    )
    file_name: str | None = Param(
        description="Filename to use", primary=True, cef_types=["file name"]
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


class ShellCommandsOutput(ActionOutput):
    entry: str = OutputField(example_values=["/bin/cp /tmp/panwtest /usr/bin/ps"])


class EntryOutput(ActionOutput):
    seq: str = OutputField(alias="@seq")


class SuspiciousOutput(ActionOutput):
    entry: list[EntryOutput]


class ElfInfoOutput(ActionOutput):
    Domains: str
    IP_Addresses: str
    Shell_Commands: ShellCommandsOutput
    URLs: str
    suspicious: SuspiciousOutput


class FileOutput(ActionOutput):
    action: str = OutputField(example_values=["read"], alias="@action")
    path: str = OutputField(example_values=["/lib64/helper64.so"], alias="@path")


class EvidenceOutput(ActionOutput):
    file: FileOutput
    mutex: str
    process: str
    registry: str


class ExtractedUrlsOutput(ActionOutput):
    entry: EntryOutput


class FileDeletedOutput(ActionOutput):
    deleted_file: str = OutputField(alias="@deleted_file")


class FileWrittenOutput(ActionOutput):
    written_file: str = OutputField(alias="@written_file")


class SectionOutput(ActionOutput):
    name: str = OutputField(example_values=[".text"], alias="@name")
    raw_size: str = OutputField(example_values=["36864"], alias="@raw_size")
    virtual_addr: str = OutputField(example_values=["4096"], alias="@virtual_addr")
    virtual_size: str = OutputField(example_values=["36378"], alias="@virtual_size")


class SectionsOutput(ActionOutput):
    section: list[SectionOutput]


class MetadataOutput(ActionOutput):
    compilation_timestamp: str = OutputField(example_values=["2012-12-20 19:14:11"])
    sections: SectionsOutput


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


class NetworkOutput(ActionOutput):
    dns: list[DnsOutput]
    tcp: list[TcpOutput]
    udp: list[UdpOutput]
    url: list[UrlOutput]


class CreateOutput(ActionOutput):
    md5: str = OutputField(cef_types=["md5", "hash"], alias="@md5")
    name: str = OutputField(cef_types=["file path"], alias="@name")
    size: str = OutputField(alias="@size")
    type: str = OutputField(alias="@type")


class CreatemutexOutput(ActionOutput):
    name: str = OutputField(alias="@name")


class MutexOutput(ActionOutput):
    createmutex: list[CreatemutexOutput]


class SetOutput(ActionOutput):
    data: str = OutputField(alias="@data")


class RegistryOutput(ActionOutput):
    set: list[SetOutput]


class ProcessOutput(ActionOutput):
    name: str = OutputField(cef_types=["process name"], alias="@name")
    text: str = OutputField(alias="@text")


class ProcessListOutput(ActionOutput):
    process: list[ProcessOutput]


class ProcessTreeOutput(ActionOutput):
    process: ProcessOutput


class DefinedReceiversOutput(ActionOutput):
    entry: str = OutputField(
        example_values=[
            "com.ibm.android.analyzer.test.sqlinjection.SqlInjectionReceiver"
        ]
    )


class DefinedSensorsOutput(ActionOutput):
    entry: str = OutputField(example_values=["Receive sensor readings from gps"])


class StaticAnalysisOutput(ActionOutput):
    Defined_Receivers: DefinedReceiversOutput
    Defined_Sensors: DefinedSensorsOutput
    Embedded_Libraries: str


class SummaryOutput(ActionOutput):
    entry: list[EntryOutput]


class SyscallOutput(ActionOutput):
    file: list[FileOutput]


class TimelineOutput(ActionOutput):
    entry: list[EntryOutput]


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
    file: FileOutput
    file_info: FileInfoOutput
    malware: str
    md5: str = OutputField(cef_types=["md5", "hash"])
    metadata: MetadataOutput
    network: NetworkOutput
    platform: str
    process_list: ProcessListOutput
    process_tree: list[ProcessTreeOutput]
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


class DetonateFileOutput(ActionOutput):
    file_info: FileInfoOutput
    task_info: TaskInfoOutput
    upload_file_info: Upload_File_InfoOutput
    version: str


@app.action(
    description="Run the file in the WildFire sandbox and retrieve the analysis results",
    action_type="investigate",
    verbose="This action requires the input file to be present in the vault and therefore takes the vault id as the input parameter.<br>When submitting supported script files, you must specify an accurate filename.<br>Currently the sandbox supports the following file types:<ul><li>PE</li><li>PDF</li><li>Flash</li><li>APK</li><li>JAR/Class</li><li>MS Office files like doc, xls and ppt</li></ul>.",
)
def detonate_file(
    params: DetonateFileParams, soar: SOARClient, asset: Asset
) -> DetonateFileOutput:
    raise NotImplementedError()


class DetonateUrlParams(Params):
    url: str = Param(
        description="URL to query. Starts with http:// or https://",
        primary=True,
        cef_types=["url"],
    )
    is_file: bool | None = Param(
        description="True if the URL points to a file (WildFire treats these differently)",
        default=False,
    )


class FileInfoOutput(ActionOutput):
    filetype: str = OutputField(example_values=["PE"])
    malware: str = OutputField(example_values=["yes"])
    md5: str = OutputField(
        cef_types=["md5"], example_values=["04f4f1c83f1e69b1f055202964536f13"]
    )
    sha1: str = OutputField(
        cef_types=["sha1"], example_values=["828f02e6ca4bcf6c30264137f758fbe20dd866db"]
    )
    sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "ca007e3b395688f5f3062729978dcdbadc90d9c3501d9a89c139d11c58d2a15e"
        ],
    )
    size: str = OutputField(example_values=["796268"])


class ArtifactsOutput(ActionOutput):
    object_id: str = OutputField(example_values=["1"])
    package: str = OutputField(
        example_values=["package--c5e1f03a-f162-4792-ced8-102cd8f6d80a"]
    )
    type: str = OutputField(example_values=["artifact-ref"])


class DetectionReasonsOutput(ActionOutput):
    artifacts: list[ArtifactsOutput]
    description: str = OutputField(
        example_values=["Previously identified as malicious"]
    )
    name: str = OutputField(example_values=["known_as_malicious_by_historical_reasons"])
    type: str = OutputField(example_values=["detection-reason"])
    verdict: str = OutputField(example_values=["malware"])


class AnalysisMetadataOutput(ActionOutput):
    analysis_type: str = OutputField(example_values=["combination"])
    conclusion: str = OutputField(example_values=["unknown"])
    description: str = OutputField(
        example_values=["Automated analysis inside a web browser"]
    )
    end_time: str = OutputField(example_values=["2021-04-15T07:31:29.519230471Z"])
    is_automated: bool = OutputField(example_values=[True])
    start_time: str = OutputField(example_values=["2021-04-15T07:31:19.220000028Z"])
    tool_refs: str = OutputField(example_values=["1"])


class MaecObjectsOutput(ActionOutput):
    analysis_metadata: list[AnalysisMetadataOutput]
    id: str = OutputField(
        example_values=["malware-instance--04a3393d-5a51-4517-2b87-a4dc27bb7a30"]
    )
    instance_object_refs: str = OutputField(example_values=["1"])
    type: str = OutputField(example_values=["malware-instance"])


class n0Output(ActionOutput):
    type: str = OutputField(example_values=["ipv4-addr"])
    value: str = OutputField(
        cef_types=["ip", "url"], example_values=["162.144.139.197"]
    )


class n1Output(ActionOutput):
    name: str = OutputField(example_values=["HtmlUnit v2.35"])
    resolves_to_refs: str = OutputField(example_values=["0"])
    type: str = OutputField(example_values=["domain-name"])
    value: str = OutputField(example_values=["mercetruck.com.br"])
    vendor: str = OutputField(
        example_values=["SourceForge Media, LLC dba Slashdot Media"]
    )


class X_Wf_Content_DescriptionOutput(ActionOutput):
    content_size_bytes: float = OutputField(example_values=[10951])
    sniffed_mime_type: str = OutputField(example_values=["text/plain"])


class ExtensionsOutput(ActionOutput):
    http_request_ext: Http_Request_ExtOutput
    x_wf_http_response_ext: X_Wf_Http_Response_ExtOutput


class HashesOutput(ActionOutput):
    SHA_256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "911e9a6ace3f72a878c5a8959c1bb8633913ec2e876ff0b953a0a0e98ed79ed4"
        ],
        alias="SHA-256",
    )


class n10Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n100Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class RequestHeaderOutput(ActionOutput):
    Accept_Language: str = OutputField(
        example_values=["en-US,en;q=0.9"], alias="Accept-Language"
    )
    Referer: str = OutputField(
        cef_types=["url"], example_values=["http://www.mercetruck.com.br/"]
    )
    User_Agent: str = OutputField(
        example_values=[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.71 Safari/537.36"
        ],
        alias="User-Agent",
    )


class Http_Request_ExtOutput(ActionOutput):
    request_header: RequestHeaderOutput
    request_method: str = OutputField(example_values=["get"])
    request_value: str = OutputField(example_values=["/js/typostores/js/app.js"])


class ResponseHeaderOutput(ActionOutput):
    Accept_Ranges: str = OutputField(example_values=["bytes"], alias="Accept-Ranges")
    Connection: str = OutputField(example_values=["Keep-Alive"])
    Content_Length: str = OutputField(example_values=["10951"], alias="Content-Length")
    Content_Type: str = OutputField(
        example_values=["application/javascript"], alias="Content-Type"
    )
    Date: str = OutputField(example_values=["Thu, 15 Apr 2021 07:31:06 GMT"])
    Keep_Alive: str = OutputField(
        example_values=["timeout=5, max=90"], alias="Keep-Alive"
    )
    Last_Modified: str = OutputField(
        example_values=["Mon, 23 Jan 2017 18:59:49 GMT"], alias="Last-Modified"
    )
    Server: str = OutputField(example_values=["Apache"])


class X_Wf_Http_Response_ExtOutput(ActionOutput):
    message_body_data_ref: str = OutputField(example_values=["98"])
    response_code: float = OutputField(example_values=[200])
    response_header: ResponseHeaderOutput


class n101Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.924999Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n102Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n103Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.924999Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n104Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n105Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.924999Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n106Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n107Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.924999Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n108Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n109Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.926Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n11Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["10"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n110Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n111Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.926Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n112Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n113Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.926Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n114Output(ActionOutput):
    type: str = OutputField(example_values=["domain-name"])
    value: str = OutputField(example_values=["www.mercetruck.com.br"])


class n115Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n116Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["114"])
    end: str = OutputField(example_values=["2021-04-15T07:31:09.816999Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n117Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n118Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["114"])
    end: str = OutputField(example_values=["2021-04-15T07:31:10.275Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n119Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n12Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n120Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["114"])
    end: str = OutputField(example_values=["2021-04-15T07:31:10.299Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n121Output(ActionOutput):
    type: str = OutputField(example_values=["x-wf-url-websocket-messages"])


class n122Output(ActionOutput):
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n123Output(ActionOutput):
    page_frame_refs: str = OutputField(example_values=["9"])
    screenshot_ref: str = OutputField(example_values=["122"])
    type: str = OutputField(example_values=["x-wf-url-browser-information"])
    websocket_messages_ref: str = OutputField(example_values=["121"])


class n124Output(ActionOutput):
    type: str = OutputField(example_values=["url"])
    value: str = OutputField(
        cef_types=["url"], example_values=["https://mercetruck.com.br"]
    )


class n125Output(ActionOutput):
    name: str = OutputField(example_values=["Chrome"])
    type: str = OutputField(example_values=["software"])
    vendor: str = OutputField(example_values=["Google Inc."])


class n13Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["12"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n14Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n15Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["14"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n16Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n17Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["16"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n18Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n19Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["18"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n2Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["1"])
    end: str = OutputField(example_values=["2021-04-15T07:31:00.489Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["https"])
    type: str = OutputField(example_values=["network-traffic"])


class n20Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n21Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["20"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n22Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n23Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["22"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n24Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n25Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["24"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n26Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n27Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["26"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n28Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n29Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["28"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n3Output(ActionOutput):
    resolves_to_refs: str = OutputField(example_values=["0"])
    type: str = OutputField(example_values=["domain-name"])
    value: str = OutputField(example_values=["www.mercetruck.com.br"])


class n30Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n31Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["30"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n32Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n33Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["32"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n34Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n35Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["34"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n36Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n37Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["36"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n38Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n39Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["38"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n4Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n40Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n41Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["40"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n42Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n43Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.894999Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n44Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n45Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.894999Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n46Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n47Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.895999Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n48Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n49Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.897Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n5Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:03.762Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n50Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n51Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.897Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n52Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n53Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.897Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n54Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n55Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.897Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n56Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n57Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.898Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n58Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n59Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.898Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n6Output(ActionOutput):
    type: str = OutputField(example_values=["x-wf-url-global-variables"])
    values: str = OutputField(example_values=["yepnope"])


class n60Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n61Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.898999Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n62Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n63Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.898999Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n64Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n65Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.898999Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n66Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n67Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.9Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n68Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n69Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.9Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n7Output(ActionOutput):
    type: str = OutputField(example_values=["x-wf-url-alert-messages"])


class n70Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n71Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.9Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n72Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n73Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.9Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n74Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n75Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.901Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n76Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n77Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.901Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n78Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n79Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.901Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n8Output(ActionOutput):
    type: str = OutputField(example_values=["url"])
    value: str = OutputField(
        cef_types=["url"], example_values=["http://www.mercetruck.com.br/"]
    )


class n80Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n81Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.901Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n82Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n83Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.901999Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n84Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n85Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.92Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n86Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n87Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.921Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n88Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n89Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.921Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n9Output(ActionOutput):
    global_variable_refs: str = OutputField(example_values=["6"])
    is_main: bool = OutputField(example_values=[True])
    observed_alert_refs: str = OutputField(example_values=["7"])
    request_ref: str = OutputField(example_values=["5"])
    type: str = OutputField(example_values=["x-wf-url-page-frame"])
    url_ref: str = OutputField(example_values=["8"])


class n90Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n91Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.921Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n92Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n93Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.924Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n94Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n95Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.924Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n96Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n97Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.924Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class n98Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n99Output(ActionOutput):
    dst_ref: str = OutputField(example_values=["3"])
    end: str = OutputField(example_values=["2021-04-15T07:31:05.924999Z"])
    extensions: ExtensionsOutput
    protocols: str = OutputField(cef_types=["url"], example_values=["http"])
    type: str = OutputField(example_values=["network-traffic"])


class ObservableObjectsOutput(ActionOutput):
    n0: n0Output
    n1: n1Output
    n10: n10Output
    n100: n100Output
    n101: n101Output
    n102: n102Output
    n103: n103Output
    n104: n104Output
    n105: n105Output
    n106: n106Output
    n107: n107Output
    n108: n108Output
    n109: n109Output
    n11: n11Output
    n110: n110Output
    n111: n111Output
    n112: n112Output
    n113: n113Output
    n114: n114Output
    n115: n115Output
    n116: n116Output
    n117: n117Output
    n118: n118Output
    n119: n119Output
    n12: n12Output
    n120: n120Output
    n121: n121Output
    n122: n122Output
    n123: n123Output
    n124: n124Output
    n125: n125Output
    n13: n13Output
    n14: n14Output
    n15: n15Output
    n16: n16Output
    n17: n17Output
    n18: n18Output
    n19: n19Output
    n2: n2Output
    n20: n20Output
    n21: n21Output
    n22: n22Output
    n23: n23Output
    n24: n24Output
    n25: n25Output
    n26: n26Output
    n27: n27Output
    n28: n28Output
    n29: n29Output
    n3: n3Output
    n30: n30Output
    n31: n31Output
    n32: n32Output
    n33: n33Output
    n34: n34Output
    n35: n35Output
    n36: n36Output
    n37: n37Output
    n38: n38Output
    n39: n39Output
    n4: n4Output
    n40: n40Output
    n41: n41Output
    n42: n42Output
    n43: n43Output
    n44: n44Output
    n45: n45Output
    n46: n46Output
    n47: n47Output
    n48: n48Output
    n49: n49Output
    n5: n5Output
    n50: n50Output
    n51: n51Output
    n52: n52Output
    n53: n53Output
    n54: n54Output
    n55: n55Output
    n56: n56Output
    n57: n57Output
    n58: n58Output
    n59: n59Output
    n6: n6Output
    n60: n60Output
    n61: n61Output
    n62: n62Output
    n63: n63Output
    n64: n64Output
    n65: n65Output
    n66: n66Output
    n67: n67Output
    n68: n68Output
    n69: n69Output
    n7: n7Output
    n70: n70Output
    n71: n71Output
    n72: n72Output
    n73: n73Output
    n74: n74Output
    n75: n75Output
    n76: n76Output
    n77: n77Output
    n78: n78Output
    n79: n79Output
    n8: n8Output
    n80: n80Output
    n81: n81Output
    n82: n82Output
    n83: n83Output
    n84: n84Output
    n85: n85Output
    n86: n86Output
    n87: n87Output
    n88: n88Output
    n89: n89Output
    n9: n9Output
    n90: n90Output
    n91: n91Output
    n92: n92Output
    n93: n93Output
    n94: n94Output
    n95: n95Output
    n96: n96Output
    n97: n97Output
    n98: n98Output
    n99: n99Output


class MaecPackagesOutput(ActionOutput):
    id: str = OutputField(
        example_values=["package--639659c2-6125-4089-8d17-e947f570893a"]
    )
    maec_objects: list[MaecObjectsOutput]
    observable_objects: ObservableObjectsOutput
    schema_version: str = OutputField(example_values=["5.0"])
    type: str = OutputField(example_values=["package"])


class PrimaryMalwareInstancesOutput(ActionOutput):
    package__37192805_9038_40ee_e0ee_2eb1c05cd94d: str = OutputField(
        example_values=["malware-instance--8b062e16-d844-4c3f-06cd-84e6be61a46e"],
        alias="package--37192805-9038-40ee-e0ee-2eb1c05cd94d",
    )
    package__639659c2_6125_4089_8d17_e947f570893a: str = OutputField(
        example_values=["malware-instance--04a3393d-5a51-4517-2b87-a4dc27bb7a30"],
        alias="package--639659c2-6125-4089-8d17-e947f570893a",
    )
    package__c5e1f03a_f162_4792_ced8_102cd8f6d80a: str = OutputField(
        example_values=["malware-instance--faf7c05d-e344-452c-4a42-e0c4ce457861"],
        alias="package--c5e1f03a-f162-4792-ced8-102cd8f6d80a",
    )


class ReportOutput(ActionOutput):
    evidence: EvidenceOutput
    malware: str = OutputField(example_values=["no"])
    md5: str = OutputField(
        cef_types=["md5"], example_values=["04f4f1c83f1e69b1f055202964536f13"]
    )
    network: NetworkOutput
    platform: str = OutputField(example_values=["204"])
    process_list: ProcessListOutput
    process_tree: list[ProcessTreeOutput]
    sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "ca007e3b395688f5f3062729978dcdbadc90d9c3501d9a89c139d11c58d2a15e"
        ],
    )
    size: str = OutputField(example_values=["796268"])
    software: str = OutputField(example_values=["PE Static Analyzer"])
    summary: SummaryOutput
    timeline: TimelineOutput
    version: str = OutputField(example_values=["3.0"])


class ResultOutput(ActionOutput):
    analysis_time: str = OutputField(example_values=["2020-08-19T16:57:40Z"])
    report: ReportOutput
    url_type: str = OutputField(example_values=["original"])


class Submit_Link_InfoOutput(ActionOutput):
    md5: str = OutputField(
        cef_types=["md5"], example_values=["ad01ab9b2bcd7f5c859521dbcd680774"]
    )
    sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "14a74b84361079e3c7c927629520d45e836de7b34f23efdcfef4294d010bc03f"
        ],
    )
    url: str = OutputField(
        cef_types=["url"], example_values=["https://www.paloaltonetworks.com"]
    )


class EntryOutput(ActionOutput):
    text: str = OutputField(
        cef_types=["file name"],
        example_values=[
            "Created Process c:\\documents and settings\\administrator\\sample.exe"
        ],
        alias="#text",
    )
    seq: str = OutputField(example_values=["1"], alias="@seq")


class FileOutput(ActionOutput):
    create: list[CreateOutput]


class EvidenceOutput(ActionOutput):
    file: FileOutput
    mutex: str
    process: str
    registry: str


class DnsOutput(ActionOutput):
    query: str = OutputField(
        example_values=["dnsqa-m03.c644a3e76e438794c399ea1ccdb9206b.me"], alias="@query"
    )
    response: str = OutputField(
        cef_types=["ip"], example_values=["82.163.143.56"], alias="@response"
    )
    type: str = OutputField(example_values=["A"], alias="@type")


class TcpOutput(ActionOutput):
    country: str = OutputField(example_values=["GB"], alias="@country")
    ip: str = OutputField(
        cef_types=["ip"], example_values=["82.163.143.56"], alias="@ip"
    )
    port: str = OutputField(example_values=["80"], alias="@port")


class UrlOutput(ActionOutput):
    host: str = OutputField(
        example_values=["dnsqa-m03.c644a3e76e438794c399ea1ccdb9206b.me"], alias="@host"
    )
    method: str = OutputField(example_values=["POST"], alias="@method")
    uri: str = OutputField(example_values=["/QualityCheck/ni5.php"], alias="@uri")
    user_agent: str = OutputField(example_values=["WinHttpClient"], alias="@user_agent")


class NetworkOutput(ActionOutput):
    dns: list[DnsOutput]
    tcp: list[TcpOutput]
    url: list[UrlOutput]


class CreateOutput(ActionOutput):
    key: str = OutputField(example_values=["HKEY_LOCAL_MACHINE"], alias="@key")
    subkey: str = OutputField(
        example_values=["SOFTWARE\\5da059a482fd494db3f252126fbc3d5b"], alias="@subkey"
    )


class CreatemutexOutput(ActionOutput):
    name: str = OutputField(
        example_values=["Local\\RstrMgr3887CAB8-533F-4C85-B0DC-3E5639F8D511"],
        alias="@name",
    )


class MutexOutput(ActionOutput):
    createmutex: list[CreatemutexOutput]


class ProcessActivityOutput(ActionOutput):
    Create: CreateOutput


class SetOutput(ActionOutput):
    data: str = OutputField(
        cef_types=["file path", "md5"], example_values=["1?"], alias="@data"
    )
    key: str = OutputField(
        example_values=[
            "\\REGISTRY\\MACHINE\\SOFTWARE\\5da059a482fd494db3f252126fbc3egs"
        ],
        alias="@key",
    )
    subkey: str = OutputField(example_values=["FX"], alias="@subkey")


class RegistryOutput(ActionOutput):
    create: list[CreateOutput]
    set: list[SetOutput]


class ProcessOutput(ActionOutput):
    name: str = OutputField(
        cef_types=["file name"], example_values=["sample.exe"], alias="@name"
    )
    pid: str = OutputField(example_values=["1880"], alias="@pid")
    text: str = OutputField(
        cef_types=["file path", "file name"],
        example_values=["c:\\documents and settings\\administrator\\sample.exe"],
        alias="@text",
    )
    child: ChildOutput


class ProcessListOutput(ActionOutput):
    process: list[ProcessOutput]


class ChildOutput(ActionOutput):
    process: ProcessOutput


class ProcessTreeOutput(ActionOutput):
    process: ProcessOutput


class SummaryOutput(ActionOutput):
    entry: list[EntryOutput]


class TimelineOutput(ActionOutput):
    entry: list[EntryOutput]


class TaskInfoOutput(ActionOutput):
    report: list[ReportOutput]


class DetonateUrlOutput(ActionOutput):
    file_info: FileInfoOutput
    result: ResultOutput
    submit_link_info: Submit_Link_InfoOutput
    success: bool = OutputField(example_values=[True])
    task_info: TaskInfoOutput
    version: str = OutputField(example_values=["2.0"])


@app.action(
    description="Submit a single website link for WildFire analysis",
    action_type="investigate",
    verbose="The URL submitted returns a hash, which is then queried in the WildFire database.<br><br>If the hash is present in the WildFire database, then a report will be returned as:<br><ul><li>0: benign</li><li>1: malware</li><li>2: grayware</li><li>4: phishing</li></ul>If not, then a verdict cannot be concluded and one of the following will be returned:<ul><li>-100: pending, the sample exists, but there is currently no verdict</li><li>-101: error</li><li>-102: unknown, cannot find sample record in database</li><li>-103: invalid hash value</li></ul>.",
)
def detonate_url(
    params: DetonateUrlParams, soar: SOARClient, asset: Asset
) -> DetonateUrlOutput:
    raise NotImplementedError()


class UrlReputationParams(Params):
    url: str = Param(
        description="URL to query. Starts with http:// or https://",
        primary=True,
        cef_types=["url"],
    )


class UrlReputationOutput(ActionOutput):
    verdict_analysis_time: str = OutputField(example_values=["2021-05-16T15:17:49Z"])
    verdict_code: float = OutputField(example_values=[-102])
    verdict_md5: str = OutputField(cef_types=["md5"])
    verdict_message: str = OutputField(
        example_values=["unknown, cannot find sample record in the WildFire database"]
    )
    verdict_sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "14a74b84361079e3c7c927629520d45e836de7b34f23efdcfef4294d010bc03f"
        ],
    )
    verdict_url: str = OutputField(example_values=["https://www.google.com"])
    verdict_valid: str = OutputField(example_values=["Yes"])


@app.action(
    description="Submit a single website link for WildFire verdict",
    action_type="investigate",
    verbose="The URL submitted returns a hash, which is then queried in the WildFire database.<br><br>The hash will be quieried on the WildFire database, returning one of the following:<br><ul><li>0: benign</li><li>1: malware</li><li>2: grayware</li><li>4: phishing</li></ul>If not, then a verdict cannot be concluded and one of the following will be returned:<ul><li>-100: pending, the sample exists, but there is currently no verdict</li><li>-101: error</li><li>-102: unknown, cannot find sample record in database</li><li>-103: invalid hash value</li></ul>.",
)
def get_url_reputation(
    params: UrlReputationParams, soar: SOARClient, asset: Asset
) -> UrlReputationOutput:
    raise NotImplementedError()


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


class EntryOutput(ActionOutput):
    seq: str = OutputField(alias="@seq")


class FileOutput(ActionOutput):
    create: list[CreateOutput]


class EvidenceOutput(ActionOutput):
    file: FileOutput
    mutex: str
    process: str
    registry: str


class ExtractedUrlsOutput(ActionOutput):
    entry: list[EntryOutput]


class FileDeletedOutput(ActionOutput):
    deleted_file: str = OutputField(alias="@deleted_file")


class FileWrittenOutput(ActionOutput):
    written_file: str = OutputField(alias="@written_file")


class SectionOutput(ActionOutput):
    name: str = OutputField(example_values=[".text"], alias="@name")
    raw_size: str = OutputField(example_values=["36864"], alias="@raw_size")
    virtual_addr: str = OutputField(example_values=["4096"], alias="@virtual_addr")
    virtual_size: str = OutputField(example_values=["36378"], alias="@virtual_size")


class SectionsOutput(ActionOutput):
    section: list[SectionOutput]


class MetadataOutput(ActionOutput):
    compilation_timestamp: str = OutputField(example_values=["2012-12-20 19:14:11"])
    sections: SectionsOutput


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


class NetworkOutput(ActionOutput):
    dns: list[DnsOutput]
    tcp: list[TcpOutput]
    udp: list[UdpOutput]
    url: list[UrlOutput]


class CreateOutput(ActionOutput):
    md5: str = OutputField(cef_types=["md5", "hash"], alias="@md5")
    name: str = OutputField(cef_types=["file path"], alias="@name")
    sha1: str = OutputField(cef_types=["sha1", "hash"], alias="@sha1")
    sha256: str = OutputField(cef_types=["sha256", "hash"], alias="@sha256")
    size: str = OutputField(alias="@size")
    type: str = OutputField(alias="@type")


class CreatemutexOutput(ActionOutput):
    name: str = OutputField(alias="@name")


class MutexOutput(ActionOutput):
    createmutex: list[CreatemutexOutput]


class SetOutput(ActionOutput):
    data: str = OutputField(alias="@data")


class RegistryOutput(ActionOutput):
    set: list[SetOutput]


class ProcessOutput(ActionOutput):
    name: str = OutputField(cef_types=["process name"], alias="@name")


class ProcessListOutput(ActionOutput):
    process: list[ProcessOutput]


class ProcessTreeOutput(ActionOutput):
    process: ProcessOutput


class StaticAnalysisOutput(ActionOutput):
    Defined_Receivers: str
    Defined_Sensors: str
    Defined_Services: str
    Embedded_Libraries: str
    Requested_Permissions: str
    Sensitive_API_Calls_Performed: str


class SummaryOutput(ActionOutput):
    entry: list[EntryOutput]


class TimelineOutput(ActionOutput):
    entry: list[EntryOutput]


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


@app.action(
    description="Query for results of an already completed detonation in WildFire",
    action_type="investigate",
    verbose="Each detonation report in WildFire is denoted by the sha256 and md5 of the file.",
)
def get_report(
    params: GetReportParams, soar: SOARClient, asset: Asset
) -> GetReportOutput:
    raise NotImplementedError()


class GetFileParams(Params):
    hash: str = Param(
        description="Hash of file/sample to download",
        primary=True,
        cef_types=["md5", "sha256", "wildfire task id"],
    )


class GetFileOutput(ActionOutput):
    name: str
    vault_id: str = OutputField(cef_types=["vault id"])


@app.action(
    description="Download a sample from WildFire and add it to the vault",
    action_type="investigate",
    verbose="Do note that WildFire does not generally store samples that have been uploaded for detonation.",
)
def get_sample(params: GetFileParams, soar: SOARClient, asset: Asset) -> GetFileOutput:
    raise NotImplementedError()


class GetPcapParams(Params):
    hash: str = Param(
        description="Hash of file/sample to download pcap of",
        primary=True,
        cef_types=["md5", "sha256", "wildfire task id"],
    )
    platform: str = Param(
        description="Platform of file/sample to download pcap of",
        value_list=[
            "Default",
            "Windows XP, Adobe Reader 9.3.3, Office 2003",
            "Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007",
            "Windows XP, Adobe Reader 11, Flash 11, Office 2010",
            "Windows 7 32-bit, Adobe Reader 11, Flash11, Office 2010",
            "Windows 7 64-bit, Adobe Reader 11, Flash 11, Office 2010",
            "Android 2.3, API 10, avd2.3.1",
            "PDF Static Analyzer",
            "DOC/CDF Static Analyzer",
            "Java/Jar Static Analyzer",
            "Office 2007 Open XML Static Analyzer",
            "Adobe Flash Static Analyzer",
            "PE Static Analyzer",
            "Archives (RAR and 7-Zip files)",
            "Windows XP, Internet Explorer 8, Flash 11",
            "Windows 7, Flash 11, Office 2010",
            "Mac OSX Mountain Lion",
            "Windows 10 64-bit, Adobe Reader 11, Flash 22, Office 2010",
            "RTF Static Analyzer",
            "Max OSX Static Analyzer",
            "APK Static Analyzer",
            "Android 4.1, API 16, avd4.1.1 X86",
            "Android 4.1, API 16, avd4.1.1 ARM",
            "Phishing Static Analyzer",
            "Android 4.3, API 18, avd4.3 ARM",
            "Script Static Analyzer",
            "Windows XP, Internet Explorer 8, Flash 13.0.0.281, Flash 16.0.0.305, Elink Analyzer",
            "Windows 7, Internet Explorer 9, Flash 13.0.0.281, Flash 17.0.0.169, Elink Analyzer",
            "Windows 7, Internet Explorer 10, Flash 16.0.0.305, Flash 17.0.0.169, Elink Analyzer",
            "Windows 7, Internet Explorer 11, Flash 16.0.0.305, Flash 17.0.0.169, Elink Analyzer",
            "Linux (ELF Files)",
            "Linux Script Dynamic Analyzer",
            "Linux Script Static Analyzer",
            "BareMetal Windows 7 x64, Adobe Reader 11, Flash 11, Office 2010",
        ],
    )


class GetPcapOutput(ActionOutput):
    name: str
    vault_id: str = OutputField(cef_types=["vault id"])


@app.action(
    description="Download the pcap file of a sample from WildFire and add it to the vault",
    action_type="investigate",
)
def get_pcap(params: GetPcapParams, soar: SOARClient, asset: Asset) -> GetPcapOutput:
    raise NotImplementedError()


class SaveReportParams(Params):
    id: str = Param(
        description="File MD5 or Sha256 to get the results of",
        primary=True,
        cef_types=["md5", "sha256", "wildfire task id"],
    )


class SaveReportOutput(ActionOutput):
    name: str
    vault_id: str = OutputField(cef_types=["vault id"])


@app.action(
    description="Save a PDF of the detonation report to the vault",
    action_type="investigate",
)
def save_report(
    params: SaveReportParams, soar: SOARClient, asset: Asset
) -> SaveReportOutput:
    raise NotImplementedError()


if __name__ == "__main__":
    app.cli()
