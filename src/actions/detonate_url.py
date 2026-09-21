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
import json
import math
import time

import httpx
import xmltodict
from soar_sdk.abstract import SOARClient
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
POLL_INTERVAL_SECONDS = 5


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


class HashesOutput(ActionOutput):
    SHA_256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "911e9a6ace3f72a878c5a8959c1bb8633913ec2e876ff0b953a0a0e98ed79ed4"
        ],
        alias="SHA-256",
    )


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


class n11Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["10"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n114Output(ActionOutput):
    type: str = OutputField(example_values=["domain-name"])
    value: str = OutputField(example_values=["www.mercetruck.com.br"])


class n121Output(ActionOutput):
    type: str = OutputField(example_values=["x-wf-url-websocket-messages"])


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


class n15Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["14"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n17Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["16"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n19Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["18"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n21Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["20"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n23Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["22"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n25Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["24"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n27Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["26"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n29Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["28"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n3Output(ActionOutput):
    resolves_to_refs: str = OutputField(example_values=["0"])
    type: str = OutputField(example_values=["domain-name"])
    value: str = OutputField(example_values=["www.mercetruck.com.br"])


class n31Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["30"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n33Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["32"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n35Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["34"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n37Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["36"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n39Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["38"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n41Output(ActionOutput):
    artifact_ref: str = OutputField(example_values=["40"])
    type: str = OutputField(example_values=["x-wf-url-resource"])


class n6Output(ActionOutput):
    type: str = OutputField(example_values=["x-wf-url-global-variables"])
    values: str = OutputField(example_values=["yepnope"])


class n7Output(ActionOutput):
    type: str = OutputField(example_values=["x-wf-url-alert-messages"])


class n8Output(ActionOutput):
    type: str = OutputField(example_values=["url"])
    value: str = OutputField(
        cef_types=["url"], example_values=["http://www.mercetruck.com.br/"]
    )


class n9Output(ActionOutput):
    global_variable_refs: str = OutputField(example_values=["6"])
    is_main: bool = OutputField(example_values=[True])
    observed_alert_refs: str = OutputField(example_values=["7"])
    request_ref: str = OutputField(example_values=["5"])
    type: str = OutputField(example_values=["x-wf-url-page-frame"])
    url_ref: str = OutputField(example_values=["8"])


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


class ChildProcessOutput(ActionOutput):
    name: str = OutputField(
        cef_types=["file name"], example_values=["sample.exe"], alias="@name"
    )
    pid: str = OutputField(example_values=["1880"], alias="@pid")
    text: str = OutputField(
        cef_types=["file path", "file name"],
        example_values=["c:\\documents and settings\\administrator\\sample.exe"],
        alias="@text",
    )


class ChildOutput(ActionOutput):
    process: ChildProcessOutput


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


class DetectionReasonsOutput(ActionOutput):
    artifacts: list[ArtifactsOutput]
    description: str = OutputField(
        example_values=["Previously identified as malicious"]
    )
    name: str = OutputField(example_values=["known_as_malicious_by_historical_reasons"])
    type: str = OutputField(example_values=["detection-reason"])
    verdict: str = OutputField(example_values=["malware"])


class MaecObjectsOutput(ActionOutput):
    analysis_metadata: list[AnalysisMetadataOutput]
    id: str = OutputField(
        example_values=["malware-instance--04a3393d-5a51-4517-2b87-a4dc27bb7a30"]
    )
    instance_object_refs: str = OutputField(example_values=["1"])
    type: str = OutputField(example_values=["malware-instance"])


class Http_Request_ExtOutput(ActionOutput):
    request_header: RequestHeaderOutput
    request_method: str = OutputField(example_values=["get"])
    request_value: str = OutputField(example_values=["/js/typostores/js/app.js"])


class X_Wf_Http_Response_ExtOutput(ActionOutput):
    message_body_data_ref: str = OutputField(example_values=["98"])
    response_code: float = OutputField(example_values=[200])
    response_header: ResponseHeaderOutput


class n122Output(ActionOutput):
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class FileOutput(ActionOutput):
    create: list[CreateOutput]


class NetworkOutput(ActionOutput):
    dns: list[DnsOutput]
    tcp: list[TcpOutput]
    url: list[UrlOutput]


class MutexOutput(ActionOutput):
    createmutex: list[CreatemutexOutput]


class ProcessActivityOutput(ActionOutput):
    Create: CreateOutput


class RegistryOutput(ActionOutput):
    create: list[CreateOutput]
    set: list[SetOutput]


class ProcessListOutput(ActionOutput):
    process: list[ProcessOutput]


class ProcessTreeOutput(ActionOutput):
    process: ProcessOutput


class SummaryOutput(ActionOutput):
    entry: list[EntryOutput]


class TimelineOutput(ActionOutput):
    entry: list[EntryOutput]


class ExtensionsOutput(ActionOutput):
    http_request_ext: Http_Request_ExtOutput
    x_wf_http_response_ext: X_Wf_Http_Response_ExtOutput


class EvidenceOutput(ActionOutput):
    file: FileOutput
    mutex: str
    process: str
    registry: str


class n10Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n100Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


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


class n14Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n16Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n18Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


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


class n22Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n24Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n26Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n28Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n30Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n32Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n34Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n36Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n38Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n4Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


class n40Output(ActionOutput):
    extensions: ExtensionsOutput
    hashes: HashesOutput
    type: str = OutputField(example_values=["artifact"])


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


class ResultOutput(ActionOutput):
    analysis_time: str = OutputField(example_values=["2020-08-19T16:57:40Z"])
    report: ReportOutput
    url_type: str = OutputField(example_values=["original"])


class TaskInfoOutput(ActionOutput):
    report: list[ReportOutput]


class MaecPackagesOutput(ActionOutput):
    id: str = OutputField(
        example_values=["package--639659c2-6125-4089-8d17-e947f570893a"]
    )
    maec_objects: list[MaecObjectsOutput]
    observable_objects: ObservableObjectsOutput
    schema_version: str = OutputField(example_values=["5.0"])
    type: str = OutputField(example_values=["package"])


class DetonateUrlOutput(ActionOutput):
    file_info: FileInfoOutput
    result: ResultOutput
    submit_link_info: Submit_Link_InfoOutput
    success: bool = OutputField(example_values=[True])
    task_info: TaskInfoOutput
    version: str = OutputField(example_values=["2.0"])


def display_detonate_url_report(
    context: ViewContext,
    action: str,
    outputs: list[WildFireReportViewOutput],
) -> dict:
    del action
    return build_report_context(context, outputs, is_url=True)


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
    raise ActionFailure(
        "REST Api Call returned error, "
        f"status_code: {response.status_code}, "
        f"detail: {response.text.strip() or 'N/A'}"
    )


def _get_verdict(
    client: httpx.Client, asset: Asset, *, task_id: str | None, url: str | None
) -> tuple[int, str]:
    field, value = ("hash", task_id) if task_id else ("url", url)
    response = client.post(
        "get/verdict",
        data={"apikey": asset.api_key},
        files={field: ("", value)},
    )
    _raise_for_error(response)
    verdict_info = _parse_wildfire_xml(response).get("get-verdict-info")
    if not isinstance(verdict_info, dict):
        raise ActionFailure("Verdict could not be retrieved")
    try:
        verdict_code = int(verdict_info["verdict"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ActionFailure("Verdict could not be retrieved") from exc
    return verdict_code, VERDICT_MESSAGES.get(verdict_code, "unknown verdict code")


def _poll_report(
    client: httpx.Client, asset: Asset, *, task_id: str | None, url: str | None
) -> dict[str, object]:
    max_attempts = math.ceil(asset.timeout * 60 / POLL_INTERVAL_SECONDS)
    report_data = (
        {"apikey": asset.api_key, "format": "xml", "hash": task_id}
        if task_id
        else {"apikey": asset.api_key, "url": url}
    )
    for attempt in range(1, max_attempts + 1):
        logger.progress("Polling attempt %s of %s", attempt, max_attempts)
        response = client.post("get/report", data=report_data)
        if response.status_code == httpx.codes.NOT_FOUND:
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        _raise_for_error(response)
        if task_id:
            return _parse_wildfire_xml(response)
        try:
            report = response.json()
            report_body = report.get("result", {}).get("report")
            if isinstance(report_body, str):
                report["result"]["report"] = json.loads(report_body)
            return report
        except (json.JSONDecodeError, TypeError, AttributeError) as exc:
            raise ActionFailure(f"Unable to parse response as JSON: {exc}") from exc

    raise ActionFailure("Reached max polling attempts.")


def detonate_url(
    params: DetonateUrlParams, soar: SOARClient, asset: Asset
) -> DetonateUrlOutput:
    del soar
    if not params.url.startswith(("http://", "https://")):
        raise ActionFailure("Please provide a valid URL")
    verify = asset.verify_server_cert if asset.verify_server_cert is not None else True
    base_url = f"{asset.base_url.rstrip('/')}/publicapi/"
    timeout = httpx.Timeout(None)
    try:
        with httpx.Client(base_url=base_url, verify=verify, timeout=timeout) as client:
            task_id = None
            if params.is_file:
                response = client.post(
                    "submit/url",
                    data={"apikey": asset.api_key},
                    files={"url": ("", params.url)},
                )
                _raise_for_error(response)
                upload_info = _parse_wildfire_xml(response).get("upload-file-info")
                if not isinstance(upload_info, dict):
                    raise ActionFailure("Task id not part of response, can't continue")
                task_id = upload_info.get("sha256") or upload_info.get("md5")
                if not isinstance(task_id, str):
                    raise ActionFailure("Task id not part of response, can't continue")
                time.sleep(1)

            verdict_code, verdict = _get_verdict(
                client,
                asset,
                task_id=task_id,
                url=None if task_id else params.url,
            )
            summary_available = verdict_code >= 0
            result = ActionResult(
                True,
                (
                    f"Verdict code: {verdict_code}, Verdict: {verdict}, "
                    f"Summary available: {summary_available}"
                ),
                params.model_dump(),
            )
            result.set_summary(
                {
                    "verdict_code": verdict_code,
                    "verdict": verdict,
                    "summary_available": summary_available,
                }
            )
            if summary_available:
                result.add_data(
                    _poll_report(
                        client,
                        asset,
                        task_id=task_id,
                        url=None if task_id else params.url,
                    )
                )
            else:
                result.add_data({})
            return result  # type: ignore[return-value]
    except httpx.HTTPError as exc:
        raise ActionFailure(f"REST Api to server failed: {exc}") from exc
