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
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset


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


def get_pcap(params: GetPcapParams, soar: SOARClient, asset: Asset) -> GetPcapOutput:
    raise NotImplementedError()
