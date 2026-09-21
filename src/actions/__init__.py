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
from soar_sdk.app import App

from .test_connectivity import test_connectivity
from .detonate_file import detonate_file
from .detonate_url import detonate_url
from .get_url_reputation import (
    UrlReputationSummary,
    get_url_reputation,
)
from .get_report import GetReportSummary, get_report
from .get_sample import GetFileSummary, get_sample
from .get_pcap import GetPcapSummary, get_pcap
from .save_report import SaveReportSummary, save_report


def register_actions(app: App) -> App:
    """Register all WildFire actions on the provided app."""
    app.test_connectivity()(test_connectivity)
    app.register_action(
        action=detonate_file,
        description="Run the file in the WildFire sandbox and retrieve the analysis results",
        action_type="investigate",
        verbose="This action requires the input file to be present in the vault and therefore takes the vault id as the input parameter.<br>When submitting supported script files, you must specify an accurate filename.<br>Currently the sandbox supports the following file types:<ul><li>PE</li><li>PDF</li><li>Flash</li><li>APK</li><li>JAR/Class</li><li>MS Office files like doc, xls and ppt</li></ul>.",
    )
    app.register_action(
        action=detonate_url,
        description="Submit a single website link for WildFire analysis",
        action_type="investigate",
        verbose="The URL submitted returns a hash, which is then queried in the WildFire database.<br><br>If the hash is present in the WildFire database, then a report will be returned as:<br><ul><li>0: benign</li><li>1: malware</li><li>2: grayware</li><li>4: phishing</li></ul>If not, then a verdict cannot be concluded and one of the following will be returned:<ul><li>-100: pending, the sample exists, but there is currently no verdict</li><li>-101: error</li><li>-102: unknown, cannot find sample record in database</li><li>-103: invalid hash value</li></ul>.",
    )
    app.register_action(
        action=get_url_reputation,
        name="url reputation",
        description="Submit a single website link for WildFire verdict",
        action_type="investigate",
        verbose="The URL submitted returns a hash, which is then queried in the WildFire database.<br><br>The hash will be quieried on the WildFire database, returning one of the following:<br><ul><li>0: benign</li><li>1: malware</li><li>2: grayware</li><li>4: phishing</li></ul>If not, then a verdict cannot be concluded and one of the following will be returned:<ul><li>-100: pending, the sample exists, but there is currently no verdict</li><li>-101: error</li><li>-102: unknown, cannot find sample record in database</li><li>-103: invalid hash value</li></ul>.",
        read_only=True,
        render_as="table",
        summary_type=UrlReputationSummary,
    )
    app.register_action(
        action=get_report,
        description="Query for results of an already completed detonation in WildFire",
        action_type="investigate",
        verbose="Each detonation report in WildFire is denoted by the sha256 and md5 of the file.",
        read_only=True,
        render_as="table",
        summary_type=GetReportSummary,
    )
    app.register_action(
        action=get_sample,
        name="get file",
        description="Download a sample from WildFire and add it to the vault",
        action_type="investigate",
        verbose="Do note that WildFire does not generally store samples that have been uploaded for detonation.",
        render_as="table",
        summary_type=GetFileSummary,
    )
    app.register_action(
        action=get_pcap,
        description="Download the pcap file of a sample from WildFire and add it to the vault",
        action_type="investigate",
        render_as="table",
        summary_type=GetPcapSummary,
    )
    app.register_action(
        action=save_report,
        description="Save a PDF of the detonation report to the vault",
        action_type="investigate",
        render_as="table",
        summary_type=SaveReportSummary,
    )
    return app
