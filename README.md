[comment]: # "Auto-generated SOAR connector documentation"
# WildFire

Publisher: Splunk  
Connector Version: 2\.2\.3  
Product Vendor: Palo Alto Networks  
Product Name: WildFire  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app supports file detonation for forensic file analysis on the Palo Alto Networks WildFire sandbox

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
To enable the access for fetching files from the Wildfire instance, please enable the Licensing API
key by [clicking here](https://support.paloaltonetworks.com/License/LicensingApi/34470) . If the
redirect link is not working, please follow the below mentioned steps for activating the licensing
API key.

1.  Navigate to [Palo Alto Networks Support](https://support.paloaltonetworks.com)
2.  Expand the Assets tab in the left navigation panel
3.  Select Licensing API option in the left navigation panel and activate the licensing API key

**Playbook Backward Compatibility**

-   The list of supported Platforms in **platform** parameter of **Get Pcap** action has been
    updated as mentioned below. Hence, it is requested to the end-user to please update their
    existing playbooks and provide updated values to this action parameter to ensure the correct
    functioning of the playbooks created on the earlier versions of the app.

      

    -   Below mentioned old values are updated to new values:

          

        -   **Win XP, Adobe 9.3.3, Office 2003** -> **Windows XP, Adobe Reader 9.3.3, Office 2003**
        -   **Win XP, Adobe 9.4.0, Flash 10, Office 2007** -> **Windows XP, Adobe Reader 9.4.0,
            Flash 10, Office 2007**
        -   **Win XP, Adobe 11, Flash 11, Office 2010** -> **Windows XP, Adobe Reader 11, Flash 11,
            Office 2010**
        -   **Win 7 32-bit, Adobe 11, Flash11, Office 2010** -> **Windows 7 32-bit, Adobe Reader 11,
            Flash11, Office 20103**
        -   **Win 7 64 bit, Adobe 11, Flash 11, Office 201** -> **Windows 7 64-bit, Adobe Reader 11,
            Flash 11, Office 2010**

    -   **27** new values have been added.

**Detonate File: Filename Parameter**

-   According to the Wildfire documentation: "When submitting supported script files, you must
    specify an accurate filename using the context parameter, otherwise WildFire is unable to parse
    the file and returns a 418 Unsupported File Type response."
-   Please see the following link for more information: [Wildfire API
    Documentation](https://docs.paloaltonetworks.com/wildfire/u-v/wildfire-api/submit-files-and-links-through-the-wildfire-api/submit-a-remote-file-to-wildfire-api.html)

The **timeout** parameter is only useful for fetching the report in detonate actions and 'get
report' action

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Wildfire server. Below are the default
ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a WildFire asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Base URL to WildFire service
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**api\_key** |  required  | password | API Key
**timeout** |  required  | numeric | Detonate timeout in mins

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity\. This action logs into the device to check the connection and credentials  
[detonate file](#action-detonate-file) - Run the file in the WildFire sandbox and retrieve the analysis results  
[detonate url](#action-detonate-url) - Submit a single website link for WildFire analysis  
[url reputation](#action-url-reputation) - Submit a single website link for WildFire verdict  
[get report](#action-get-report) - Query for results of an already completed detonation in WildFire  
[get file](#action-get-file) - Download a sample from WildFire and add it to the vault  
[get pcap](#action-get-pcap) - Download the pcap file of a sample from WildFire and add it to the vault  
[save report](#action-save-report) - Save a PDF of the detonation report to the vault  

## action: 'test connectivity'
Validate the asset configuration for connectivity\. This action logs into the device to check the connection and credentials

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'detonate file'
Run the file in the WildFire sandbox and retrieve the analysis results

Type: **investigate**  
Read only: **True**

This action requires the input file to be present in the vault and therefore takes the vault id as the input parameter\.<br>When submitting supported script files, you must specify an accurate filename\.<br>Currently the sandbox supports the following file types\:<ul><li>PE</li><li>PDF</li><li>Flash</li><li>APK</li><li>JAR/Class</li><li>MS Office files like doc, xls and ppt</li></ul>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Vault ID of file to detonate | string |  `pe file`  `pdf`  `flash`  `apk`  `jar`  `doc`  `xls`  `ppt` 
**file\_name** |  optional  | Filename to use | string |  `file name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_name | string |  `file name` 
action\_result\.parameter\.vault\_id | string |  `pe file`  `pdf`  `flash`  `apk`  `jar`  `doc`  `xls`  `ppt` 
action\_result\.data\.\*\.file\_info\.file\_signer | string | 
action\_result\.data\.\*\.file\_info\.filetype | string | 
action\_result\.data\.\*\.file\_info\.malware | string | 
action\_result\.data\.\*\.file\_info\.md5 | string |  `md5`  `hash` 
action\_result\.data\.\*\.file\_info\.sha1 | string |  `sha1`  `hash` 
action\_result\.data\.\*\.file\_info\.sha256 | string |  `sha256`  `hash` 
action\_result\.data\.\*\.file\_info\.size | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\#text | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@File\_Location | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@SDK | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@SDK\_Status | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@SHA1 | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@SHA256 | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@ip | string |  `ip` 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@key | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@pid | string |  `pid` 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@port | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@process\_image | string |  `process name` 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@reg\_key | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@subkey | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Cert\_File\.\@Format | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Cert\_File\.\@Issuer | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Cert\_File\.\@MD5 | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Cert\_File\.\@Owner | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Embedded\_URLs\.\*\.\@Known\_Malicious\_URL | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Embedded\_URLs\.\*\.\@URL | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Internal\_File\.\*\.\@Format | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_API\_Calls\.\*\.\@API\_Calls | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_API\_Calls\.\*\.\@Description | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Action\_Monitored\.\*\.\@Action | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Action\_Monitored\.\*\.\@Details | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Behavior\.\@Behavior | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Behavior\.\@Description | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Behavior\.\@Target | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Files\.\*\.\@File\_Type | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Files\.\*\.\@Reason | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Pattern\.\*\.\@Description | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Pattern\.\*\.\@Feature | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Strings\.\*\.\@Description | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Strings\.\*\.\@String | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.doc\_embedded\_files | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.elf\_api | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.elf\_info\.Domains | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.elf\_info\.IP\_Addresses | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.elf\_info\.Shell\_Commands\.entry | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.elf\_info\.URLs | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.elf\_info\.suspicious\.entry\.\*\.\@behavior | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.elf\_info\.suspicious\.entry\.\*\.\@behavior\_id | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.elf\_info\.suspicious\.entry\.\*\.\@description | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.elf\_info\.suspicious\.entry\.\*\.\@family | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.elf\_info\.suspicious\.entry\.\*\.\@matched\_ioc\_hash | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.embedded\_files | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.embedded\_urls | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.file | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.file\.entry\.\*\.\@behavior\_id | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.file\.entry\.\*\.\@md5 | string |  `md5`  `hash` 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.file\.entry\.\@behavior\_id | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.file\.entry\.\@md5 | string |  `md5`  `hash` 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.mutex | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.process | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.registry | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.extracted\_urls\.entry\.\*\.\@url | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.extracted\_urls\.entry\.\*\.\@verdict | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.extracted\_urls\.entry\.\@url | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.extracted\_urls\.entry\.\@verdict | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\.file\_deleted\.\*\.\@deleted\_file | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\.file\_written\.\*\.\@written\_file | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.APK\_Certificate | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.APK\_Package\_Name | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.APK\_Signer | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.APK\_Version | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.App\_Icon | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.App\_Name | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.File\_Type | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.Max\_SDK\_Requirement | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.Min\_SDK\_Requirement | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.Repackaged | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.Target\_SDK | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.malware | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.md5 | string |  `md5`  `hash` 
action\_result\.data\.\*\.task\_info\.report\.\*\.metadata\.compilation\_timestamp | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.metadata\.sections\.section\.\*\.\@name | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.metadata\.sections\.section\.\*\.\@raw\_size | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.metadata\.sections\.section\.\*\.\@virtual\_addr | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.metadata\.sections\.section\.\*\.\@virtual\_size | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.dns\.\*\.\@query | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.dns\.\*\.\@response | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.dns\.\*\.\@type | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.tcp\.\*\.\@country | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.udp\.\*\.\@country | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.url\.\*\.\@host | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.url\.\*\.\@method | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.url\.\*\.\@uri | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.url\.\*\.\@user\_agent | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.platform | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.\@command | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.\@name | string |  `process name` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@md5 | string |  `md5`  `hash` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@name | string |  `file path` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@size | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@type | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.java\_api | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.mutex\.createmutex\.\*\.\@name | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.process\_activity | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.registry\.set\.\*\.\@data | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_tree\.\*\.process\.\*\.\@name | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_tree\.\*\.process\.\*\.\@text | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_tree\.\*\.process\.\@name | string |  `process name` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_tree\.\*\.process\.\@text | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.sha256 | string |  `sha256`  `hash` 
action\_result\.data\.\*\.task\_info\.report\.\*\.size | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.software | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.static\_analysis\.Defined\_Receivers\.entry | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.static\_analysis\.Defined\_Sensors\.entry | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.static\_analysis\.Embedded\_Libraries | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.summary\.entry\.\*\.\@behavior | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.summary\.entry\.\*\.\@details | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.summary\.entry\.\*\.\@id | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.summary\.entry\.\*\.\@score | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.syscall\.file\.\*\.\@action | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.syscall\.file\.\*\.\@path | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.task | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.timeline\.entry\.\*\.\@seq | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.version | string | 
action\_result\.data\.\*\.upload\-file\-info\.filename | string | 
action\_result\.data\.\*\.upload\-file\-info\.filetype | string | 
action\_result\.data\.\*\.upload\-file\-info\.md5 | string | 
action\_result\.data\.\*\.upload\-file\-info\.sha256 | string | 
action\_result\.data\.\*\.upload\-file\-info\.size | string | 
action\_result\.data\.\*\.upload\-file\-info\.url | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.malware | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate url'
Submit a single website link for WildFire analysis

Type: **investigate**  
Read only: **True**

The URL submitted returns a hash, which is then queried in the WildFire database\.<br><br>If the hash is present in the WildFire database, then a report will be returned as\:<br><ul><li>0\: benign</li><li>1\: malware</li><li>2\: grayware</li><li>4\: phishing</li></ul>If not, then a verdict cannot be concluded and one of the following will be returned\:<ul><li>\-100\: pending, the sample exists, but there is currently no verdict</li><li>\-101\: error</li><li>\-102\: unknown, cannot find sample record in database</li><li>\-103\: invalid hash value</li></ul>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query\. Starts with http\:// or https\:// | string |  `url` 
**is\_file** |  optional  | True if the URL points to a file \(WildFire treats these differently\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.is\_file | boolean | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.file\_info\.filetype | string | 
action\_result\.data\.\*\.file\_info\.malware | string | 
action\_result\.data\.\*\.file\_info\.md5 | string |  `md5` 
action\_result\.data\.\*\.file\_info\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.file\_info\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.file\_info\.size | string | 
action\_result\.data\.\*\.result\.analysis\_time | string | 
action\_result\.data\.\*\.result\.report\.da\_packages | string | 
action\_result\.data\.\*\.result\.report\.detection\_reasons\.\*\.artifacts\.\*\.object\_id | string | 
action\_result\.data\.\*\.result\.report\.detection\_reasons\.\*\.artifacts\.\*\.package | string | 
action\_result\.data\.\*\.result\.report\.detection\_reasons\.\*\.artifacts\.\*\.type | string | 
action\_result\.data\.\*\.result\.report\.detection\_reasons\.\*\.description | string | 
action\_result\.data\.\*\.result\.report\.detection\_reasons\.\*\.name | string | 
action\_result\.data\.\*\.result\.report\.detection\_reasons\.\*\.type | string | 
action\_result\.data\.\*\.result\.report\.detection\_reasons\.\*\.verdict | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.id | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.maec\_objects\.\*\.analysis\_metadata\.\*\.analysis\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.maec\_objects\.\*\.analysis\_metadata\.\*\.conclusion | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.maec\_objects\.\*\.analysis\_metadata\.\*\.description | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.maec\_objects\.\*\.analysis\_metadata\.\*\.end\_time | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.maec\_objects\.\*\.analysis\_metadata\.\*\.is\_automated | boolean | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.maec\_objects\.\*\.analysis\_metadata\.\*\.start\_time | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.maec\_objects\.\*\.analysis\_metadata\.\*\.tool\_refs | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.maec\_objects\.\*\.id | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.maec\_objects\.\*\.instance\_object\_refs | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.maec\_objects\.\*\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.0\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.0\.value | string |  `ip`  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.1\.name | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.1\.resolves\_to\_refs | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.1\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.1\.value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.1\.vendor | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.10\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.10\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.10\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.100\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.100\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.100\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.100\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.101\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.102\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.102\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.102\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.102\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.103\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.104\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.104\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.104\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.104\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.105\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.106\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.106\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.106\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.106\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.107\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.108\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.108\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.108\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.108\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.109\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.11\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.11\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.110\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.110\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.110\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.110\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.111\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.112\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.112\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.112\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.112\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.113\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.114\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.114\.value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.115\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.115\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.115\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.116\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.116\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.116\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.116\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.116\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.116\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.116\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.117\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.117\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.117\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.118\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.118\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.118\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.118\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.118\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.118\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.118\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.119\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.119\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.119\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.12\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.12\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.12\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.120\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.120\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.120\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.120\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.120\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.120\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.120\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.121\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.122\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.122\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.123\.page\_frame\_refs | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.123\.screenshot\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.123\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.123\.websocket\_messages\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.124\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.124\.value | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.125\.name | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.125\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.125\.vendor | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.13\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.13\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.14\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.14\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.14\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.15\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.15\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.16\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.16\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.16\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.17\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.17\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.18\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.18\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.18\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.19\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.19\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.http\-request\-ext\.request\_header\.Sec\-Fetch\-Mode | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.http\-request\-ext\.request\_header\.Sec\-Fetch\-User | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.http\-request\-ext\.request\_header\.Upgrade\-Insecure\-Requests | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Location | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Transfer\-Encoding | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.2\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.20\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.20\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.20\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.21\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.21\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.22\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.22\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.22\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.23\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.23\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.24\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.24\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.24\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.25\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.25\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.26\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.26\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.26\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.27\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.27\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.28\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.28\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.28\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.29\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.29\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.3\.resolves\_to\_refs | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.3\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.3\.value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.30\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.30\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.30\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.31\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.31\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.32\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.32\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.32\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.33\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.33\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.34\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.34\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.34\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.35\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.35\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.36\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.36\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.36\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.37\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.37\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.38\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.38\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.38\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.39\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.39\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.4\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.4\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.4\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.4\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.40\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.40\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.40\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.41\.artifact\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.41\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.42\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.42\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.42\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.42\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.43\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.44\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.44\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.44\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.44\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.45\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.46\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.46\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.46\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.46\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.47\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.48\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.48\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.48\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.48\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.49\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.http\-request\-ext\.request\_header\.Sec\-Fetch\-Mode | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.http\-request\-ext\.request\_header\.Sec\-Fetch\-User | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.http\-request\-ext\.request\_header\.Upgrade\-Insecure\-Requests | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Cache\-Control | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Expires | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Pragma | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Set\-Cookie | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Transfer\-Encoding | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.X\-Frame\-Options | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.5\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.50\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.50\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.50\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.50\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.51\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.52\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.52\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.52\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.52\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.53\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.54\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.54\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.54\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.54\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.55\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.56\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.56\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.56\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.56\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.57\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.58\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.58\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.58\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.58\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.59\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.6\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.6\.values | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.60\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.60\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.60\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.60\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.61\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.62\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.62\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.62\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.62\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.63\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.64\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.64\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.64\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.64\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.65\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.66\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.66\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.66\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.66\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.67\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.68\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.68\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.68\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.68\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.69\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.7\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.70\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.70\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.70\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.70\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.71\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.72\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.72\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.72\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.72\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.73\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.74\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.74\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.74\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.74\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.75\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.76\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.76\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.76\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.76\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.77\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.78\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.78\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.78\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.78\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.79\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.8\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.8\.value | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.80\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.80\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.80\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.80\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.81\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.82\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.82\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.82\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.82\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.83\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.84\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.84\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.84\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.84\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.85\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.86\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.86\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.86\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.86\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.87\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.88\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.88\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.88\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.88\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.89\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.9\.global\_variable\_refs | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.9\.is\_main | boolean | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.9\.observed\_alert\_refs | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.9\.request\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.9\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.9\.url\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.90\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.90\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.90\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.90\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.91\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.92\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.92\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.92\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.92\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.93\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.94\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.94\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.94\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.94\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.95\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.96\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.96\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.96\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.96\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.97\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.98\.extensions\.x\-wf\-content\-description\.content\_size\_bytes | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.98\.extensions\.x\-wf\-content\-description\.sniffed\_mime\_type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.98\.hashes\.SHA\-256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.98\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.dst\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.end | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.http\-request\-ext\.request\_header\.Accept\-Language | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.http\-request\-ext\.request\_header\.Referer | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.http\-request\-ext\.request\_header\.User\-Agent | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.http\-request\-ext\.request\_method | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.http\-request\-ext\.request\_value | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.x\-wf\-http\-response\-ext\.message\_body\_data\_ref | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.x\-wf\-http\-response\-ext\.response\_code | numeric | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Accept\-Ranges | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Connection | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Length | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Content\-Type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Date | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Keep\-Alive | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Last\-Modified | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.extensions\.x\-wf\-http\-response\-ext\.response\_header\.Server | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.protocols | string |  `url` 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.observable\_objects\.99\.type | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.schema\_version | string | 
action\_result\.data\.\*\.result\.report\.maec\_packages\.\*\.type | string | 
action\_result\.data\.\*\.result\.report\.primary\_malware\_instances\.package\-\-37192805\-9038\-40ee\-e0ee\-2eb1c05cd94d | string | 
action\_result\.data\.\*\.result\.report\.primary\_malware\_instances\.package\-\-639659c2\-6125\-4089\-8d17\-e947f570893a | string | 
action\_result\.data\.\*\.result\.report\.primary\_malware\_instances\.package\-\-c5e1f03a\-f162\-4792\-ced8\-102cd8f6d80a | string | 
action\_result\.data\.\*\.result\.report\.sa\_package | string | 
action\_result\.data\.\*\.result\.report\.schema\_version | string | 
action\_result\.data\.\*\.result\.report\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.result\.report\.type | string | 
action\_result\.data\.\*\.result\.report\.verdict | string | 
action\_result\.data\.\*\.result\.url\_type | string | 
action\_result\.data\.\*\.submit\-link\-info\.md5 | string |  `md5` 
action\_result\.data\.\*\.submit\-link\-info\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.submit\-link\-info\.url | string |  `url` 
action\_result\.data\.\*\.success | boolean | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.file\.entry\.\*\.\#text | string |  `file path`  `file name` 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.file\.entry\.\*\.\@behavior\_id | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.file\.entry\.\*\.\@md5 | string |  `md5` 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.file\.entry\.\*\.\@sha1 | string |  `sha1` 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.file\.entry\.\*\.\@sha256 | string |  `sha256` 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.mutex | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.process | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.registry | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.malware | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.dns\.\*\.\@query | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.dns\.\*\.\@response | string |  `ip` 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.dns\.\*\.\@type | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.tcp\.\*\.\@country | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.tcp\.\*\.\@ip | string |  `ip` 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.tcp\.\*\.\@port | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.url\.\*\.\@host | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.url\.\*\.\@method | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.url\.\*\.\@uri | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.url\.\*\.\@user\_agent | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.platform | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.\@command | string |  `file path`  `file name` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.\@name | string |  `file name` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.\@pid | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@md5 | string |  `md5` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@name | string |  `file path`  `file name` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@sha1 | string |  `sha1` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@sha256 | string |  `sha256` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@size | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@type | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.java\_api | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.mutex\.createmutex\.\*\.\@name | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.process\_activity | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.process\_activity\.Create\.\@child\_pid | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.process\_activity\.Create\.\@child\_process\_image | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.process\_activity\.Create\.\@command | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.registry\.create\.\*\.\@key | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.registry\.create\.\*\.\@subkey | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.registry\.set\.\*\.\@data | string |  `file path`  `md5` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.registry\.set\.\*\.\@key | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.registry\.set\.\*\.\@subkey | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_tree\.\*\.process\.\@name | string |  `file name` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_tree\.\*\.process\.\@pid | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_tree\.\*\.process\.\@text | string |  `file path`  `file name` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_tree\.\*\.process\.child\.process\.\@name | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_tree\.\*\.process\.child\.process\.\@pid | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_tree\.\*\.process\.child\.process\.\@text | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.task\_info\.report\.\*\.size | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.software | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.summary\.entry\.\*\.\#text | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.summary\.entry\.\*\.\@details | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.summary\.entry\.\*\.\@id | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.summary\.entry\.\*\.\@score | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.timeline\.entry\.\*\.\#text | string |  `file name` 
action\_result\.data\.\*\.task\_info\.report\.\*\.timeline\.entry\.\*\.\@seq | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.version | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.md5 | string |  `md5` 
action\_result\.summary\.sha256 | string |  `sha256` 
action\_result\.summary\.summary\_available | boolean | 
action\_result\.summary\.task\_id | string |  `sha256` 
action\_result\.summary\.verdict | string | 
action\_result\.summary\.verdict\_code | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'url reputation'
Submit a single website link for WildFire verdict

Type: **investigate**  
Read only: **True**

The URL submitted returns a hash, which is then queried in the WildFire database\.<br><br>The hash will be quieried on the WildFire database, returning one of the following\:<br><ul><li>0\: benign</li><li>1\: malware</li><li>2\: grayware</li><li>4\: phishing</li></ul>If not, then a verdict cannot be concluded and one of the following will be returned\:<ul><li>\-100\: pending, the sample exists, but there is currently no verdict</li><li>\-101\: error</li><li>\-102\: unknown, cannot find sample record in database</li><li>\-103\: invalid hash value</li></ul>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query\. Starts with http\:// or https\:// | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.verdict\_analysis\_time | string | 
action\_result\.data\.\*\.verdict\_code | numeric | 
action\_result\.data\.\*\.verdict\_md5 | string |  `md5` 
action\_result\.data\.\*\.verdict\_message | string | 
action\_result\.data\.\*\.verdict\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.verdict\_url | string | 
action\_result\.data\.\*\.verdict\_valid | string | 
action\_result\.summary\.success | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get report'
Query for results of an already completed detonation in WildFire

Type: **investigate**  
Read only: **True**

Each detonation report in WildFire is denoted by the sha256 and md5 of the file\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | File MD5 or Sha256 to get the results of | string |  `md5`  `sha256`  `wildfire task id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `md5`  `sha256`  `wildfire task id` 
action\_result\.data\.\*\.file\_info\.file\_signer | string | 
action\_result\.data\.\*\.file\_info\.filetype | string | 
action\_result\.data\.\*\.file\_info\.malware | string | 
action\_result\.data\.\*\.file\_info\.md5 | string |  `md5`  `hash` 
action\_result\.data\.\*\.file\_info\.sha1 | string |  `sha1`  `hash` 
action\_result\.data\.\*\.file\_info\.sha256 | string |  `sha256`  `hash` 
action\_result\.data\.\*\.file\_info\.size | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\#text | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@File\_Location | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@SDK | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@SDK\_Status | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@key | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@md5 | string |  `md5`  `hash` 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@pid | string |  `pid` 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@process\_image | string |  `process name` 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@reg\_key | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@sha1 | string |  `sha1`  `hash` 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@sha256 | string |  `sha256`  `hash` 
action\_result\.data\.\*\.task\_info\.report\.\*\.\@subkey | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Cert\_File\.\@Format | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Cert\_File\.\@Issuer | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Cert\_File\.\@MD5 | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Cert\_File\.\@Owner | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Cert\_File\.\@SHA1 | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Cert\_File\.\@SHA256 | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Embedded\_URLs\.\*\.\@Known\_Malicious\_URL | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Embedded\_URLs\.\*\.\@URL | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Internal\_File\.\*\.\@Format | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Internal\_File\.\*\.\@SHA256 | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_API\_Calls\.\*\.\@API\_Calls | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_API\_Calls\.\*\.\@Description | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Action\_Monitored\.\*\.\@Action | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Action\_Monitored\.\*\.\@Details | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Behavior\.\@Behavior | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Behavior\.\@Description | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Behavior\.\@Target | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Files\.\*\.\@File\_Type | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Files\.\*\.\@Reason | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Pattern\.\*\.\@Description | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Pattern\.\*\.\@Feature | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Strings\.\*\.\@Description | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.apk\_api\.Suspicious\_Strings\.\*\.\@String | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.doc\_embedded\_files | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.embedded\_files | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.embedded\_urls | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.entry | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.file | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.file\.entry\.\*\.\@behavior\_id | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.file\.entry\.\@behavior\_id | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.mutex | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.process | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.evidence\.registry | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.extracted\_urls\.entry\.\*\.\@url | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.extracted\_urls\.entry\.\*\.\@verdict | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\.file\_deleted\.\*\.\@deleted\_file | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\.file\_written\.\*\.\@written\_file | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.APK\_Certificate | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.APK\_Package\_Name | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.APK\_Signer | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.APK\_Version | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.App\_Icon | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.App\_Name | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.File\_Type | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.Max\_SDK\_Requirement | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.Min\_SDK\_Requirement | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.Repackaged | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.Target\_SDK | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.Min\_SDK\_Requirement | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.Repackaged | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.file\_info\.Target\_SDK | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.malware | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.md5 | string |  `md5`  `hash` 
action\_result\.data\.\*\.task\_info\.report\.\*\.metadata\.compilation\_timestamp | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.metadata\.sections\.section\.\*\.\@name | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.metadata\.sections\.section\.\*\.\@raw\_size | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.metadata\.sections\.section\.\*\.\@virtual\_addr | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.metadata\.sections\.section\.\*\.\@virtual\_size | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.dns\.\*\.\@query | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.dns\.\*\.\@response | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.dns\.\*\.\@type | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.tcp\.\*\.\@country | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.tcp\.\*\.\@ip | string |  `ip` 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.tcp\.\*\.\@ja3 | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.tcp\.\*\.\@ja3s | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.tcp\.\*\.\@port | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.udp\.\*\.\@country | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.udp\.\*\.\@ip | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.udp\.\*\.\@port | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.url\.\*\.\@host | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.url\.\*\.\@method | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.url\.\*\.\@uri | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.network\.url\.\*\.\@user\_agent | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.platform | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.\@command | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.\@name | string |  `process name` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@md5 | string |  `md5`  `hash` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@name | string |  `file path` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@sha1 | string |  `sha1`  `hash` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@sha256 | string |  `sha256`  `hash` 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@size | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.file\.create\.\*\.\@type | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.java\_api | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.mutex\.createmutex\.\*\.\@name | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.process\_activity | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_list\.process\.\*\.registry\.set\.\*\.\@data | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_tree\.\*\.process\.\*\.\@name | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_tree\.\*\.process\.\*\.\@text | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.process\_tree\.\*\.process\.\@name | string |  `process name` 
action\_result\.data\.\*\.task\_info\.report\.\*\.sha256 | string |  `sha256`  `hash` 
action\_result\.data\.\*\.task\_info\.report\.\*\.size | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.software | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.static\_analysis\.Defined\_Receivers | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.static\_analysis\.Defined\_Sensors | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.static\_analysis\.Defined\_Services | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.static\_analysis\.Embedded\_Libraries | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.static\_analysis\.Requested\_Permissions | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.static\_analysis\.Sensitive\_API\_Calls\_Performed | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.summary\.entry\.\*\.\@details | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.summary\.entry\.\*\.\@id | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.summary\.entry\.\*\.\@score | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.task | string | 
action\_result\.data\.\*\.task\_info\.report\.\*\.timeline\.entry\.\*\.\@seq | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.malware | string | 
action\_result\.summary\.summary\_available | boolean | 
action\_result\.summary\.verdict | string | 
action\_result\.summary\.verdict\_code | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file'
Download a sample from WildFire and add it to the vault

Type: **investigate**  
Read only: **True**

Do note that WildFire does not generally store samples that have been uploaded for detonation\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash of file/sample to download | string |  `md5`  `sha256`  `wildfire task id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `md5`  `sha256`  `wildfire task id` 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.vault\_id | string |  `vault id` 
action\_result\.summary\.file\_type | string | 
action\_result\.summary\.name | string | 
action\_result\.summary\.vault\_id | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get pcap'
Download the pcap file of a sample from WildFire and add it to the vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash of file/sample to download pcap of | string |  `md5`  `sha256`  `wildfire task id` 
**platform** |  required  | Platform of file/sample to download pcap of | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `md5`  `sha256`  `wildfire task id` 
action\_result\.parameter\.platform | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.vault\_id | string |  `vault id` 
action\_result\.summary\.file\_type | string | 
action\_result\.summary\.name | string | 
action\_result\.summary\.vault\_id | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'save report'
Save a PDF of the detonation report to the vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | File MD5 or Sha256 to get the results of | string |  `md5`  `sha256`  `wildfire task id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `md5`  `sha256`  `wildfire task id` 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.vault\_id | string |  `vault id` 
action\_result\.summary\.file\_type | string | 
action\_result\.summary\.name | string | 
action\_result\.summary\.vault\_id | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 