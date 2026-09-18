# WildFire

Publisher: Splunk <br>
Connector Version: 4.0.0 <br>
Product Vendor: Palo Alto Networks <br>
Product Name: WildFire <br>
Minimum Product Version: 7.0.0

This app supports file detonation for forensic file analysis on the Palo Alto Networks WildFire sandbox

### Configuration variables

This table lists the configuration variables required to operate WildFire. These variables are specified when configuring a WildFire asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** | required | string | Base URL to WildFire service |
**verify_server_cert** | optional | boolean | Verify server certificate |
**api_key** | required | password | API Key |
**timeout** | required | numeric | Detonate timeout in mins |

### Supported Actions

[test connectivity](#action-test-connectivity) - Upload the bundled test PDF to verify WildFire connectivity. <br>
[detonate file](#action-detonate-file) - Run the file in the WildFire sandbox and retrieve the analysis results <br>
[detonate url](#action-detonate-url) - Submit a single website link for WildFire analysis <br>
[url reputation](#action-url-reputation) - Submit a single website link for WildFire verdict <br>
[get report](#action-get-report) - Query for results of an already completed detonation in WildFire <br>
[get sample](#action-get-sample) - Download a sample from WildFire and add it to the vault <br>
[get pcap](#action-get-pcap) - Download the pcap file of a sample from WildFire and add it to the vault <br>
[save report](#action-save-report) - Save a PDF of the detonation report to the vault

## action: 'test connectivity'

Upload the bundled test PDF to verify WildFire connectivity.

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'detonate file'

Run the file in the WildFire sandbox and retrieve the analysis results

Type: **investigate** <br>
Read only: **False**

This action requires the input file to be present in the vault and therefore takes the vault id as the input parameter.<br>When submitting supported script files, you must specify an accurate filename.<br>Currently the sandbox supports the following file types:<ul><li>PE</li><li>PDF</li><li>Flash</li><li>APK</li><li>JAR/Class</li><li>MS Office files like doc, xls and ppt</li></ul>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID of file to detonate | string | `pe file` `pdf` `flash` `apk` `jar` `doc` `xls` `ppt` |
**file_name** | optional | Filename to use | string | `file name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.vault_id | string | `pe file` `pdf` `flash` `apk` `jar` `doc` `xls` `ppt` | |
action_result.parameter.file_name | string | `file name` | |
action_result.data.\*.file_info.APK_Certificate | string | | E579936D9FCA68C394F3AE8C604EBB4C |
action_result.data.\*.file_info.APK_Package_Name | string | | com.ibm.android.analyzer.test |
action_result.data.\*.file_info.APK_Signer | string | | CN=Android Debug, O=Android, C=US |
action_result.data.\*.file_info.APK_Version | string | | 1.0 |
action_result.data.\*.file_info.App_Icon | string | | res/drawable-ldpi-v4/icon.png |
action_result.data.\*.file_info.App_Name | string | | com.ibm.android.analyzer.test |
action_result.data.\*.file_info.File_Type | string | | APK |
action_result.data.\*.file_info.Max_SDK_Requirement | string | | |
action_result.data.\*.file_info.Min_SDK_Requirement | string | | 11 |
action_result.data.\*.file_info.Repackaged | string | | False |
action_result.data.\*.file_info.Target_SDK | string | | 11 |
action_result.data.\*.task_info.report.\*.#text | string | | |
action_result.data.\*.task_info.report.\*.@File_Location | string | | META-INF/CERT.RSA |
action_result.data.\*.task_info.report.\*.@SDK | string | | |
action_result.data.\*.task_info.report.\*.@SDK_Status | string | | |
action_result.data.\*.task_info.report.\*.@SHA1 | string | | 7BD81368B868225BDE96FC1A3FEE59A8EA06296A |
action_result.data.\*.task_info.report.\*.@SHA256 | string | | 5D3820107210AA11007A7E1BDCA9590916F2C8C52B132CD53A9C83373805C280 |
action_result.data.\*.task_info.report.\*.@ip | string | `ip` | |
action_result.data.\*.task_info.report.\*.@key | string | | |
action_result.data.\*.task_info.report.\*.@pid | string | `pid` | |
action_result.data.\*.task_info.report.\*.@port | string | | |
action_result.data.\*.task_info.report.\*.@process_image | string | `process name` | |
action_result.data.\*.task_info.report.\*.@reg_key | string | | |
action_result.data.\*.task_info.report.\*.@subkey | string | | |
action_result.data.\*.task_info.report.\*.apk_api.Cert_File.@Format | string | | certificate |
action_result.data.\*.task_info.report.\*.apk_api.Cert_File.@Issuer | string | | CN=Android Debug, O=Android, C=US |
action_result.data.\*.task_info.report.\*.apk_api.Cert_File.@MD5 | string | | E579936D9FCA68C394F3AE8C604EBB4C |
action_result.data.\*.task_info.report.\*.apk_api.Cert_File.@Owner | string | | CN=Android Debug, O=Android, C=US |
action_result.data.\*.task_info.report.\*.apk_api.Embedded_URLs.\*.@Known_Malicious_URL | string | | |
action_result.data.\*.task_info.report.\*.apk_api.Embedded_URLs.\*.@URL | string | | https://1.www.s81c.com/i/v17/t/ibm_logo_print.png?s3 |
action_result.data.\*.task_info.report.\*.apk_api.Internal_File.\*.@Format | string | | xml |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_API_Calls.\*.@API_Calls | string | | android/telephony/TelephonyManager;->getDeviceId |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_API_Calls.\*.@Description | string | | APK file invokes sensitive APIs |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Action_Monitored.\*.@Action | string | | APK file displayed a float window |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Action_Monitored.\*.@Details | string | | {'flags': 8454400, 'format': -1, 'height': -1, 'type': 1, 'width': -1} |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Behavior.@Behavior | string | | APK file can send an SMS message |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Behavior.@Description | string | | |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Behavior.@Target | string | | +49 1234 |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Files.\*.@File_Type | string | | ELF |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Files.\*.@Reason | string | | APK file contains native code |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Pattern.\*.@Description | string | | APK file uses java reflection technique;String:\\n|createSubprocess|waitFor|data|android.os.Exec |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Pattern.\*.@Feature | string | | java reflection |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Strings.\*.@Description | string | | APK file contains shell command strings |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Strings.\*.@String | string | | /system/bin/sh |
action_result.data.\*.task_info.report.\*.doc_embedded_files | string | | |
action_result.data.\*.task_info.report.\*.elf_api | string | | |
action_result.data.\*.task_info.report.\*.elf_info.Domains | string | | |
action_result.data.\*.task_info.report.\*.elf_info.IP_Addresses | string | | |
action_result.data.\*.task_info.report.\*.elf_info.Shell_Commands.entry | string | | /bin/cp /tmp/panwtest /usr/bin/ps |
action_result.data.\*.task_info.report.\*.elf_info.URLs | string | | |
action_result.data.\*.task_info.report.\*.elf_info.suspicious.entry.\*.@seq | string | | |
action_result.data.\*.task_info.report.\*.embedded_files | string | | |
action_result.data.\*.task_info.report.\*.embedded_urls | string | | |
action_result.data.\*.task_info.report.\*.evidence.file.@action | string | | read |
action_result.data.\*.task_info.report.\*.evidence.file.@path | string | | /lib64/helper64.so |
action_result.data.\*.task_info.report.\*.evidence.mutex | string | | |
action_result.data.\*.task_info.report.\*.evidence.process | string | | |
action_result.data.\*.task_info.report.\*.evidence.registry | string | | |
action_result.data.\*.task_info.report.\*.extracted_urls.entry.@seq | string | | |
action_result.data.\*.task_info.report.\*.file.@action | string | | read |
action_result.data.\*.task_info.report.\*.file.@path | string | | /lib64/helper64.so |
action_result.data.\*.task_info.report.\*.file_info.APK_Certificate | string | | E579936D9FCA68C394F3AE8C604EBB4C |
action_result.data.\*.task_info.report.\*.file_info.APK_Package_Name | string | | com.ibm.android.analyzer.test |
action_result.data.\*.task_info.report.\*.file_info.APK_Signer | string | | CN=Android Debug, O=Android, C=US |
action_result.data.\*.task_info.report.\*.file_info.APK_Version | string | | 1.0 |
action_result.data.\*.task_info.report.\*.file_info.App_Icon | string | | res/drawable-ldpi-v4/icon.png |
action_result.data.\*.task_info.report.\*.file_info.App_Name | string | | com.ibm.android.analyzer.test |
action_result.data.\*.task_info.report.\*.file_info.File_Type | string | | APK |
action_result.data.\*.task_info.report.\*.file_info.Max_SDK_Requirement | string | | |
action_result.data.\*.task_info.report.\*.file_info.Min_SDK_Requirement | string | | 11 |
action_result.data.\*.task_info.report.\*.file_info.Repackaged | string | | False |
action_result.data.\*.task_info.report.\*.file_info.Target_SDK | string | | 11 |
action_result.data.\*.task_info.report.\*.malware | string | | |
action_result.data.\*.task_info.report.\*.md5 | string | `md5` `hash` | |
action_result.data.\*.task_info.report.\*.metadata.compilation_timestamp | string | | 2012-12-20 19:14:11 |
action_result.data.\*.task_info.report.\*.metadata.sections.section.\*.@name | string | | .text |
action_result.data.\*.task_info.report.\*.metadata.sections.section.\*.@raw_size | string | | 36864 |
action_result.data.\*.task_info.report.\*.metadata.sections.section.\*.@virtual_addr | string | | 4096 |
action_result.data.\*.task_info.report.\*.metadata.sections.section.\*.@virtual_size | string | | 36378 |
action_result.data.\*.task_info.report.\*.network.dns.\*.@query | string | | |
action_result.data.\*.task_info.report.\*.network.dns.\*.@response | string | | |
action_result.data.\*.task_info.report.\*.network.dns.\*.@type | string | | |
action_result.data.\*.task_info.report.\*.network.tcp.\*.@country | string | | |
action_result.data.\*.task_info.report.\*.network.udp.\*.@country | string | | |
action_result.data.\*.task_info.report.\*.network.url.\*.@host | string | | |
action_result.data.\*.task_info.report.\*.network.url.\*.@method | string | | |
action_result.data.\*.task_info.report.\*.network.url.\*.@uri | string | | |
action_result.data.\*.task_info.report.\*.network.url.\*.@user_agent | string | | |
action_result.data.\*.task_info.report.\*.platform | string | | |
action_result.data.\*.task_info.report.\*.process_list.process.\*.@name | string | `process name` | |
action_result.data.\*.task_info.report.\*.process_list.process.\*.@text | string | | |
action_result.data.\*.task_info.report.\*.process_tree.\*.process.@name | string | `process name` | |
action_result.data.\*.task_info.report.\*.process_tree.\*.process.@text | string | | |
action_result.data.\*.task_info.report.\*.sha256 | string | `sha256` `hash` | |
action_result.data.\*.task_info.report.\*.size | string | | |
action_result.data.\*.task_info.report.\*.software | string | | |
action_result.data.\*.task_info.report.\*.static_analysis.Defined_Receivers.entry | string | | com.ibm.android.analyzer.test.sqlinjection.SqlInjectionReceiver |
action_result.data.\*.task_info.report.\*.static_analysis.Defined_Sensors.entry | string | | Receive sensor readings from gps |
action_result.data.\*.task_info.report.\*.static_analysis.Embedded_Libraries | string | | |
action_result.data.\*.task_info.report.\*.summary.entry.\*.@seq | string | | |
action_result.data.\*.task_info.report.\*.syscall.file.\*.@action | string | | read |
action_result.data.\*.task_info.report.\*.syscall.file.\*.@path | string | | /lib64/helper64.so |
action_result.data.\*.task_info.report.\*.task | string | | |
action_result.data.\*.task_info.report.\*.timeline.entry.\*.@seq | string | | |
action_result.data.\*.task_info.report.\*.version | string | | |
action_result.data.\*.upload_file_info.filename | string | | Test |
action_result.data.\*.upload_file_info.filetype | string | | Adobe PDF document |
action_result.data.\*.upload_file_info.md5 | string | | 735539f0d18befd6dd13aadd95038c39 |
action_result.data.\*.upload_file_info.sha256 | string | | 79bc86e0e4134a0883655deadda46ce1a8d8e6e98faf8eab17f14d47b8dfbcc2 |
action_result.data.\*.upload_file_info.size | string | | 77756 |
action_result.data.\*.upload_file_info.url | string | | |
action_result.data.\*.version | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'detonate url'

Submit a single website link for WildFire analysis

Type: **investigate** <br>
Read only: **False**

The URL submitted returns a hash, which is then queried in the WildFire database.<br><br>If the hash is present in the WildFire database, then a report will be returned as:<br><ul><li>0: benign</li><li>1: malware</li><li>2: grayware</li><li>4: phishing</li></ul>If not, then a verdict cannot be concluded and one of the following will be returned:<ul><li>-100: pending, the sample exists, but there is currently no verdict</li><li>-101: error</li><li>-102: unknown, cannot find sample record in database</li><li>-103: invalid hash value</li></ul>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to query. Starts with http:// or https:// | string | `url` |
**is_file** | optional | True if the URL points to a file (WildFire treats these differently) | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` | |
action_result.parameter.is_file | boolean | | |
action_result.data.\*.file_info.filetype | string | | PE |
action_result.data.\*.file_info.malware | string | | yes |
action_result.data.\*.file_info.md5 | string | `md5` | 04f4f1c83f1e69b1f055202964536f13 |
action_result.data.\*.file_info.sha1 | string | `sha1` | 828f02e6ca4bcf6c30264137f758fbe20dd866db |
action_result.data.\*.file_info.sha256 | string | `sha256` | ca007e3b395688f5f3062729978dcdbadc90d9c3501d9a89c139d11c58d2a15e |
action_result.data.\*.file_info.size | string | | 796268 |
action_result.data.\*.result.analysis_time | string | | 2020-08-19T16:57:40Z |
action_result.data.\*.result.report.evidence.file.create.\*.@key | string | | HKEY_LOCAL_MACHINE |
action_result.data.\*.result.report.evidence.file.create.\*.@subkey | string | | SOFTWARE\\5da059a482fd494db3f252126fbc3d5b |
action_result.data.\*.result.report.evidence.mutex | string | | |
action_result.data.\*.result.report.evidence.process | string | | |
action_result.data.\*.result.report.evidence.registry | string | | |
action_result.data.\*.result.report.malware | string | | no |
action_result.data.\*.result.report.md5 | string | `md5` | 04f4f1c83f1e69b1f055202964536f13 |
action_result.data.\*.result.report.network.dns.\*.@query | string | | dnsqa-m03.c644a3e76e438794c399ea1ccdb9206b.me |
action_result.data.\*.result.report.network.dns.\*.@response | string | `ip` | 82.163.143.56 |
action_result.data.\*.result.report.network.dns.\*.@type | string | | A |
action_result.data.\*.result.report.network.tcp.\*.@country | string | | GB |
action_result.data.\*.result.report.network.tcp.\*.@ip | string | `ip` | 82.163.143.56 |
action_result.data.\*.result.report.network.tcp.\*.@port | string | | 80 |
action_result.data.\*.result.report.network.url.\*.@host | string | | dnsqa-m03.c644a3e76e438794c399ea1ccdb9206b.me |
action_result.data.\*.result.report.network.url.\*.@method | string | | POST |
action_result.data.\*.result.report.network.url.\*.@uri | string | | /QualityCheck/ni5.php |
action_result.data.\*.result.report.network.url.\*.@user_agent | string | | WinHttpClient |
action_result.data.\*.result.report.platform | string | | 204 |
action_result.data.\*.result.report.process_list.process.\*.@name | string | `file name` | sample.exe |
action_result.data.\*.result.report.process_list.process.\*.@pid | string | | 1880 |
action_result.data.\*.result.report.process_list.process.\*.@text | string | `file path` `file name` | c:\\documents and settings\\administrator\\sample.exe |
action_result.data.\*.result.report.process_list.process.\*.child.process.@name | string | `file name` | sample.exe |
action_result.data.\*.result.report.process_list.process.\*.child.process.@pid | string | | 1880 |
action_result.data.\*.result.report.process_list.process.\*.child.process.@text | string | `file path` `file name` | c:\\documents and settings\\administrator\\sample.exe |
action_result.data.\*.result.report.process_tree.\*.process.@name | string | `file name` | sample.exe |
action_result.data.\*.result.report.process_tree.\*.process.@pid | string | | 1880 |
action_result.data.\*.result.report.process_tree.\*.process.@text | string | `file path` `file name` | c:\\documents and settings\\administrator\\sample.exe |
action_result.data.\*.result.report.process_tree.\*.process.child.process.@name | string | `file name` | sample.exe |
action_result.data.\*.result.report.process_tree.\*.process.child.process.@pid | string | | 1880 |
action_result.data.\*.result.report.process_tree.\*.process.child.process.@text | string | `file path` `file name` | c:\\documents and settings\\administrator\\sample.exe |
action_result.data.\*.result.report.sha256 | string | `sha256` | ca007e3b395688f5f3062729978dcdbadc90d9c3501d9a89c139d11c58d2a15e |
action_result.data.\*.result.report.size | string | | 796268 |
action_result.data.\*.result.report.software | string | | PE Static Analyzer |
action_result.data.\*.result.report.summary.entry.\*.#text | string | `file name` | Created Process c:\\documents and settings\\administrator\\sample.exe |
action_result.data.\*.result.report.summary.entry.\*.@seq | string | | 1 |
action_result.data.\*.result.report.timeline.entry.\*.#text | string | `file name` | Created Process c:\\documents and settings\\administrator\\sample.exe |
action_result.data.\*.result.report.timeline.entry.\*.@seq | string | | 1 |
action_result.data.\*.result.report.version | string | | 3.0 |
action_result.data.\*.result.url_type | string | | original |
action_result.data.\*.submit_link_info.md5 | string | `md5` | ad01ab9b2bcd7f5c859521dbcd680774 |
action_result.data.\*.submit_link_info.sha256 | string | `sha256` | 14a74b84361079e3c7c927629520d45e836de7b34f23efdcfef4294d010bc03f |
action_result.data.\*.submit_link_info.url | string | `url` | https://www.paloaltonetworks.com |
action_result.data.\*.success | boolean | | True False |
action_result.data.\*.task_info.report.\*.evidence.file.create.\*.@key | string | | HKEY_LOCAL_MACHINE |
action_result.data.\*.task_info.report.\*.evidence.file.create.\*.@subkey | string | | SOFTWARE\\5da059a482fd494db3f252126fbc3d5b |
action_result.data.\*.task_info.report.\*.evidence.mutex | string | | |
action_result.data.\*.task_info.report.\*.evidence.process | string | | |
action_result.data.\*.task_info.report.\*.evidence.registry | string | | |
action_result.data.\*.task_info.report.\*.malware | string | | no |
action_result.data.\*.task_info.report.\*.md5 | string | `md5` | 04f4f1c83f1e69b1f055202964536f13 |
action_result.data.\*.task_info.report.\*.network.dns.\*.@query | string | | dnsqa-m03.c644a3e76e438794c399ea1ccdb9206b.me |
action_result.data.\*.task_info.report.\*.network.dns.\*.@response | string | `ip` | 82.163.143.56 |
action_result.data.\*.task_info.report.\*.network.dns.\*.@type | string | | A |
action_result.data.\*.task_info.report.\*.network.tcp.\*.@country | string | | GB |
action_result.data.\*.task_info.report.\*.network.tcp.\*.@ip | string | `ip` | 82.163.143.56 |
action_result.data.\*.task_info.report.\*.network.tcp.\*.@port | string | | 80 |
action_result.data.\*.task_info.report.\*.network.url.\*.@host | string | | dnsqa-m03.c644a3e76e438794c399ea1ccdb9206b.me |
action_result.data.\*.task_info.report.\*.network.url.\*.@method | string | | POST |
action_result.data.\*.task_info.report.\*.network.url.\*.@uri | string | | /QualityCheck/ni5.php |
action_result.data.\*.task_info.report.\*.network.url.\*.@user_agent | string | | WinHttpClient |
action_result.data.\*.task_info.report.\*.platform | string | | 204 |
action_result.data.\*.task_info.report.\*.process_list.process.\*.@name | string | `file name` | sample.exe |
action_result.data.\*.task_info.report.\*.process_list.process.\*.@pid | string | | 1880 |
action_result.data.\*.task_info.report.\*.process_list.process.\*.@text | string | `file path` `file name` | c:\\documents and settings\\administrator\\sample.exe |
action_result.data.\*.task_info.report.\*.process_list.process.\*.child.process.@name | string | `file name` | sample.exe |
action_result.data.\*.task_info.report.\*.process_list.process.\*.child.process.@pid | string | | 1880 |
action_result.data.\*.task_info.report.\*.process_list.process.\*.child.process.@text | string | `file path` `file name` | c:\\documents and settings\\administrator\\sample.exe |
action_result.data.\*.task_info.report.\*.process_tree.\*.process.@name | string | `file name` | sample.exe |
action_result.data.\*.task_info.report.\*.process_tree.\*.process.@pid | string | | 1880 |
action_result.data.\*.task_info.report.\*.process_tree.\*.process.@text | string | `file path` `file name` | c:\\documents and settings\\administrator\\sample.exe |
action_result.data.\*.task_info.report.\*.process_tree.\*.process.child.process.@name | string | `file name` | sample.exe |
action_result.data.\*.task_info.report.\*.process_tree.\*.process.child.process.@pid | string | | 1880 |
action_result.data.\*.task_info.report.\*.process_tree.\*.process.child.process.@text | string | `file path` `file name` | c:\\documents and settings\\administrator\\sample.exe |
action_result.data.\*.task_info.report.\*.sha256 | string | `sha256` | ca007e3b395688f5f3062729978dcdbadc90d9c3501d9a89c139d11c58d2a15e |
action_result.data.\*.task_info.report.\*.size | string | | 796268 |
action_result.data.\*.task_info.report.\*.software | string | | PE Static Analyzer |
action_result.data.\*.task_info.report.\*.summary.entry.\*.#text | string | `file name` | Created Process c:\\documents and settings\\administrator\\sample.exe |
action_result.data.\*.task_info.report.\*.summary.entry.\*.@seq | string | | 1 |
action_result.data.\*.task_info.report.\*.timeline.entry.\*.#text | string | `file name` | Created Process c:\\documents and settings\\administrator\\sample.exe |
action_result.data.\*.task_info.report.\*.timeline.entry.\*.@seq | string | | 1 |
action_result.data.\*.task_info.report.\*.version | string | | 3.0 |
action_result.data.\*.version | string | | 2.0 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'url reputation'

Submit a single website link for WildFire verdict

Type: **investigate** <br>
Read only: **True**

The URL submitted returns a hash, which is then queried in the WildFire database.<br><br>The hash will be quieried on the WildFire database, returning one of the following:<br><ul><li>0: benign</li><li>1: malware</li><li>2: grayware</li><li>4: phishing</li></ul>If not, then a verdict cannot be concluded and one of the following will be returned:<ul><li>-100: pending, the sample exists, but there is currently no verdict</li><li>-101: error</li><li>-102: unknown, cannot find sample record in database</li><li>-103: invalid hash value</li></ul>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to query. Starts with http:// or https:// | string | `url` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` | |
action_result.data.\*.verdict_analysis_time | string | | 2021-05-16T15:17:49Z |
action_result.data.\*.verdict_code | numeric | | -102 |
action_result.data.\*.verdict_md5 | string | `md5` | |
action_result.data.\*.verdict_message | string | | unknown, cannot find sample record in the WildFire database |
action_result.data.\*.verdict_sha256 | string | `sha256` | 14a74b84361079e3c7c927629520d45e836de7b34f23efdcfef4294d010bc03f |
action_result.data.\*.verdict_url | string | | https://www.google.com |
action_result.data.\*.verdict_valid | string | | Yes |
action_result.summary.success | boolean | | True False |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get report'

Query for results of an already completed detonation in WildFire

Type: **investigate** <br>
Read only: **True**

Each detonation report in WildFire is denoted by the sha256 and md5 of the file.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | File MD5 or Sha256 to get the results of | string | `md5` `sha256` `wildfire task id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `md5` `sha256` `wildfire task id` | |
action_result.data.\*.file_info.APK_Certificate | string | | E579936D9FCA68C394F3AE8C604EBB4C |
action_result.data.\*.file_info.APK_Package_Name | string | | com.ibm.android.analyzer.test |
action_result.data.\*.file_info.APK_Signer | string | | CN=Android Debug, O=Android, C=US |
action_result.data.\*.file_info.APK_Version | string | | 1.0 |
action_result.data.\*.file_info.App_Icon | string | | res/drawable-ldpi-v4/icon.png |
action_result.data.\*.file_info.App_Name | string | | com.ibm.android.analyzer.test |
action_result.data.\*.file_info.File_Type | string | | APK |
action_result.data.\*.file_info.Max_SDK_Requirement | string | | |
action_result.data.\*.file_info.Min_SDK_Requirement | string | | 11 |
action_result.data.\*.file_info.Repackaged | string | | False |
action_result.data.\*.file_info.Target_SDK | string | | 11 |
action_result.data.\*.task_info.report.\*.#text | string | | |
action_result.data.\*.task_info.report.\*.@File_Location | string | | META-INF/CERT.RSA |
action_result.data.\*.task_info.report.\*.@SDK | string | | |
action_result.data.\*.task_info.report.\*.@SDK_Status | string | | |
action_result.data.\*.task_info.report.\*.@key | string | | |
action_result.data.\*.task_info.report.\*.md5 | string | `md5` `hash` | |
action_result.data.\*.task_info.report.\*.@pid | string | `pid` | |
action_result.data.\*.task_info.report.\*.@process_image | string | `process name` | |
action_result.data.\*.task_info.report.\*.@reg_key | string | | |
action_result.data.\*.task_info.report.\*.@sha1 | string | `sha1` `hash` | |
action_result.data.\*.task_info.report.\*.sha256 | string | `sha256` `hash` | |
action_result.data.\*.task_info.report.\*.@subkey | string | | |
action_result.data.\*.task_info.report.\*.apk_api.Cert_File.@Format | string | | certificate |
action_result.data.\*.task_info.report.\*.apk_api.Cert_File.@Issuer | string | | CN=Android Debug, O=Android, C=US |
action_result.data.\*.task_info.report.\*.apk_api.Cert_File.@MD5 | string | | E579936D9FCA68C394F3AE8C604EBB4C |
action_result.data.\*.task_info.report.\*.apk_api.Cert_File.@Owner | string | | CN=Android Debug, O=Android, C=US |
action_result.data.\*.task_info.report.\*.apk_api.Cert_File.@SHA1 | string | | 7BD81368B868225BDE96FC1A3FEE59A8EA06296A |
action_result.data.\*.task_info.report.\*.apk_api.Cert_File.@SHA256 | string | | 5D3820107210AA11007A7E1BDCA9590916F2C8C52B132CD53A9C83373805C280 |
action_result.data.\*.task_info.report.\*.apk_api.Embedded_URLs.\*.@Known_Malicious_URL | string | | |
action_result.data.\*.task_info.report.\*.apk_api.Embedded_URLs.\*.@URL | string | | https://1.www.s81c.com/i/v17/t/ibm_logo_print.png?s3 |
action_result.data.\*.task_info.report.\*.apk_api.Internal_File.\*.@Format | string | | xml |
action_result.data.\*.task_info.report.\*.apk_api.Internal_File.\*.@SHA256 | string | | F9A42AF08FEE0695E3E3825DD4D27011078E6C9FFE237F8990876E6BBE31EA2B |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_API_Calls.\*.@API_Calls | string | | android/telephony/TelephonyManager;->getDeviceId |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_API_Calls.\*.@Description | string | | APK file invokes sensitive APIs |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Action_Monitored.\*.@Action | string | | APK file displayed a float window |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Action_Monitored.\*.@Details | string | | {'flags': 8454400, 'format': -1, 'height': -1, 'type': 1, 'width': -1} |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Behavior.@Behavior | string | | APK file can send an SMS message |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Behavior.@Description | string | | |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Behavior.@Target | string | | +49 1234 |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Files.\*.@File_Type | string | | ELF |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Files.\*.@Reason | string | | APK file contains native code |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Pattern.\*.@Description | string | | APK file uses java reflection technique;String:\\n|createSubprocess|waitFor|data|android.os.Exec |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Pattern.\*.@Feature | string | | java reflection |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Strings.\*.@Description | string | | APK file contains shell command strings |
action_result.data.\*.task_info.report.\*.apk_api.Suspicious_Strings.\*.@String | string | | /system/bin/sh |
action_result.data.\*.task_info.report.\*.doc_embedded_files | string | | |
action_result.data.\*.task_info.report.\*.embedded_files | string | | |
action_result.data.\*.task_info.report.\*.embedded_urls | string | | |
action_result.data.\*.task_info.report.\*.entry | string | | com.panw.panwapktest.MainActivity |
action_result.data.\*.task_info.report.\*.evidence.file.create.\*.@md5 | string | `md5` `hash` | |
action_result.data.\*.task_info.report.\*.evidence.file.create.\*.@name | string | `file path` | |
action_result.data.\*.task_info.report.\*.evidence.file.create.\*.@sha1 | string | `sha1` `hash` | |
action_result.data.\*.task_info.report.\*.evidence.file.create.\*.@sha256 | string | `sha256` `hash` | |
action_result.data.\*.task_info.report.\*.evidence.file.create.\*.@size | string | | |
action_result.data.\*.task_info.report.\*.evidence.file.create.\*.@type | string | | |
action_result.data.\*.task_info.report.\*.evidence.mutex | string | | |
action_result.data.\*.task_info.report.\*.evidence.process | string | | |
action_result.data.\*.task_info.report.\*.evidence.registry | string | | |
action_result.data.\*.task_info.report.\*.extracted_urls.entry.\*.@seq | string | | |
action_result.data.\*.task_info.report.\*.file.create.\*.@md5 | string | `md5` `hash` | |
action_result.data.\*.task_info.report.\*.file.create.\*.@name | string | `file path` | |
action_result.data.\*.task_info.report.\*.file.create.\*.@sha1 | string | `sha1` `hash` | |
action_result.data.\*.task_info.report.\*.file.create.\*.@sha256 | string | `sha256` `hash` | |
action_result.data.\*.task_info.report.\*.file.create.\*.@size | string | | |
action_result.data.\*.task_info.report.\*.file.create.\*.@type | string | | |
action_result.data.\*.task_info.report.\*.file_info.APK_Certificate | string | | E579936D9FCA68C394F3AE8C604EBB4C |
action_result.data.\*.task_info.report.\*.file_info.APK_Package_Name | string | | com.ibm.android.analyzer.test |
action_result.data.\*.task_info.report.\*.file_info.APK_Signer | string | | CN=Android Debug, O=Android, C=US |
action_result.data.\*.task_info.report.\*.file_info.APK_Version | string | | 1.0 |
action_result.data.\*.task_info.report.\*.file_info.App_Icon | string | | res/drawable-ldpi-v4/icon.png |
action_result.data.\*.task_info.report.\*.file_info.App_Name | string | | com.ibm.android.analyzer.test |
action_result.data.\*.task_info.report.\*.file_info.File_Type | string | | APK |
action_result.data.\*.task_info.report.\*.file_info.Max_SDK_Requirement | string | | |
action_result.data.\*.task_info.report.\*.file_info.Min_SDK_Requirement | string | | 11 |
action_result.data.\*.task_info.report.\*.file_info.Repackaged | string | | False |
action_result.data.\*.task_info.report.\*.file_info.Target_SDK | string | | 11 |
action_result.data.\*.task_info.report.\*.malware | string | | |
action_result.data.\*.task_info.report.\*.metadata.compilation_timestamp | string | | 2012-12-20 19:14:11 |
action_result.data.\*.task_info.report.\*.metadata.sections.section.\*.@name | string | | .text |
action_result.data.\*.task_info.report.\*.metadata.sections.section.\*.@raw_size | string | | 36864 |
action_result.data.\*.task_info.report.\*.metadata.sections.section.\*.@virtual_addr | string | | 4096 |
action_result.data.\*.task_info.report.\*.metadata.sections.section.\*.@virtual_size | string | | 36378 |
action_result.data.\*.task_info.report.\*.network.dns.\*.@query | string | | |
action_result.data.\*.task_info.report.\*.network.dns.\*.@response | string | | |
action_result.data.\*.task_info.report.\*.network.dns.\*.@type | string | | |
action_result.data.\*.task_info.report.\*.network.tcp.\*.@country | string | | |
action_result.data.\*.task_info.report.\*.network.tcp.\*.@ip | string | `ip` | |
action_result.data.\*.task_info.report.\*.network.tcp.\*.@ja3 | string | | |
action_result.data.\*.task_info.report.\*.network.tcp.\*.@ja3s | string | | |
action_result.data.\*.task_info.report.\*.network.tcp.\*.@port | string | | |
action_result.data.\*.task_info.report.\*.network.udp.\*.@country | string | | |
action_result.data.\*.task_info.report.\*.network.udp.\*.@ip | string | | |
action_result.data.\*.task_info.report.\*.network.udp.\*.@port | string | | |
action_result.data.\*.task_info.report.\*.network.url.\*.@host | string | | |
action_result.data.\*.task_info.report.\*.network.url.\*.@method | string | | |
action_result.data.\*.task_info.report.\*.network.url.\*.@uri | string | | |
action_result.data.\*.task_info.report.\*.network.url.\*.@user_agent | string | | |
action_result.data.\*.task_info.report.\*.platform | string | | |
action_result.data.\*.task_info.report.\*.process_list.process.\*.@name | string | `process name` | |
action_result.data.\*.task_info.report.\*.process_tree.\*.process.@name | string | `process name` | |
action_result.data.\*.task_info.report.\*.size | string | | |
action_result.data.\*.task_info.report.\*.software | string | | |
action_result.data.\*.task_info.report.\*.static_analysis.Defined_Receivers | string | | |
action_result.data.\*.task_info.report.\*.static_analysis.Defined_Sensors | string | | |
action_result.data.\*.task_info.report.\*.static_analysis.Defined_Services | string | | |
action_result.data.\*.task_info.report.\*.static_analysis.Embedded_Libraries | string | | |
action_result.data.\*.task_info.report.\*.static_analysis.Requested_Permissions | string | | |
action_result.data.\*.task_info.report.\*.static_analysis.Sensitive_API_Calls_Performed | string | | |
action_result.data.\*.task_info.report.\*.summary.entry.\*.@seq | string | | |
action_result.data.\*.task_info.report.\*.task | string | | |
action_result.data.\*.task_info.report.\*.timeline.entry.\*.@seq | string | | |
action_result.data.\*.version | string | | |
action_result.summary.verdict_code | numeric | | |
action_result.summary.verdict | string | | |
action_result.summary.summary_available | boolean | | True False |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get sample'

Download a sample from WildFire and add it to the vault

Type: **investigate** <br>
Read only: **False**

Do note that WildFire does not generally store samples that have been uploaded for detonation.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | Hash of file/sample to download | string | `md5` `sha256` `wildfire task id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.hash | string | `md5` `sha256` `wildfire task id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.vault_id | string | `vault id` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get pcap'

Download the pcap file of a sample from WildFire and add it to the vault

Type: **investigate** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | Hash of file/sample to download pcap of | string | `md5` `sha256` `wildfire task id` |
**platform** | required | Platform of file/sample to download pcap of | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.hash | string | `md5` `sha256` `wildfire task id` | |
action_result.parameter.platform | string | | |
action_result.data.\*.name | string | | |
action_result.data.\*.vault_id | string | `vault id` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'save report'

Save a PDF of the detonation report to the vault

Type: **investigate** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | File MD5 or Sha256 to get the results of | string | `md5` `sha256` `wildfire task id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `md5` `sha256` `wildfire task id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.vault_id | string | `vault id` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
