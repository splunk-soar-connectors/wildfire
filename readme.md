[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2021 Splunk Inc."
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

-   According to the Wildfire documentation: "When submitting supported script files, you must specify 
    an accurate filename using the context parameter, otherwise WildFire is unable to parse the file 
    and returns a 418 Unsupported File Type response." 
-   Please see the following link for more information: [Wildfire API Documentation](https://docs.paloaltonetworks.com/wildfire/u-v/wildfire-api/submit-files-and-links-through-the-wildfire-api)


The **timeout** parameter is only useful for fetching the report in detonate actions and 'get
report' action
