## Authentication

Select the method with the **Authentication method** asset parameter:

- **API Key (legacy):** the static WildFire API key. Palo Alto is retiring this — static keys stop
  working after **Jan 15, 2027**. Provide the **API Key** parameter.
- **OAuth2 (Strata Cloud Manager):** token-based. Provide **Client ID**, **Client Secret**, and
  **TSG ID**; the app fetches and refreshes a short-lived Bearer token automatically. Leave
  **OAuth2 token URL** at its default unless directed otherwise.

### Migrating to OAuth2 (Strata Cloud Manager)

1. **Identity & Access → Roles:** create a custom role with the `iam.service_account` and
   `iam.custom_role` permissions.
1. **Identity & Access → Access Management:** add a service account with the **All Apps & Services**
   scope and the role above. Save the **Client ID** and **Client Secret** (the secret is shown
   once). The **TSG ID** is the number in the account name
   (`name@<tsg_id>.iam.panserviceaccount.com`).
1. **Configuration → WildFire Settings:** create a WildFire API key and bind it to that service
   account, then wait for its status to reach **Valid**. This requires an Advanced WildFire or
   Prisma Access licence on the tenant — a token whose service account has no bound key is rejected.
1. Enter **Client ID**, **Client Secret**, and **TSG ID** in the asset and run **Test
   Connectivity**.

### Licensing API (API Key method)

To enable the access for fetching files from the Wildfire instance, please enable the Licensing API
key by [clicking here](https://support.paloaltonetworks.com/License/LicensingApi/34470) . If the
redirect link is not working, please follow the below mentioned steps for activating the licensing
API key.

1. Navigate to [Palo Alto Networks Support](https://support.paloaltonetworks.com)
1. Expand the Assets tab in the left navigation panel
1. Select Licensing API option in the left navigation panel and activate the licensing API key

**Playbook Backward Compatibility**

- The list of supported Platforms in **platform** parameter of **Get Pcap** action has been
  updated as mentioned below. Hence, it is requested to the end-user to please update their
  existing playbooks and provide updated values to this action parameter to ensure the correct
  functioning of the playbooks created on the earlier versions of the app.

  - Below mentioned old values are updated to new values:

    - **Win XP, Adobe 9.3.3, Office 2003** -> **Windows XP, Adobe Reader 9.3.3, Office 2003**
    - **Win XP, Adobe 9.4.0, Flash 10, Office 2007** -> **Windows XP, Adobe Reader 9.4.0,
      Flash 10, Office 2007**
    - **Win XP, Adobe 11, Flash 11, Office 2010** -> **Windows XP, Adobe Reader 11, Flash 11,
      Office 2010**
    - **Win 7 32-bit, Adobe 11, Flash11, Office 2010** -> **Windows 7 32-bit, Adobe Reader 11,
      Flash11, Office 20103**
    - **Win 7 64 bit, Adobe 11, Flash 11, Office 201** -> **Windows 7 64-bit, Adobe Reader 11,
      Flash 11, Office 2010**

  - **27** new values have been added.

**Detonate File: Filename Parameter**

- According to the Wildfire documentation: "When submitting supported script files, you must
  specify an accurate filename using the context parameter, otherwise WildFire is unable to parse
  the file and returns a 418 Unsupported File Type response."
- Please see the following link for more information: [Wildfire API
  Documentation](https://docs.paloaltonetworks.com/wildfire/u-v/wildfire-api/submit-files-and-links-through-the-wildfire-api/submit-a-remote-file-to-wildfire-api.html)

The **timeout** parameter is only useful for fetching the report in detonate actions and 'get
report' action

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Wildfire server. Below are the default
ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http | tcp | 80 |
|         https | tcp | 443 |
