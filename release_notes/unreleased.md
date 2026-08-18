**Unreleased**

* Added **OAuth2 (Strata Cloud Manager)** authentication. The app automatically obtains and refreshes a short-lived access token using a service account (Client ID, Client Secret, and TSG ID) [ESPM-5147]
* Added an **Authentication method** asset setting to choose between OAuth2 and the legacy API key, along with the Client ID, Client Secret, TSG ID, and OAuth2 token URL parameters
* Existing assets that use the static API key continue to work without any changes
