# File: wildfire_consts.py
#
# Copyright (c) 2016-2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
WILDFIRE_JSON_BASE_URL = "base_url"
WILDFIRE_JSON_TASK_ID = "task_id"
WILDFIRE_JSON_API_KEY = "api_key"  # pragma: allowlist secret
WILDFIRE_JSON_MALWARE = "malware"
WILDFIRE_JSON_TASK_ID = "id"
WILDFIRE_JSON_URL = "url"
WILDFIRE_JSON_HASH = "hash"
WILDFIRE_JSON_PLATFORM = "platform"
WILDFIRE_JSON_POLL_TIMEOUT_MINS = "timeout"

# Authentication configuration
WILDFIRE_JSON_AUTH_METHOD = "auth_method"
WILDFIRE_JSON_CLIENT_ID = "client_id"
WILDFIRE_JSON_CLIENT_SECRET = "client_secret"  # pragma: allowlist secret
WILDFIRE_JSON_TSG_ID = "tsg_id"
WILDFIRE_JSON_AUTH_URL = "auth_url"

# Auth method values (must match the value_list in wildfire.json)
WILDFIRE_AUTH_API_KEY = "API Key (legacy)"  # pragma: allowlist secret
WILDFIRE_AUTH_OAUTH = "OAuth2 (Strata Cloud Manager)"

# OAuth2 client-credentials flow (Strata Cloud Manager)
WILDFIRE_DEFAULT_OAUTH_TOKEN_URL = "https://auth.apps.paloaltonetworks.com/am/oauth2/access_token"
WILDFIRE_OAUTH_GRANT_TYPE = "client_credentials"
WILDFIRE_OAUTH_SCOPE_FORMAT = "tsg_id:{tsg_id}"
# Access tokens have a 15-min TTL; refresh early to avoid mid-request expiry.
WILDFIRE_OAUTH_DEFAULT_TTL_SECS = 15 * 60
WILDFIRE_OAUTH_REFRESH_SKEW_SECS = 120
# Floor on the cached lifetime so a short/misconfigured TTL doesn't force a token fetch per request.
WILDFIRE_OAUTH_MIN_TTL_SECS = 30

WILDFIRE_ERR_UNABLE_TO_PARSE_REPLY = "Unable to parse reply from device"
WILDFIRE_ERR_REPLY_FORMAT_KEY_MISSING = "None '{key}' missing in reply from device"
WILDFIRE_ERR_REPLY_NOT_SUCC = "REST call returned '{status}'"
WILDFIRE_SUCC_REST_CALL_SUCC = "REST Api call succeeded"
WILDFIRE_ERR_REST_API = "REST Api Call returned error, status_code: {status_code}, detail: {detail}"
WILDFIRE_ERR_FILE_NOT_FOUND_IN_VAULT = "File not found in vault"
WILDFIRE_INVALID_INT = "Please provide a valid integer value in the {param}"
WILDFIRE_ERR_INVALID_PARAM = "Please provide a non-zero positive integer in the {param}"
WILDFIRE_ERR_NEGATIVE_INT_PARAM = "Please provide a valid non-negative integer value in the {param}"

# Authentication error messages
WILDFIRE_ERR_MISSING_API_KEY = "'API Key' is required in the asset configuration when 'Authentication method' is 'API Key (legacy)'"
WILDFIRE_ERR_MISSING_OAUTH_CREDS = (
    "'Client ID', 'Client Secret' and 'TSG ID' are all required in the asset configuration "
    "when 'Authentication method' is 'OAuth2 (Strata Cloud Manager)'"
)
WILDFIRE_ERR_TOKEN_FETCH = "Failed to obtain OAuth2 access token from Strata Cloud Manager"
WILDFIRE_ERR_TOKEN_MISSING = "OAuth2 token response did not contain an 'access_token'"

WILDFIRE_TEST_PDF_FILE = "wildfire_test_connectivity.pdf"
WILDFIRE_SLEEP_SECS = 10
WILDFIRE_MESSAGE_REPORT_PENDING = "Report Pending"
WILDFIRE_MESSAGE_MAX_POLLS_REACHED = (
    "Reached max polling attempts. Please use the MD5 or Sha256 of the file as a parameter to <b>get report</b> to query the report status."
)

WILDFIRE_TIMEOUT = "'timeout' action parameter"

# in minutes
WILDFIRE_MAX_TIMEOUT_DEF = 10
