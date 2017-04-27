# --
# File: wildfire_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

WILDFIRE_JSON_BASE_URL = "base_url"
WILDFIRE_JSON_TASK_ID = "task_id"
WILDFIRE_JSON_API_KEY = "api_key"
WILDFIRE_JSON_MALWARE = "malware"
WILDFIRE_JSON_TASK_ID = "id"
WILDFIRE_JSON_URL = "url"
WILDFIRE_JSON_HASH = "hash"
WILDFIRE_JSON_PLATFORM = "platform"
WILDFIRE_JSON_POLL_TIMEOUT_MINS = "timeout"

WILDFIRE_ERR_UNABLE_TO_PARSE_REPLY = "Unable to parse reply from device"
WILDFIRE_ERR_REPLY_FORMAT_KEY_MISSING = "None '{key}' missing in reply from device"
WILDFIRE_ERR_REPLY_NOT_SUCCESS = "REST call returned '{status}'"
WILDFIRE_SUCC_REST_CALL_SUCCEEDED = "REST Api call succeeded"
WILDFIRE_ERR_REST_API = "REST Api Call returned error, status_code: {status_code}, detail: {detail}"

WILDFIRE_TEST_PDF_FILE = "wildfire_test_connectivity.pdf"
WILDFIRE_SLEEP_SECS = 10
WILDFIRE_MSG_REPORT_PENDING = "Report Pending"
WILDFIRE_MSG_MAX_POLLS_REACHED = "Reached max polling attempts. Please use the MD5 or Sha256 of the file as a parameter to <b>get report</b> to query the report status."

# in minutes
WILDFIRE_MAX_TIMEOUT_DEF = 10
