# --
# File: wildfire_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.app import BaseConnector
from phantom.app import ActionResult
try:
    from phantom.vault import Vault
except:
    import phantom.vault as Vault

import phantom.utils as ph_utils

from wildfire_consts import *

# Other imports used by this connector
import os
import time
import inspect
import json
import requests
import xmltodict
import uuid
import re
import magic
import shutil


class WildfireConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_DETONATE_FILE = "detonate_file"
    ACTION_ID_DETONATE_URL = "detonate_url"
    ACTION_ID_GET_REPORT = "get_report"
    ACTION_ID_GET_SAMPLE = "get_sample"
    ACTION_ID_GET_PCAP = "get_pcap"
    ACTION_ID_SAVE_REPORT = "save_report"
    ACTION_ID_TEST_ASSET_CONNECTIVITY = 'test_asset_connectivity'

    MAGIC_FORMATS = [
      (re.compile('^PE.* Windows'), ['pe file'], '.exe'),
      (re.compile('^MS-DOS executable'), ['pe file'], '.exe'),
      (re.compile('^PDF '), ['pdf'], '.pdf'),
      (re.compile('^MDMP crash'), ['process dump'], '.dmp'),
      (re.compile('^Macromedia Flash'), ['flash'], '.flv'),
      (re.compile('^tcpdump capture'), ['pcap'], '.pcap'),
    ]

    FILE_UPLOAD_ERROR_DESC = {
            '401': 'API key invalid',
            '405': 'HTTP method Not Allowed',
            '413': 'Sample file size over max limit',
            '418': 'Sample file type is not supported',
            '419': 'Max number of uploads per day exceeded',
            '422': 'URL download error',
            '500': 'Internal error',
            '513': 'File upload failed'}

    GET_REPORT_ERROR_DESC = {
            '401': 'API key invalid',
            '404': 'The report was not found',
            '405': 'HTTP method Not Allowed',
            '419': 'Request report quota exceeded',
            '420': 'Insufficient arguments',
            '421': 'Invalid arguments',
            '500': 'Internal error'}

    GET_SAMPLE_ERROR_DESC = {
            '401': 'API key invalid',
            '403': 'Permission Denied',
            '404': 'The sample was not found',
            '405': 'HTTP method Not Allowed',
            '419': 'Request sample quota exceeded',
            '420': 'Insufficient arguments',
            '421': 'Invalid arguments',
            '500': 'Internal error'}

    GET_PCAP_ERROR_DESC = {
            '401': 'API key invalid',
            '403': 'Permission Denied',
            '404': 'The pcap was not found',
            '405': 'HTTP method Not Allowed',
            '419': 'Request sample quota exceeded',
            '420': 'Insufficient arguments',
            '421': 'Invalid arguments',
            '500': 'Internal error'}

    PLATFORM_ID_MAPPING = {
            'Default': None,
            'Win XP, Adobe 9.3.3, Office 2003': 1,
            'Win XP, Adobe 9.4.0, Flash 10, Office 2007': 2,
            'Win XP, Adobe 11, Flash 11, Office 2010': 3,
            'Win 7 32-bit, Adobe 11, Flash11, Office 2010': 4,
            'Win 7 64 bit, Adobe 11, Flash 11, Office 2010': 5,
            'Android 2.3, API 10, avd2.3.1': 201}

    def __init__(self):

        # Call the BaseConnectors init first
        super(WildfireConnector, self).__init__()

        self._api_token = None

    def initialize(self):

        config = self.get_config()

        # Base URL
        self._base_url = config[WILDFIRE_JSON_BASE_URL]
        if (self._base_url.endswith('/')):
            self._base_url = self._base_url[:-1]

        self._host = self._base_url[self._base_url.find('//') + 2:]

        self._base_url += '/publicapi'

        self._req_sess = requests.Session()

        return phantom.APP_SUCCESS

    def _parse_report_status_msg(self, response, action_result):

        reports = response.get('task_info', {}).get('report', [])

        if (not reports):
            return None

        if (type(reports) != list):
            reports = [reports]

        response['task_info']['report'] = reports

        for report in reports:

            report['network'] = self._normalize_children_into_list(report.get('network'))
            report['timeline'] = self._normalize_children_into_list(report.get('timeline'))
            report['process'] = self._normalize_children_into_list(report.get('process_created'))
            # self._normalize_into_list(report, 'process_list')
            self._normalize_into_list(report, 'process_tree')
            report['summary'] = self._normalize_children_into_list(report.get('summary'))
            report['process_list'] = self._normalize_children_into_list(report.get('process_list'))

            try:
                processes = report['process_list']['process']
            except:
                processes = []

            for process in processes:
                process['service'] = self._normalize_children_into_list(process.get('service'))
                process['registry'] = self._normalize_children_into_list(process.get('registry'))
                process['file'] = self._normalize_children_into_list(process.get('file'))
                process['mutex'] = self._normalize_children_into_list(process.get('mutex'))

            # need to modify the summary to contain a dictionary
            sum_entries = report.get('summary', {}).get('entry')
            if (sum_entries):
                for i, entry in enumerate(sum_entries):
                    if (type(entry) != dict):
                        sum_entries[i] = {'#text': entry, '@details': 'N/A', '@score': 'N/A', '@id': 'N/A'}

            report['registry'] = self._normalize_children_into_list(report.get('registry'))
            report['file'] = self._normalize_children_into_list(report.get('file'))

        return response

    def _parse_error(self, response, result, error_desc):

        status_code = response.status_code
        detail = response.text

        if (detail):
            return result.set_status(phantom.APP_ERROR, WILDFIRE_ERR_REST_API.format(status_code=status_code, detail=detail))

        if (not error_desc):
           return result.set_status(phantom.APP_ERROR, WILDFIRE_ERR_REST_API.format(status_code=status_code, detail='N/A'))

        detail = error_desc.get(str(status_code))

        if (not detail):
            # no detail
            return result.set_status(phantom.APP_ERROR, WILDFIRE_ERR_REST_API.format(status_code=status_code, detail='N/A'))

        return result.set_status(phantom.APP_ERROR, WILDFIRE_ERR_REST_API.format(status_code=status_code, detail=detail))

    def _make_rest_call(self, endpoint, result, error_desc, method="get", params={}, data={}, files=None, parse_response=True, additional_succ_codes={}):

        url = "{0}{1}".format(self._base_url, endpoint)

        config = self.get_config()

        request_func = getattr(self._req_sess, method)

        if (not request_func):
            return (result.set_status(phantom.APP_ERROR, "Invalid method call: {0} for requests module".format(method)), None)

        data.update({'apikey': config[WILDFIRE_JSON_API_KEY]})

        try:
            r = request_func(url, params=params, data=data, files=files, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            return (result.set_status(phantom.APP_ERROR, "REST Api to server failed", e), None)

        # It's ok if r.text is None, dump that
        if (hasattr(result, 'add_debug_data')):
            result.add_debug_data({'r_text': r.text if r else 'r is None'})

        if (r.status_code in additional_succ_codes):
            response = additional_succ_codes[r.status_code]
            return (phantom.APP_SUCCESS, response if response is not None else r.text)

        # Look for errors
        if (r.status_code != requests.codes.ok):  # pylint: disable=E1101
            self._parse_error(r, result, error_desc)
            return (result.get_status(), r.text)

        if (not parse_response):
            return (phantom.APP_SUCCESS, r)

        xml = r.text

        try:
            response_dict = xmltodict.parse(xml)
        except Exception as e:
            self.save_progress(WILDFIRE_ERR_UNABLE_TO_PARSE_REPLY)
            return (result.set_status(phantom.APP_ERROR, WILDFIRE_ERR_UNABLE_TO_PARSE_REPLY, e), None)

        if ('wildfire' not in response_dict):
            return result.set_status(phantom.APP_ERROR, WILDFIRE_ERR_REPLY_FORMAT_KEY_MISSING.format(key='wildfire'))

        response_dict = json.loads(json.dumps(response_dict))

        return (phantom.APP_SUCCESS, response_dict['wildfire'])

    def _get_file_dict(self, param, action_result):

        vault_id = param['vault_id']

        filename = param.get('file_name')
        if not filename:
            filename = vault_id

        try:
            if (hasattr(Vault, 'get_file_path')):
                payload = open(Vault.get_file_path(vault_id), 'rb')
            else:
                payload = open(Vault.get_vault_file(vault_id), 'rb')  # pylint: disable=E1101
        except:
            return (action_result.set_status(phantom.APP_ERROR, 'File not found in vault ("{}")'.format(vault_id)), None)

        files = {'file': (filename, payload)}

        return (phantom.APP_SUCCESS, files)

    def _test_connectivity(self, param):

        # get the file from the app directory
        dirpath = os.path.dirname(inspect.getfile(self.__class__))
        filename = WILDFIRE_TEST_PDF_FILE

        filepath = "{}/{}".format(dirpath, filename)

        try:
            payload = open(filepath, 'rb')
        except:
           self.set_status(phantom.APP_ERROR, 'Test pdf file not found at "{}"'.format(filepath))
           self.append_to_message('Test Connectivity failed')
           return self.get_status()

        self.save_progress('Detonating test pdf file for checking connectivity')

        files = {'file': (filename, payload)}

        ret_val, response = self._make_rest_call('/submit/file', self, self.FILE_UPLOAD_ERROR_DESC, method='post', files=files)

        if (phantom.is_fail(ret_val)):
            self.append_to_message('Test Connectivity Failed')
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, 'Test Connectivity Passed')

    def _normalize_into_list(self, input_dict, key):

        if (not input_dict):
            return None

        if (key not in input_dict):
            return None

        if (type(input_dict[key] != list)):
            input_dict[key] = [input_dict[key]]
        input_dict[key.lower()] = input_dict.pop(key)

        return input_dict

    def _normalize_children_into_list(self, input_dict):

        if (not input_dict):
            return {}

        for key in input_dict.keys():
            if (type(input_dict[key]) != list):
                input_dict[key] = [input_dict[key]]
            input_dict[key.lower()] = input_dict.pop(key)

        return input_dict

    def _check_detonated_report(self, task_id, action_result):
        """This function is different than other functions that get the report
        since it is supposed to check just once and return, also treat a 404 as error
        """

        data = {'format': 'xml', 'hash': task_id}

        ret_val, response = self._make_rest_call('/get/report', action_result, self.GET_REPORT_ERROR_DESC, method='post', data=data)

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        # parse if successfull
        response = self._parse_report_status_msg(response, action_result)

        if (response):
            return (phantom.APP_SUCCESS, response)

        return (phantom.APP_ERROR, None)

    def _poll_task_status(self, task_id, action_result):

        polling_attempt = 0

        config = self.get_config()

        timeout = config[WILDFIRE_JSON_POLL_TIMEOUT_MINS]

        if (not timeout):
            timeout = WILDFIRE_MAX_TIMEOUT_DEF

        max_polling_attempts = (int(timeout) * 60) / WILDFIRE_SLEEP_SECS

        data = {'format': 'xml', 'hash': task_id}

        while (polling_attempt < max_polling_attempts):

            polling_attempt += 1

            self.save_progress("Polling attempt {0} of {1}".format(polling_attempt, max_polling_attempts))

            ret_val, response = self._make_rest_call('/get/report', action_result, self.GET_REPORT_ERROR_DESC, method='post', data=data,
                    additional_succ_codes={404: WILDFIRE_MSG_REPORT_PENDING})

            if (phantom.is_fail(ret_val)):
                return (action_result.get_status(), None)

            if (WILDFIRE_MSG_REPORT_PENDING in response):
                time.sleep(WILDFIRE_SLEEP_SECS)
                continue

            if (phantom.is_success(ret_val)):

                # parse if successfull
                response = self._parse_report_status_msg(response, action_result)

                if (response):
                    return (phantom.APP_SUCCESS, response)

            time.sleep(WILDFIRE_SLEEP_SECS)

        self.save_progress("Reached max polling attempts.")

        return (action_result.set_status(phantom.APP_ERROR, WILDFIRE_MSG_MAX_POLLS_REACHED), None)

    def _get_report(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        task_id = param[WILDFIRE_JSON_TASK_ID]

        # Now poll for the result
        ret_val, response = self._poll_task_status(task_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        data = action_result.add_data({})

        # The next part is the report
        data.update(response)

        malware = data.get('file_info', {}).get('malware', 'no')

        action_result.update_summary({WILDFIRE_JSON_MALWARE: malware})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _save_file_to_vault(self, action_result, response, sample_hash):

        # Create a tmp directory on the vault partition
        guid = uuid.uuid4()
        local_dir = '/vault/tmp/{}'.format(guid)
        self.save_progress("Using temp directory: {0}".format(guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to create temporary folder '/vault/tmp'.", e)

        file_path = "{0}/{1}".format(local_dir, sample_hash)

        # open and download the file
        with open(file_path, 'wb') as f:
            f.write(response.content)

        contains = []
        file_ext = ''
        magic_str = magic.from_file(file_path)
        for regex, cur_contains, extension in self.MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)
                if (not file_ext):
                    file_ext = extension

        file_name = '{}{}'.format(sample_hash, file_ext)

        # move the file to the vault
        vault_ret_dict = Vault.add_attachment(file_path, self.get_container_id(), file_name=file_name, metadata={'contains': contains})
        curr_data = {}

        if (vault_ret_dict['succeeded']):
            curr_data[phantom.APP_JSON_VAULT_ID] = vault_ret_dict[phantom.APP_JSON_HASH]
            curr_data[phantom.APP_JSON_NAME] = file_name
            action_result.add_data(curr_data)
            wanted_keys = [phantom.APP_JSON_VAULT_ID, phantom.APP_JSON_NAME]
            summary = {x: curr_data[x] for x in wanted_keys}
            if (contains):
                summary.update({'file_type': ','.join(contains)})
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_dict['message'])

        # remove the /tmp/<> temporary directory
        shutil.rmtree(local_dir)

        return action_result.get_status()

    def _get_sample(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        sample_hash = param[WILDFIRE_JSON_HASH]

        self.save_progress('Getting file from WildFire')

        ret_val, response = self._make_rest_call('/get/sample', action_result, self.GET_SAMPLE_ERROR_DESC, method='post', data={'hash': sample_hash}, parse_response=False)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return self._save_file_to_vault(action_result, response, sample_hash)

    def _save_report(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        sample_hash = param[WILDFIRE_JSON_TASK_ID]

        self.save_progress('Getting report from WildFire')

        data = {
            'hash': sample_hash,
            'format': 'pdf'
        }

        ret_val, response = self._make_rest_call('/get/report', action_result, self.GET_REPORT_ERROR_DESC, method='post', data=data, parse_response=False)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return self._save_file_to_vault(action_result, response, sample_hash)

    def _get_platform_id(self, param):

        platform = param.get(WILDFIRE_JSON_PLATFORM)

        if (not platform):
            return None

        platform = platform.upper()

        if (platform not in self.PLATFORM_ID_MAPPING):
            return None

        return self.PLATFORM_ID_MAPPING[platform]

    def _get_pcap(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        sample_hash = param[WILDFIRE_JSON_HASH]
        rest_data = {'hash': sample_hash}

        platform_id = self._get_platform_id(param)

        if (platform_id):
            rest_data.update({'platform': platform_id})

        self.save_progress('Getting pcap from WildFire')

        ret_val, response = self._make_rest_call('/get/pcap', action_result, self.GET_PCAP_ERROR_DESC, method='post', data=rest_data, parse_response=False)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return self._save_file_to_vault(action_result, response, sample_hash)

    def _get_verdict(self, task_id, action_result):

        self.save_progress("Getting verdict for: {0}".format(task_id))

        # make rest call to get verdict whether URL is in wildfire db
        ret_val, response = self._make_rest_call('/get/verdict', action_result, self.FILE_UPLOAD_ERROR_DESC, method='post', files={'hash': ('', task_id)})

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # get verdict whether hash is in WildFire database
        verdict_code = int(response['get-verdict-info']['verdict'])

        try:
            if verdict_code == 0:
                verdict = {0: 'benign'}
            elif verdict_code == 1:
                verdict = {1: 'malware'}
            elif verdict_code == 2:
                verdict = {2: 'grayware'}
            elif verdict_code == 4:
                verdict = {4: 'phishing'}
            elif verdict_code == -100:
                verdict = {-100: 'pending, the sample exists, but there is currently no verdict'}
            elif verdict_code == -101:
                verdict = {-101: 'error'}
            elif verdict_code == -102:
                verdict = {-102: 'unknown, cannot find sample record in the WildFire database'}
            elif verdict_code == -103:
                verdict = {-103: 'invalid hash value'}
            return verdict
        except:
            return "verdict unknown"

    def _detonate_url(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # add an http to url if not present
        url = param['url']

        if (not ph_utils.is_url(url)):
            return action_result.get_status()

        # make rest call to get sha256 and md5
        ret_val, response = self._make_rest_call('/submit/link', action_result, self.FILE_UPLOAD_ERROR_DESC, method='post', files={'link': ('', url)})

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # get sha256 and md5 hashes
        try:
            task_id = response['submit-link-info']['sha256']
        except:
            return action_result.set_status(phantom.APP_ERROR, "task id not part of response, can't continue")

        verdict = self._get_verdict(task_id, action_result)

        try:
            verdict_code, verdict_message = verdict.items()[0]
        except:
            return action_result.set_status(phantom.APP_ERROR, verdict)

        if verdict_code >= 0:
            summary_available = True
            # Now poll for the result
            ret_val, response = self._poll_task_status(task_id, action_result)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()
        else:
            summary_available = False

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['verdict_code'] = verdict_code
        summary['verdict'] = verdict_message
        summary['summary_available'] = summary_available

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_vault_file_sha256(self, vault_id, action_result):

        self.save_progress('Getting the sha256 of the file')

        sha256 = None
        metadata = None

        if (hasattr(Vault, 'get_file_info')):
            try:
                metadata = Vault.get_file_info(container_id=self.get_container_id(), vault_id=vault_id)[0]['metadata']
            except Exception as e:
                self.debug_print('Handled Exception:', e)
                metadata = None
        else:
            try:
                metadata = Vault.get_meta_by_hash(self.get_container_id(), vault_id, calculate=True)[0]
            except:
                self.debug_print('Handled Exception:', e)
                metadata = None

        if (not metadata):
            return (action_result.set_status(phantom.APP_ERROR, "Unable to get meta info of vault file"), None)

        try:
            sha256 = metadata['sha256']
        except Exception as e:
            self.debug_print('Handled exception', e)
            return (action_result.set_status(phantom.APP_ERROR, "Unable to get meta info of vault file"), None)

        return (phantom.APP_SUCCESS, sha256)

    def _detonate_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, files = self._get_file_dict(param, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # get the sha256 of the file
        vault_id = param['vault_id']
        ret_val, sha256 = self._get_vault_file_sha256(vault_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        data = action_result.add_data({})
        self.save_progress('Checking for prior detonations')

        ret_val, response = self._check_detonated_report(sha256, action_result)

        if (phantom.is_fail(ret_val)):

            # Was not detonated before
            self.save_progress('Uploading the file')

            ret_val, response = self._make_rest_call('/submit/file', action_result, self.FILE_UPLOAD_ERROR_DESC, method='post', files=files)

            if (phantom.is_fail(ret_val)):
                return self.get_status()

            # The first part is the uploaded file info
            data.update(response)

            # get the sha256
            task_id = response.get('upload-file-info', {}).get('sha256')

            if (not task_id):
                task_id = response.get('upload-file-info', {}).get('md5')

            # Now poll for the result
            ret_val, response = self._poll_task_status(task_id, action_result)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

        # Add the report
        data.update(response)

        malware = data.get('file_info', {}).get('malware', 'no')

        action_result.update_summary({WILDFIRE_JSON_MALWARE: malware})

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this connector run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == self.ACTION_ID_DETONATE_FILE):
            ret_val = self._detonate_file(param)
        elif (action_id == self.ACTION_ID_DETONATE_URL):
            ret_val = self._detonate_url(param)
        elif (action_id == self.ACTION_ID_GET_REPORT):
            ret_val = self._get_report(param)
        elif (action_id == self.ACTION_ID_GET_SAMPLE):
            ret_val = self._get_sample(param)
        elif (action_id == self.ACTION_ID_GET_PCAP):
            ret_val = self._get_pcap(param)
        elif (action_id == self.ACTION_ID_SAVE_REPORT):
            ret_val = self._save_report(param)
        elif (action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = WildfireConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(ret_val), indent=4)

    exit(0)
