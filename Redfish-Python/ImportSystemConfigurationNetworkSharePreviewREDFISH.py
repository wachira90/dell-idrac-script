#!/usr/bin/python3
#
# ImportSystemConfigurationNetworkSharePreviewREDFISH. Python script using Redfish API to preview import server configuration profile on a network share. 
#
# _author_ = Texas Roemer <Texas_Roemer@Dell.com>
# _version_ = 3.0
#
# Copyright (c) 2019, Dell, Inc.
#
# This software is licensed to you under the GNU General Public License,
# version 2 (GPLv2). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
# along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
#

import argparse
import getpass
import json
import logging
import re
import requests
import sys
import time
import warnings

from datetime import datetime
from pprint import pprint

warnings.filterwarnings("ignore")

parser = argparse.ArgumentParser(description="Python script using Redfish API to preview server configuration profile (SCP) on a supported network share")
parser.add_argument('-ip',help='iDRAC IP address', required=False)
parser.add_argument('-u', help='iDRAC username', required=False)
parser.add_argument('-p', help='iDRAC password. If you do not pass in argument -p, script will prompt to enter user password which will not be echoed to the screen.', required=False)
parser.add_argument('-x', help='Pass in X-Auth session token for executing Redfish calls. All Redfish calls will use X-Auth token instead of username/password', required=False)
parser.add_argument('--ssl', help='SSL cert verification for all Redfish calls, pass in value \"true\" or \"false\". By default, this argument is not required and script ignores validating SSL cert for all Redfish calls.', required=False)
parser.add_argument('--script-examples', action="store_true", help='Prints script examples')
parser.add_argument('--shareip', help='Pass in the IP address of the network share', required=False)
parser.add_argument('--sharetype', help='Pass in the share type of the network share. Supported values: NFS, CIFS, HTTP and HTTPS.', required=False)
parser.add_argument('--sharename', help='Pass in the network share share name', required=False)
parser.add_argument('--username', help='Pass in the network share username if your share is setup for auth (required for CIFS)', required=False)
parser.add_argument('--password', help='Pass in the network share username password if your share is setup for auth (required for CIFS)', required=False)
parser.add_argument('--workgroup', help='Pass in the workgroup of your CIFS network share. This argument is optional', required=False)
parser.add_argument('--filename', help='Pass in the filename of the SCP file which is on the network share you are using', required=False)
parser.add_argument('--ignorecertwarning', help='Supported values are Disabled and Enabled. This argument is only required if using HTTPS for share type. If you don\'t pass in this argument when using HTTPS, default iDRAC setting is Enabled', required=False)
args = vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- ImportSystemConfigurationNetworkSharePreviewREDFISH.py -ip 192.168.0.120 -u root -p calvin --shareip 192.168.0.130 --sharetype NFS --sharename /nfs --filename SCP_export_R740, this example is going to preview SCP file on NFS share.
    \n- ImportSystemConfigurationNetworkSharePreviewREDFISH.py -ip 192.168.0.120 -u root -p calvin --shareip 192.168.0.140 --sharetype CIFS --sharename cifs_share_vm --filename R740_scp_file --username administrator --password password, this example is going to preview SCP file on the CIFS share.""")
    sys.exit(0)

def check_supported_idrac_version():
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code == 401:
        logging.warning("\n- WARNING, status code %s returned, check your iDRAC username/password is correct or iDRAC user has correct privileges to execute Redfish commands" % response.status_code)
        sys.exit(0)
    if response.status_code != 200:
        logging.warning("\n- WARNING, GET command failed to check supported iDRAC version, status code %s returned" % response.status_code)
        sys.exit(0)

def get_server_generation():
    global idrac_version
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1?$select=Model' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1?$select=Model' % idrac_ip, verify=False,auth=(idrac_username,idrac_password))
    data = response.json()
    if response.status_code == 401:
        logging.error("\n- ERROR, status code 401 detected, check to make sure your iDRAC script session has correct username/password credentials or if using X-auth token, confirm the session is still active.")
        sys.exit(0)
    elif response.status_code != 200:
        logging.warning("\n- WARNING, unable to get current iDRAC version installed")
        sys.exit(0)
    if "12" in data["Model"] or "13" in data["Model"]:
        idrac_version = 8
    elif "14" in data["Model"] or "15" in data["Model"] or "16" in data["Model"]:
        idrac_version = 9
    else:
        idrac_version = 10
    
def import_server_configuration_profile_preview():
    global job_id
    method = "ImportSystemConfigurationPreview"
    if idrac_version >= 10:
        url = 'https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/OemManager.ImportSystemConfigurationPreview' % idrac_ip
    else:    
        url = 'https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/EID_674_Manager.ImportSystemConfigurationPreview' % idrac_ip
    payload = {"ShareParameters":{"Target":["ALL"]}}
    if args["shareip"]:
        payload["ShareParameters"]["IPAddress"] = args["shareip"]
    if args["sharetype"]:
        payload["ShareParameters"]["ShareType"] = args["sharetype"]
    if args["sharename"]:
        payload["ShareParameters"]["ShareName"] = args["sharename"]
    if args["filename"]:
        payload["ShareParameters"]["FileName"] = args["filename"]
    if args["username"]:
        payload["ShareParameters"]["UserName"] = args["username"]
    if args["password"]:
        payload["ShareParameters"]["Password"] = args["password"]
    if args["workgroup"]:
        payload["ShareParameters"]["Workgroup"] = args["workgroup"]
    if args["ignorecertwarning"]:
        payload["ShareParameters"]["IgnoreCertificateWarning"] = args["ignorecertwarning"]
    if args["x"]:
        headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
    else:
        headers = {'content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
    if response.status_code != 202:
        logging.error("- FAIL, POST command failed to export system configuration, status code %s returned" % response.status_code)
        logging.error("- Error details: %s" % response.__dict__)
        sys.exit(0)
    try:
        job_id = response.headers['Location'].split("/")[-1]
    except:
        logging.error("- FAIL, unable to find job ID in headers POST response, headers output is:\n%s" % response.headers)
        sys.exit(0)
    logging.info("\n- Job ID \"%s\" successfully created" % job_id)
    
def loop_job_status():
    start_job_message = ""
    start_time = datetime.now()
    count = 1
    get_job_status_count = 1
    new_password_set = "no"
    while True:
        if count == 10:
            logging.error("- FAIL, 10 attempts at getting job status failed, script will exit")
            sys.exit(0)
        if get_job_status_count == 10:
            logging.warning("- WARNING, retry count of 10 has been hit for retry job status GET request, script will exit")
            sys.exit(0)
        try:
            if args["x"]:
                response = requests.get('https://%s/redfish/v1/TaskService/Tasks/%s' % (idrac_ip, job_id), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
            else:
                response = requests.get('https://%s/redfish/v1/TaskService/Tasks/%s' % (idrac_ip, job_id), verify=verify_cert, auth=(idrac_username, idrac_password))
        except requests.ConnectionError as error_message:
            logging.warning("- WARNING, requests command failed to GET job status, detailed error information: \n%s" % error_message)
            logging.info("- INFO, script will attempt to get job status again")
            time.sleep(10)
            count += 1
            continue
        data = response.json()
        try:
            current_job_message = data['Oem']['Dell']['Message']
        except:
            logging.info("- INFO, unable to get job ID message string from JSON output, retry")
            count += 1
            continue
        current_time = (datetime.now()-start_time)
        if response.status_code == 202 or response.status_code == 200:
            logging.debug("- INFO, GET command passed to get job status details")
            time.sleep(1)
        else:
            logging.info("- INFO, GET command failed to get job ID details, error code: %s, retry" % response.status_code)
            count += 1
            time.sleep(5)
            continue
        if "Oem" not in data:
            logging.info("- INFO, unable to locate OEM data in JSON response, retry")
            get_job_status_count += 1
            time.sleep(5)
            continue
        if data['Oem']['Dell']['JobState'] == "Failed" or data['Oem']['Dell']['JobState'] == "CompletedWithErrors":
            logging.info("\n- INFO, job ID %s status marked as \"%s\"" % (job_id, data['Oem']['Dell']['JobState']))
            logging.info("\n- Detailed configuration changes and job results for \"%s\"\n" % job_id)
            try:
                for i in data["Messages"]:
                    pprint(i)
            except:
                logging.error("- FAIL, unable to get configuration results for job ID, returning only final job results\n")
                for i in data['Oem']['Dell'].items():
                    print("%s: %s" % (i[0], i[1]))
            logging.info("- %s completed in: %s" % (job_id, str(current_time)[0:7]))
            sys.exit(0)
        elif data['Oem']['Dell']['JobState'] == "Completed":
            if "fail" in data['Oem']['Dell']['Message'].lower() or "error" in data['Oem']['Dell']['Message'].lower() or "not" in data['Oem']['Dell']['Message'].lower() or "unable" in data['Oem']['Dell']['Message'].lower() or "no device configuration" in data['Oem']['Dell']['Message'].lower() or "time" in data['Oem']['Dell']['Message'].lower():
                logging.error("- FAIL, Job ID %s marked as %s but detected issue(s). See detailed job results below for more information on failure\n" % (job_id, data['Oem']['Dell']['JobState']))
            elif "success" in data['Oem']['Dell']['Message'].lower():
                logging.info("- PASS, job ID %s successfully marked completed\n" % job_id)
            elif "no changes" in data['Oem']['Dell']['Message'].lower():
                logging.info("\n- PASS, job ID %s marked completed\n" % job_id)
                logging.info("- Detailed job results for job ID %s\n" % job_id)
                for i in data['Oem']['Dell'].items():
                    pprint(i)
                sys.exit(0)
            logging.info("- Detailed configuration changes and job results for \"%s\"\n" % job_id)
            try:
                for i in data["Messages"]:
                    pprint(i)
            except:
                logging.error("- FAIL, unable to get configuration results for job ID, returning only final job results\n")
                for i in data['Oem']['Dell'].items():
                    pprint(i)
            logging.info("\n- %s completed in: %s" % (job_id, str(current_time)[0:7]))
            sys.exit(0)
        else:
            if start_job_message != current_job_message:
                logging.info("- INFO, \"%s\", percent complete: %s" % (data['Oem']['Dell']['Message'],data['Oem']['Dell']['PercentComplete']))
                start_job_message = current_job_message
                continue        

if __name__ == "__main__":
    if args["script_examples"]:
        script_examples()
    if args["ip"] or args["ssl"] or args["u"] or args["p"] or args["x"]:
        idrac_ip = args["ip"]
        idrac_username = args["u"]
        if args["p"]:
            idrac_password = args["p"]
        if not args["p"] and not args["x"] and args["u"]:
            idrac_password = getpass.getpass("\n- Argument -p not detected, pass in iDRAC user %s password: " % args["u"])
        if args["ssl"]:
            if args["ssl"].lower() == "true":
                verify_cert = True
            elif args["ssl"].lower() == "false":
                verify_cert = False
            else:
                verify_cert = False
        else:
            verify_cert = False
        check_supported_idrac_version()
        get_server_generation()
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
        sys.exit(0)
    if args["filename"] and args["shareip"] and args["sharename"] and args["sharetype"]:
        import_server_configuration_profile_preview()
        loop_job_status()
    else:
        logging.warning("\n- WARNING, arguments --filename, --sharename, --sharetype and --shareip are required for import. See help text or argument --script-examples for more details.")
