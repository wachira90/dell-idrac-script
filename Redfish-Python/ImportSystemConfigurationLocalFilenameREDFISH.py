#!/usr/bin/python3
#
# ImportSystemConfigurationLocalFilenameREDFISH. Python script using Redfish API to import system configuration profile attributes locally from a configuration file.
#
# _author_ = Texas Roemer <Texas_Roemer@Dell.com>
# _version_ = 22.0
#
# Copyright (c) 2017, Dell, Inc.
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

parser=argparse.ArgumentParser(description="Python script using Redfish API to import the host server configuration profile locally from a configuration file.")
parser.add_argument('-ip',help='iDRAC IP address', required=False)
parser.add_argument('-u', help='iDRAC username', required=False)
parser.add_argument('-p', help='iDRAC password. If you do not pass in argument -p, script will prompt to enter user password which will not be echoed to the screen.', required=False)
parser.add_argument('-x', help='Pass in X-Auth session token for executing Redfish calls. All Redfish calls will use X-Auth token instead of username/password', required=False)
parser.add_argument('--ssl', help='SSL cert verification for all Redfish calls, pass in value \"true\" or \"false\". By default, this argument is not required and script ignores validating SSL cert for all Redfish calls.', required=False)
parser.add_argument('--script-examples', action="store_true", help='Prints script examples')
parser.add_argument('--new-password', help='Pass in new iDRAC user password that gets set during SCP import. This will be required to continue to query the job status. NOTE: If you pass in "" for value, script will prompt you to enter the password which is not echoed to the screen.', dest="new_password", required=False)
parser.add_argument('--get-target-values', help='Get supported values for --target argument', action="store_true", dest="get_target_values", required=False)
parser.add_argument('--target', help='Pass in Target value to get component attributes. You can pass in \"ALL" to get all component attributes or pass in specific component(s) to get only those attributes. If you pass in multiple values use a comma separator. To get all supported values, use argument --get-target-values', required=False)
parser.add_argument('--shutdown-type', help='Pass in ShutdownType value. Supported values are Graceful, Forced and NoReboot. If you don\'t use this optional parameter, default value is Graceful. NOTE: If you pass in NoReboot value, configuration changes will not be applied until the next server manual reboot.', dest="shutdown_type", required=False)
parser.add_argument('--filename', help='Pass in Server Configuration Profile filename', required=False)
parser.add_argument('--end-powerstate', help='Pass in end HostPowerState value. Supported values are On and Off. If you don\'t use this optional parameter, default value is On', dest="end_powerstate", required=False)

args=vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- ImportSystemConfigurationLocalFilenameREDFISH.py -ip 192.168.0.120 -u root -p calvin --target ALL --filename SCP_export_R740, this example is going to import SCP file and apply all attribute changes for all components.
    \n- ImportSystemConfigurationLocalFilenameREDFISH.py -ip 192.168.0.120 -u root -p calvin --target BIOS --filename R740_scp_file --shutdown-type Forced, this example is going to only apply BIOS changes from the SCP file along with forcing a server power reboot.
    \n- ImportSystemConfigurationLocalFilenameREDFISH.py -ip 192.168.0.120 -u root -p calvin --target IDRAC --filename 2020-8-5_135318_export.xml --new-password Test1234#, this example uses SCP import to change root user password and will leverage the new user password to continue to query the job status until marked completed.
    \n- ImportSystemConfigurationLocalFilenameREDFISH.py -ip 192.168.0.120 -u root --target IDRAC --filename 2022-4-21_111957_export.xml --new-password \"\", this example will first prompt you to enter current root password, then prompt you to enter new password set for root which was passed in the SCP file.""")
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


def get_target_values():
    if idrac_version >= 10:
        logging.info("\n- INFO, supported target values:\n\nALL\nIDRAC\nBIOS\nNIC\nRAID\nFC\nInfiniBand\nSupportAssist\nEventFilters\nSystem\nLifecycleController\nAHCI\nPCIeSSD")
        sys.exit(0)
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.warning("\n- WARNING, GET command failed to get supported target values, status code %s returned" % response.status_code)
        print(data)
        sys.exit(0)
    logging.info("\n- INFO, supported values for --target argument\n")
    try:
        for i in data["Actions"]["Oem"]["#OemManager.v1_4_0.OemManager#OemManager.ImportSystemConfiguration"]["ShareParameters"]["Target@Redfish.AllowableValues"]:
            print(i)
    except:
        for i in data["Actions"]["Oem"]["#OemManager.ImportSystemConfiguration"]["ShareParameters"]["Target@Redfish.AllowableValues"]:
            print(i)

def import_SCP_local_filename():
    global job_id
    try:
        open_file = open(args["filename"],"r")
    except:
        logging.error("\n- FAIL, \"%s\" file doesn't exist" % args["filename"])
        sys.exit(0)    
    if idrac_version >= 10:
        url = 'https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/OemManager.ImportSystemConfiguration' % idrac_ip
    else:    
        url = 'https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/EID_674_Manager.ImportSystemConfiguration' % idrac_ip
    task_uri = "redfish/v1/TaskService/Tasks/"
        
    # Code needed to modify the SCP file to one string to pass in for POST command
    modify_file = open_file.read()
    modify_file = re.sub(" \n ","",modify_file)
    modify_file = re.sub(" \n","",modify_file)
    file_string = re.sub("   ","",modify_file)
    open_file.close()
    payload = {"ImportBuffer":"","ShareParameters":{"Target":[args["target"]]}}
    if args["shutdown_type"]:
        payload["ShutdownType"] = args["shutdown_type"].title()
    if args["end_powerstate"]:
        payload["HostPowerState"] = args["end_powerstate"].title()
    payload["ImportBuffer"] = file_string
    if args["x"]:
        headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
    else:
        headers = {'content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username, args["p"]))
    if response.status_code != 202:
        logging.error("\n- FAIL, POST command failed for import system configuration, status code %s returned" % response.status_code)
        logging.error(response.json())
        sys.exit(0)
    try:
        job_id = response.headers['Location'].split("/")[-1]
    except:
        logging.error("- FAIL, unable to find job ID in headers POST response, headers output is:\n%s" % response.headers)
        sys.exit(0)
    logging.info("\n- PASS, %s successfully created for ImportSystemConfiguration method\n" % (job_id))
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
                response = requests.get('https://%s/%s/%s' % (idrac_ip, task_uri, job_id), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
            else:
                response = requests.get('https://%s/%s/%s' % (idrac_ip, task_uri, job_id), verify=verify_cert, auth=(idrac_username, args["p"]))
        except requests.ConnectionError as error_message:
            logging.warning("- WARNING, requests command failed to GET job status, detailed error information: \n%s" % error_message)
            logging.info("- INFO, script will attempt to get job status again")
            time.sleep(10)
            count += 1
            continue
        if args["new_password"] == "" and new_password_set == "no":
            args["p"] = getpass.getpass("- INFO, empty value detected for argument --new-password, pass in new password being set by SCP: ")
            new_password_set = "yes"
        if response.status_code == 401 and args["new_password"]:
            if args["x"]:
                logging.warning("- WARNING, X-auth token session detected along with new password changed, script will exit. Manually check the overall job queue for completed job status. X-auth token session is no longer valid, recreate the token using new password set.")
                sys.exit(0)
            logging.info("- INFO, status code 401 and argument --new-password detected. Script will now query job status using iDRAC user \"%s\" new password set by SCP import" % idrac_username)
            time.sleep(5)
            args["p"] = args["new_password"]
            if args["x"]:
                response = requests.get('https://%s/%s/%s' % (idrac_ip, task_uri, job_id), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
            else:
                response = requests.get('https://%s/%s/%s' % (idrac_ip, task_uri, job_id), verify=verify_cert, auth=(idrac_username, args["p"]))
            if response.status_code == 401:
                logging.info("- INFO, new password passed in for argument --new-password still failed with status code 401 for idrac user \"%s\", unable to check job status" % idrac_username)
                sys.exit(0)
            else:
                continue
        elif response.status_code == 401:
            logging.info("- INFO, status code 401 still detected for iDRAC user \"%s\". Check SCP file to see if iDRAC user \"%s\" password was changed for import" % (idrac_username, idrac_username))
            sys.exit(0)
        data = response.json()
        try:
            current_job_message = data["Oem"]["Dell"]["Message"]
        except:
            logging.info("- INFO, unable to get job ID message string from JSON output, retry")
            count += 1
            continue
        current_time = (datetime.now()-start_time)
        if response.status_code == 202 or response.status_code == 200:
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
        elif "no reboot" in data["Oem"]["Dell"]["Message"].lower():
            logging.info("- PASS, job ID %s successfully marked completed. NoReboot value detected and config changes will not be applied until next manual server reboot\n" % job_id)
            logging.info("\n- Detailed job results for job ID %s\n" % job_id)
            for i in data['Oem']['Dell'].items():
                print("%s: %s" % (i[0], i[1]))
            sys.exit(0)
        elif data["Oem"]["Dell"]["JobState"] == "Failed" or data["Oem"]["Dell"]["JobState"] == "CompletedWithErrors":
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
        elif data["Oem"]["Dell"]["JobState"] == "Completed":
            if "fail" in data["Oem"]["Dell"]["Message"].lower() or "error" in data["Oem"]["Dell"]["Message"].lower() or "not" in data["Oem"]["Dell"]["Message"].lower() or "unable" in data["Oem"]["Dell"]["Message"].lower() or "no device configuration" in data['Oem']['Dell']['Message'].lower() or "time" in data['Oem']['Dell']['Message'].lower():
                logging.error("- FAIL, Job ID %s marked as %s but detected issue(s). See detailed job results below for more information on failure\n" % (job_id, data["Oem"]["Dell"]["JobState"]))
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
                logging.info("- INFO, \"%s\", percent complete: %s" % (data["Oem"]["Dell"]["Message"],data["Oem"]["Dell"]["PercentComplete"]))
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
            args["p"] = idrac_password
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
    if args["target"]:
        import_SCP_local_filename()
    elif args["get_target_values"]:
        get_target_values()
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
