#!/usr/bin/python3
#
# _author_ = Texas Roemer <Texas_Roemer@Dell.com>
# _version_ = 2.0
#
# Copyright (c) 2022, Dell, Inc.
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
import os
import platform
import re
import requests
import subprocess
import sys
import time
import warnings

from datetime import datetime
from pprint import pprint

warnings.filterwarnings("ignore")

parser = argparse.ArgumentParser(description="Python script using Redfish API to first check current firmware version for a device, then only apply the new firmware package if version difference is detected. NOTE: There is a --force argument to apply the firmware even if same version is detected.")
parser.add_argument('-ip',help='iDRAC IP address', required=False)
parser.add_argument('-u', help='iDRAC username', required=False)
parser.add_argument('-p', help='iDRAC password. If you do not pass in argument -p, script will prompt to enter user password which will not be echoed to the screen.', required=False)
parser.add_argument('-x', help='Pass in X-Auth session token for executing Redfish calls. All Redfish calls will use X-Auth token instead of username/password', required=False)
parser.add_argument('--ssl', help='SSL cert verification for all Redfish calls, pass in value \"true\" or \"false\". By default, this argument is not required and script ignores validating SSL cert for all Redfish calls.', required=False)
parser.add_argument('--script-examples', action="store_true", help='Prints script examples')
parser.add_argument('--location', help='Pass in the local directory location of the firmware image', required=False)
parser.add_argument('--image', help='Pass in the firmware image name', required=False)
parser.add_argument('--reboot', help='Reboot the server to apply the update if needed. if argument not passed in, job ID will still be in scheduled state and execute on next manual server reboot. Note: If the update gets applied with no server reboot (Example: iDRAC, DIAGs, Driver pack), you don\'t need to pass in this argument. For more details on which devices update immediately, refer to Lifecycle Controller User Guide Update section.', action="store_true", required=False)
parser.add_argument('--force', help='Pass in this argument to force the update when same version installed and package version are the same', action="store_true", required=False)
args = vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- DeviceFirmwareSimpleUpdateCheckVersionREDFISH.py -ip 192.168.0.120 -u root -p calvin --location C:\\Users\\administrator\\Downloads --image Network_Firmware_H8M48_WN64_20.5.16_A00.EXE, this example will attempt to apply the update package.
    \n- DeviceFirmwareSimpleUpdateCheckVersionREDFISH.py -ip 192.168.0.120 -u root -p calvin --location C:\\Users\\administrator\\Downloads --image Network_Firmware_H8M48_WN64_20.5.16_A00.EXE --force, this example will force the update even if same version and package version is detected.""")
    sys.exit(0)

def check_supported_idrac_version():
    # Validates iDRAC version and credentials.
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/UpdateService' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/UpdateService' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
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


def download_image_payload():
    # Download the payload from the Dell update package to create the available URI entry. 
    global available_entry
    global http_push_uri
    global start_time
    start_time = datetime.now()
    logging.info("\n- INFO, downloading \"%s\" image, this may take a few minutes depending on the size of the payload" % args["image"])
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/UpdateService' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/UpdateService' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    http_push_uri = data['HttpPushUri']
    if args["x"]:
        response = requests.get('https://%s%s' % (idrac_ip, http_push_uri), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s%s' % (idrac_ip, http_push_uri), verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    ImageLocation = args["location"]
    filename = args["image"]
    ImagePath = os.path.join(ImageLocation, filename)
    ETag = response.headers['ETag']
    url = 'https://%s%s' % (idrac_ip, http_push_uri)
    files = {'file': (filename, open(ImagePath, 'rb'), 'multipart/form-data')}
    if args["x"]:
        headers = {'X-Auth-Token': args["x"], "if-match": ETag}
        response = requests.post(url, files=files, headers=headers, verify=verify_cert)
    else:
        headers = {"if-match": ETag}
        response = requests.post(url, files=files, verify=verify_cert,auth=(idrac_username,idrac_password), headers=headers)
    post_command_response_output = response.json()
    if response.status_code == 201:
        logging.info("\n- PASS: POST command passed successfully to download image")
    else:
        logging.error("\n- FAIL: POST command failed to download image payload, status code %s returned" % response.status_code)
        logging.error(post_command_response_output)
        sys.exit(0)
    available_entry = post_command_response_output['Id']
    logging.info("- INFO, AVAILABLE entry created for download image \"%s\" is \"%s\"" % (filename, available_entry))

def get_available_entry_version_compare_current_version():
    # Get available entry URI and compare against current installed version. If versions are the same, no update will get applied and available entry will be deleted, script exit.
    # If version difference detected, script will now apply the update. 
    global available_entry_details
    logging.info("- INFO, getting details for available package entry, compare against current installed version")
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory/%s' % (idrac_ip, available_entry), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory/%s' % (idrac_ip, available_entry), verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.error("\n- ERROR, GET request failed to get AVAILABLE entry data, error: \n%s" % data)
        sys.exit(0)
    available_entry_details = {"Name": data["Name"], "Version": data["Version"], "etag": response.headers["ETag"]}
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.error("\n- ERROR, GET request failed to get current firmware version details, error: \n%s" % data)
        sys.exit(0)
    for i in data["Members"]:
        for ii in i.items():
            if "installed" in ii[1].lower():
                if args["x"]:
                    response = requests.get('https://%s%s' % (idrac_ip, ii[1]), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
                else:
                    response = requests.get('https://%s%s' % (idrac_ip, ii[1]), verify=verify_cert, auth=(idrac_username, idrac_password))
                    data = response.json()
                    if response.status_code != 200:
                        logging.error("\n- ERROR, GET request failed to get URI details for Name and Version, error: \n%s" % data)
                        sys.exit(0)
                    installed_entry_details = {"Name": data["Name"], "Version": data["Version"]}
                    if available_entry_details["Name"] == installed_entry_details["Name"]:
                        logging.info("\n- Device Name: %s" % installed_entry_details["Name"])
                        logging.info("- Installed version detected: %s" % installed_entry_details["Version"])
                        logging.info("- Available package version detected: %s" % available_entry_details["Version"])
                        if installed_entry_details["Version"] != available_entry_details["Version"]:
                            logging.info("\n- INFO, version difference detected, script will now apply firmware version %s" % available_entry_details["Version"])
                        elif installed_entry_details["Version"] == available_entry_details["Version"]:
                            if args["force"]:
                                logging.info("- WARNING, same version installed and package version detected but force argument passed, update will get applied")
                                return
                            else:
                                logging.info("\n- WARNING, same version detected, script will NOT apply package version and delete available entry")
                                url = 'https://%s/redfish/v1/UpdateService/FirmwareInventory/%s' % (idrac_ip, available_entry)
                                if args["x"]:
                                    headers = {'X-Auth-Token': args["x"], "if-match": "%s" % available_entry_details["etag"]}
                                    response = requests.delete(url, headers=headers, verify=verify_cert)
                                else:
                                    headers = {"if-match": "%s" % available_entry_details["etag"]}
                                    response = requests.delete(url, headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
                                data = response.json()
                                if response.status_code == 200:
                                    logging.debug("\n- PASS, successfully deleted available entry")
                                    sys.exit(0)
                                else:
                                    logging.error("\n- FAIL, command failed to delete available entry, error: \n%s" % data)
                                    sys.exit(0)
        
def install_image_payload():
    # Once the payload has been downloaded and available URI created, payload will now be applied and create an update job ID which can be used to track update progress. 
    global job_id
    url = 'https://%s/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate' % (idrac_ip)
    if args["reboot"]:
        payload = {"ImageURI":"%s/%s" % (http_push_uri, available_entry),"@Redfish.OperationApplyTime": "Immediate"}
    else:
        payload = {"ImageURI":"%s/%s" % (http_push_uri, available_entry),"@Redfish.OperationApplyTime": "OnReset"}
    if args["x"]:
        headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
    else:
        headers = {'content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
    if response.status_code == 202 or response.status_code == 200:
        logging.info("- PASS, POST command passed for SimpleUpdate action, status code %s returned" % response.status_code)
    else:
        logging.error("\n- FAIL, Command failed to check job status, return code is %s" % response.status_code)
        loging.error("Extended Info Message: {0}".format(response.json()))
        sys.exit(0)
    try:
        job_id = response.headers['Location'].split("/")[-1]
    except:
        logging.error("- FAIL, unable to locate job ID in header")
        sys.exit(0)
    logging.info("- PASS, update job ID %s successfully created, script will now loop polling the job status" % job_id)

def check_job_status():
    retry_count = 1
    schedule_job_status_count = 1
    if "idrac" in args["location"].lower():
        idrac_update = "yes"
    else:
        idrac_update = "no"
    while True:
        current_time = str(datetime.now()-start_time)[0:7]
        check_idrac_connection()
        if retry_count == 30:
            logging.warning("- WARNING, GET command retry count of 30 has been reached, script will exit")
            sys.exit(0)
        try:
            if args["x"]:
                response = requests.get('https://%s/redfish/v1/TaskService/Tasks/%s' % (idrac_ip, job_id), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
            else:
                response = requests.get('https://%s/redfish/v1/TaskService/Tasks/%s' % (idrac_ip, job_id), verify=verify_cert, auth=(idrac_username, idrac_password))
        except requests.exceptions.ConnectTimeout as json_error:
            print("ConnectTimeout:", json_error)
            time.sleep(180)
            retry_count += 1
            continue
        except json.decoder.JSONDecodeError as json_error:
            print("JSONDecodeError:", json_error)
            time.sleep(180)
            retry_count += 1
            continue
        except requests.exceptions.ConnectionError as error_message:
            logging.info("- INFO, GET request failed due to connection error, retry in 30 seconds")
            time.sleep(30)
            retry_count += 1
            continue
        except requests.exceptions.RequestException as req_error:
            print("RequestException:", req_error)
            time.sleep(180)
            retry_count += 1
            continue
        try:
            data = response.json()
        except:
            logging.warning("- WARNING, unable to get JSON data response from GET request, script will retry in 1 minute")
            time.sleep(60)
            retry_count +=1 
            continue
        if response.status_code == 200 or response.status_code == 202:
            time.sleep(1)
        elif response.status_code == 404:
            if idrac_update == "yes":
                if args["x"]:
                    response = requests.get('https://%s/redfish/v1/JobService/Jobs/%s' % (idrac_ip, job_id), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
                else:
                    response = requests.get('https://%s/redfish/v1/JobService/Jobs/%s' % (idrac_ip, job_id), verify=verify_cert, auth=(idrac_username, idrac_password))
                if response.status_code == 200 or response.status_code == 202:
                    time.sleep(1)
                else:
                    logging.error("\n- ERROR, GET request failed to get job ID details, status code %s returned, error: \n%s" % (response.status_code, data))
                data = response.json()
                if "success" in data["Messages"][0]["Message"].lower() and data["JobState"] == "Completed":
                    logging.info("\n- PASS, job completed, detailed final job status results\n")
                    pprint(data)
                    logging.info("\n- JOB ID %s completed in %s" % (job_id, current_time))
                    sys.exit(0)
            else:
                time.sleep(10)
                retry_count +=1
                continue
        elif response.status_code == 500:
            logging.warning("- WARNING, status code 500 returned for internal server error, GET request will retry in 1 minute")
            time.sleep(60)
            retry_count +=1 
            continue
        elif response.status_code == 401 and idrac_update == "yes":
            logging.warning("- WARNING, status code 401 detected for iDRAC firmware update, GET will retry in 1 minute")
            time.sleep(60)
            retry_count +=1 
            continue
        elif response.status_code == 503:
            logging.warning("- WARNING, status code 503 returned for service unavailable, GET request will retry in 1 minute")
            time.sleep(60)
            retry_count +=1 
            continue
        else:
            logging.error("\n- ERROR, GET request failed to get job ID details, status code %s returned, error: \n%s" % (response.status_code, data))
            sys.exit(0)
        try:
            message_string = data["Messages"]
        except:
            logging.warning("- WARNING, unable to get Messages property value from JSON response, script will retry in 1 minute")
            time.sleep(60)
            retry_count += 1
            if idrac_update == "yes":
                if args["x"]:
                    response = requests.get('https://%s/redfish/v1/JobService/Jobs/%s' % (idrac_ip, job_id), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
                else:
                    response = requests.get('https://%s/redfish/v1/JobService/Jobs/%s' % (idrac_ip, job_id), verify=verify_cert, auth=(idrac_username, idrac_password))
                if response.status_code == 200 or response.status_code == 202:
                    time.sleep(1)
                else:
                    logging.error("\n- ERROR, GET request failed to get job ID details, status code %s returned, error: \n%s" % (response.status_code, data))
                data = response.json()
                if "success" in data["Messages"][0]["Message"].lower() and data["JobState"] == "Completed":
                    logging.info("\n- PASS, job completed, detailed final job status results\n")
                    pprint(data)
                    logging.info("\n- JOB ID %s completed in %s" % (job_id, current_time))
                    sys.exit(0)
                else:
                    time.sleep(10)
                    retry_count +=1
                    continue
        if "fail" in data['Oem']['Dell']['Message'].lower() or "error" in data['Oem']['Dell']['Message'].lower() or "unable" in data['Oem']['Dell']['Message'].lower():
            logging.error("- FAIL: Job failed, current message: %s" % data["Messages"])
            sys.exit(0)
        elif data["TaskState"] == "Completed" and data["Oem"]["Dell"]["JobState"]:
            logging.info("\n- PASS, job ID successfuly marked completed, detailed final job status results\n")
            for i in data['Oem']['Dell'].items():
                pprint(i)
            logging.info("\n- JOB ID %s completed in %s" % (job_id, current_time))
            sys.exit(0)
        if data["TaskState"] == "UserIntervention" and data["PercentComplete"] == 100:
            logging.info("\n- JOB ID %s completed in %s but user intervention is needed, final job message: %s" % (job_id, current_time, message_string[0]["Message"].rstrip(".")))
            if args["reboot"]:
                if "reboot" in message_string[0]["Message"].lower():
                    logging.info("- INFO, rebooting server for the new firmware installed to become effective")
                    reboot_server()
                if "virtual" in message_string[0]["Message"].lower():
                    logging.info("- INFO, server virtual a/c cycle is needed for the new firmware installed to become effective")
            sys.exit(0)
        if data["TaskState"] == "Completed":
            logging.info("\n- PASS, job ID successfuly marked completed, detailed final job status results\n")
            for i in data['Oem']['Dell'].items():
                pprint(i)
            logging.info("\n- JOB ID %s completed in %s" % (job_id, current_time))
            sys.exit(0)
        if str(current_time)[0:7] >= "0:30:00":
            logging.error("\n- FAIL: Timeout of 30 minutes has been hit, update job should of already been marked completed. Check the iDRAC job queue and LC logs to debug the issue\n")
            sys.exit(0)
        elif "scheduled" in data['Oem']['Dell']['Message']:
            if schedule_job_status_count == 1:
                time.sleep(15)
                schedule_job_status_count += 1
                continue
            else:
                print("- PASS, job ID %s successfully marked as scheduled" % data["Id"])
                if not args["reboot"]:
                    logging.warning("- WARNING, missing argument --reboot for rebooting the server. Job is still scheduled and will be applied on next manual server reboot")
                    sys.exit(0)
                else:
                    time.sleep(15)
                    return
        elif "completed successfully" in data['Oem']['Dell']['Message']:
            logging.info("\n- PASS, job ID %s successfully marked completed, detailed final job status results\n")
            for i in data['Oem']['Dell'].items():
                pprint(i)
            logging.info("\n- %s completed in: %s" % (job_id, str(current_time)[0:7]))
            break
        else:
            logging.info("- INFO: %s, execution time: %s" % (message_string[0]["Message"].rstrip("."), current_time))
            time.sleep(1)
            continue


def loop_check_final_job_status():
    # Loop to check final job status, either marked completed or failed. 
    retry_count = 1
    while True:
        if retry_count == 20:
            logging.warning("- WARNING, GET command retry count of 20 has been reached, script will exit")
            sys.exit(0)
        check_idrac_connection()
        try:
            if args["x"]:
                response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs/%s' % (idrac_ip, job_id), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
            else:
                response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs/%s' % (idrac_ip, job_id), verify=verify_cert,auth=(idrac_username, idrac_password))
        except requests.ConnectionError as error_message:
            logging.info("- INFO, GET request failed due to connection error, retry")
            time.sleep(10)
            retry_count += 1
            continue 
        current_time = str((datetime.now()-start_time))[0:7]
        if response.status_code != 200:
            logging.error("\n- FAIL, GET command failed to check job status, return code %s" % response.status_code)
            logging.error("Extended Info Message: {0}".format(response.json()))
            sys.exit(0)
        data = response.json()
        if str(current_time)[0:7] >= "0:50:00":
            logging.error("\n- FAIL: Timeout of 50 minutes has been hit, script stopped\n")
            sys.exit(0)
        elif "Fail" in data['Message'] or "fail" in data['Message'] or "fail" in data['JobState'] or "Fail" in data['JobState']:
            logging.error("- FAIL: job ID %s failed" % job_id)
            sys.exit(0)
        elif "completed successfully" in data['Message'].lower():
            logging.info("\n- PASS, job ID %s successfully marked completed" % job_id)
            logging.info("\n- Final detailed job results -\n")
            for i in data.items():
                pprint(i)
            logging.info("\n- JOB ID %s completed in %s" % (job_id, current_time))
            break
        else:
            logging.info("- INFO, %s, execution time: %s" % (data['Message'].rstrip("."), current_time))
            time.sleep(15)

def reboot_server():
    # Reboot the server once update job is marked scheduled. This function will only be called if iDRAC version is 4.x or older. 
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})   
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert,auth=(idrac_username, idrac_password))
    data = response.json()
    logging.info("\n- INFO, Current server power state is: %s" % data['PowerState'])
    if data['PowerState'] == "On":
        url = 'https://%s/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset' % idrac_ip
        payload = {'ResetType': 'GracefulShutdown'}
        if args["x"]:
            headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
            response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
        else:
            headers = {'content-type': 'application/json'}
            response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
        if response.status_code == 204:
            logging.info("- PASS, POST command passed to gracefully power OFF server")
            logging.info("- INFO, script will now verify the server was able to perform a graceful shutdown. If the server was unable to perform a graceful shutdown, forced shutdown will be invoked in 5 minutes")
            time.sleep(15)
            start_time = datetime.now()
        else:
            logging.error("\n- FAIL, Command failed to gracefully power OFF server, status code is: %s\n" % response.status_code)
            logging.error("Extended Info Message: {0}".format(response.json()))
            sys.exit(0)
        while True:
            if args["x"]:
                response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})   
            else:
                response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert,auth=(idrac_username, idrac_password))
            data = response.json()
            current_time = str(datetime.now() - start_time)[0:7]
            if data['PowerState'] == "Off":
                logging.info("- PASS, GET command passed to verify graceful shutdown was successful and server is in OFF state")
                break
            elif current_time >= "0:05:00":
                logging.info("- INFO, unable to perform graceful shutdown, server will now perform forced shutdown")
                payload = {'ResetType': 'ForceOff'}
                if args["x"]:
                    headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
                    response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
                else:
                    headers = {'content-type': 'application/json'}
                    response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
                if response.status_code == 204:
                    logging.info("- PASS, POST command passed to perform forced shutdown")
                    time.sleep(15)
                    if args["x"]:
                        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})   
                    else:
                        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert,auth=(idrac_username, idrac_password))
                    data = response.json()
                    if data['PowerState'] == "Off":
                        logging.info("- PASS, GET command passed to verify forced shutdown was successful and server is in OFF state")
                        break
                    else:
                        logging.error("- FAIL, server not in OFF state, current power status is %s" % data['PowerState'])
                        sys.exit(0)    
            else:
                continue 
        payload = {'ResetType': 'On'}
        if args["x"]:
            headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
            response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
        else:
            headers = {'content-type': 'application/json'}
            response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
        if response.status_code == 204:
            logging.info("- PASS, POST command passed to power ON server")
        else:
            logging.error("\n- FAIL, Command failed to power ON server, status code is: %s\n" % response.status_code)
            logging.error("Extended Info Message: {0}".format(response.json()))
            sys.exit(0)
    elif data['PowerState'] == "Off":
        url = 'https://%s/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset' % idrac_ip
        payload = {'ResetType': 'On'}
        if args["x"]:
            headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
            response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
        else:
            headers = {'content-type': 'application/json'}
            response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
        if response.status_code == 204:
            logging.info("- PASS, Command passed to power ON server, code return is %s" % response.status_code)
        else:
            logging.error("\n- FAIL, Command failed to power ON server, status code is: %s\n" % response.status_code)
            logging.error("Extended Info Message: {0}".format(response.json()))
            sys.exit(0)
    else:
        logging.error("- FAIL, unable to get current server power state to perform either reboot or power on")
        sys.exit(0)

def check_idrac_connection():
    # Function to check iDRAC network connection using ping command
    run_network_connection_function = ""
    if platform.system().lower() == "windows":
        ping_arg = "-n"
    elif platform.system().lower() == "linux":
        ping_arg = "-c"
    else:
        logging.error("- FAIL, unable to determine OS type, check iDRAC connection function will not execute")
        run_network_connection_function = "fail"
    execute_command = subprocess.call(['ping', '%s' % ping_arg, '3', '%s' % idrac_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if execute_command != 0:
        ping_status = "lost"
    else:
        ping_status = "good"
        logging.debug("- PASS, ping response successful")
    if ping_status == "lost":
            logging.info("- INFO, iDRAC network connection lost due to slow network response, waiting 30 seconds to access iDRAC again")
            time.sleep(30)
            while True:
                if run_network_connection_function == "fail":
                    break
                execute_command = subprocess.call(['ping', '%s' % ping_arg, '3', '%s' % idrac_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if execute_command != 0:
                    ping_status = "lost"
                else:
                    ping_status = "good"
                if ping_status == "lost":
                    logging.info("- INFO, unable to ping iDRAC IP, script will wait 30 seconds and try again")
                    time.sleep(30)
                    continue
                else:
                    break
            while True:
                try:
                    if args["x"]:
                        response = requests.get('https://%s/redfish/v1/TaskService/Tasks/%s' % (idrac_ip, job_id), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
                    else:
                        response = requests.get('https://%s/redfish/v1/TaskService/Tasks/%s' % (idrac_ip, job_id), verify=verify_cert, auth=(idrac_username, idrac_password))
                except requests.ConnectionError as error_message:
                    logging.info("- INFO, GET request failed due to connection error, retry")
                    time.sleep(10)
                    continue
                break

def validate_new_version_installed():
    # Once update job ID is marked completed, code will get current version installed and compare against the package version, validate firmware applied was successful.
    logging.info("- INFO, getting new version installed to compare against available package version")
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.error("\n- ERROR, GET request failed to get current firmware version details, error: \n%s" % data)
        sys.exit(0)
    for i in data["Members"]:
        for ii in i.items():
            if "installed" in ii[1].lower():
                if args["x"]:
                    response = requests.get('https://%s%s' % (idrac_ip, ii[1]), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
                else:
                    response = requests.get('https://%s%s' % (idrac_ip, ii[1]), verify=verify_cert, auth=(idrac_username, idrac_password))
                    data = response.json()
                    if response.status_code != 200:
                        logging.error("\n- ERROR, GET request failed to get URI details for Name and Version, error: \n%s" % data)
                        sys.exit(0)
                    installed_entry_details = {"Name": data["Name"], "Version": data["Version"]}
                    if available_entry_details["Name"] == installed_entry_details["Name"]:
                        if available_entry_details["Version"] == installed_entry_details["Version"]:
                            logging.info("\n- PASS, successfully updated %s to version %s" % (installed_entry_details["Name"], installed_entry_details["Version"]))
                            sys.exit(0)
                        else:
                            logging.error("- FAIL, %s not updated to version %s, current installed version detected %s" % (installed_entry_details["Name"], available_entry_details["Version"], installed_entry_details["Version"]))
        
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
        if idrac_version == 10:
            logging.info("\n- INFO, iDRAC version detected does not support this script workflow")
            sys.exit(0)
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
        sys.exit(0)
    if args["location"] and args["image"]:
        download_image_payload()
        get_available_entry_version_compare_current_version()
        install_image_payload()
        check_job_status()
        loop_check_final_job_status()
        validate_new_version_installed()
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
