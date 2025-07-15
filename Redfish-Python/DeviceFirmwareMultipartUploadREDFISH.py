#!/usr/bin/python3
#
# DeviceFirmwareMultipartUploadREDFISH.py. Python script using Redfish API to update a device firmware with DMTF MultipartUpload. Supported file image types are Windows DUPs, d7/d9 image or pm files.
#
# _author_ = Texas Roemer <Texas_Roemer@Dell.com>
# _version_ = 10.0
#
# Copyright (c) 2020, Dell, Inc.
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

parser=argparse.ArgumentParser(description="Python script using Redfish API to update a device firmware with DMTF MultipartUpload from a local directory")
parser.add_argument('-ip',help='iDRAC IP address', required=False)
parser.add_argument('-u', help='iDRAC username', required=False)
parser.add_argument('-p', help='iDRAC password. If you do not pass in argument -p, script will prompt to enter user password which will not be echoed to the screen.', required=False)
parser.add_argument('-x', help='Pass in X-Auth session token for executing Redfish calls. All Redfish calls will use X-Auth token instead of username/password', required=False)
parser.add_argument('--ssl', help='SSL cert verification for all Redfish calls, pass in value \"true\" or \"false\". By default, this argument is not required and script ignores validating SSL cert for all Redfish calls.', required=False)
parser.add_argument('--script-examples', action="store_true", help='Prints script examples')
parser.add_argument('--get', help='Get current supported devices for firmware updates and their current firmware versions', action="store_true", required=False)
parser.add_argument('--location', help='Pass in the full directory path location of the firmware image. Make sure to also pass in the name of the Dell Update package (DUP) executable, example: C:\\Users\\admin\\Downloads\\Diagnostics_Application_CH7FG_WN64_4301A42_4301.43.EXE', required=False)
parser.add_argument('--reboot', help='Pass in this argument to reboot the server now to perform the update. If you do not pass in this argument, update job is still scheduled and will get applied on next server manual reboot. Note: For devices that do not need a reboot to apply the firmware update (Examples: iDRAC, DIAGS, Driver Pack), you don\'t need to pass in this agrument(update will happen immediately). See Lifecycle Controller User Guide firmware update section for more details on which devices get applied immediately or need a reboot to get updated', action="store_true", required=False)

args=vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- DeviceFirmwareMultipartUploadREDFISH.py -ip 192.168.0.120 -u root -p calvin --get, this example will get current firmware versions for all devices in the server.
    \n- DeviceFirmwareMultipartUploadREDFISH.py -ip 192.168.0.120 -u root --location C:\\Users\\administrator\\Downloads\\BIOS_8MRPC_C6420_WN64_2.11.2.EXE --reboot, this example will first prompt to enter iDRAC user password, then reboot the server now to execute BIOS firmware update.""")
    sys.exit(0)
    
def check_supported_idrac_version():
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/UpdateService' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/UpdateService' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code == 401:
        logging.warning("\n- WARNING, status code %s returned, check your iDRAC username/password is correct or iDRAC user has correct privileges to execute Redfish commands" % response.status_code)
        sys.exit(0)
    if 'MultipartHttpPushUri' not in data.keys():
        logging.warning("\n- WARNING, iDRAC version installed does not support this feature using Redfish API")
        sys.exit(0)   

def get_idrac_version():
    global idrac_fw_version
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1?$select=FirmwareVersion' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1?$select=FirmwareVersion' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.error("\n- ERROR, GET request failed to get iDRAC firmware version, error: \n%s" % data)
        sys.exit(0)
    idrac_fw_version = data["FirmwareVersion"].replace(".","")

def get_server_generation():
    global idrac_model
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
    if "14" in data["Model"] or "15" in data["Model"] or "16" in data["Model"]:
        idrac_model = 9
    else:
        idrac_model = 10
    
def get_FW_inventory():
    logging.info("\n- INFO, getting current firmware inventory for iDRAC %s -\n" % idrac_ip)
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory?$expand=*($levels=1)' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory?$expand=*($levels=1)' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.error("\n- ERROR, GET request failed to get firmware inventory, error: \n%s" % data)
        sys.exit(0)
    installed_devices = []
    for i in data['Members']:
        pprint(i)
        print("\n")

def download_image_create_update_job():
    global job_id
    global start_time
    start_time = datetime.now()
    logging.info("\n- INFO, downloading update package to create update job, this may take a few minutes depending on firmware image size")
    url = "https://%s/redfish/v1/UpdateService/MultipartUpload" % idrac_ip
    if args["reboot"]:
        payload = {"Targets": [], "@Redfish.OperationApplyTime": "Immediate", "Oem": {}}
    else:
        payload = {"Targets": [], "@Redfish.OperationApplyTime": "OnReset", "Oem": {}}
    files = {
         'UpdateParameters': (None, json.dumps(payload), 'application/json'),
         'UpdateFile': (os.path.basename(args["location"]), open(args["location"], 'rb'), 'application/octet-stream')
    }

    if args["x"]:
        headers = {'X-Auth-Token': args["x"]}
        response = requests.post(url, files=files, headers=headers, verify=verify_cert)
    else:
        response = requests.post(url, files=files, verify=verify_cert,auth=(idrac_username,idrac_password))
    
    if response.status_code != 202:
        data = response.json()
        logging.error("- FAIL, status code %s returned, detailed error: %s" % (response.status_code,data))
        sys.exit(0)
    try:
        job_id = response.headers['Location'].split("/")[-1]
    except:
        logging.error("- FAIL, unable to locate job ID in header")
        sys.exit(0)
    logging.info("- PASS, update job ID %s successfully created, script will now loop polling the job status\n" % job_id)
    time.sleep(10)
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/TaskService/Tasks/%s' % (idrac_ip, job_id), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/TaskService/Tasks/%s' % (idrac_ip, job_id), verify=verify_cert, auth=(idrac_username, idrac_password))
    if response.status_code == 200 or response.status_code == 202:
        data = response.json()
        time.sleep(1)
    elif response.status_code == 401:
        logging.warning("\n- WARNING, status code 401 detected for authentication credential failure, if iDRAC or CPLD/FPGA update is being performed and using X-auth token, the X-auth token session is deleted due to iDRAC reboot, please manually check the job queue to confirm final job status.")
        sys.exit(0)
    else:
        data = response.json()
        logging.error("\n- ERROR, GET request failed to get job ID details, status code %s returned, error: \n%s" % (response.status_code, data))
        sys.exit(0)
    if "cpld" in data["Name"].lower() or "fpga" in data["Name"].lower():
        logging.info("- INFO, CPLD/FPGA update detected, once the update is complete virtual a/c cycle will be performed. GET request to poll the job status will start failing which is expected")

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
                elif response.status_code == 401:
                    logging.warning("\n- WARNING, status code 401 detected for authentication credential failure, if iDRAC or CPLD/FPGA update is being performed and using X-auth token, the X-auth token session is deleted due to iDRAC reboot, please manually check the job queue to confirm final job status.")
                    sys.exit(0)
                else:
                    logging.error("\n- ERROR, GET request failed to get job ID details, status code%s returned, error: \n%s" % (response.status_code, data))
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
        elif response.status_code == 401:
            logging.warning("\n- WARNING, status code 401 detected for authentication credential failure, if iDRAC or CPLD/FPGA update is being performed and using X-auth token, the X-auth token session is deleted due to iDRAC reboot, please manually check the job queue to confirm final job status.")
            sys.exit(0)
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
                elif response.status_code == 401:
                    logging.warning("\n- WARNING, status code 401 detected for authentication credential failure, if iDRAC or CPLD/FPGA update is being performed and using X-auth token, the X-auth token session is deleted due to iDRAC reboot, please manually check the job queue to confirm final job status.")
                    sys.exit(0)
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
                    break
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
            if response.status_code == 500:
                logging.info("- WARNING, iDRAC connection lost, script will sleep 3 minutes and then retry GET request")
                time.sleep(180)
                check_idrac_connection()
                continue
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
            logging.info("- INFO, GET request failed due to connection error, retry")
            time.sleep(10)
            retry_count += 1
            continue
        except requests.exceptions.RequestException as req_error:
            print("RequestException:", req_error)
            time.sleep(180)
            retry_count += 1
            continue
        current_time = str((datetime.now()-start_time))[0:7]
        data = response.json()
        if response.status_code == 200 or response.status_code == 202:
            logging.debug("- PASS, GET request passed to check job status")
        else:
            logging.error("\n- FAIL, GET command failed to check job status, return code %s" % response.status_code)
            logging.error("Extended Info Message: {0}".format(response.json()))
            sys.exit(0)
        if str(current_time)[0:7] >= "0:30:00":
            logging.error("\n- FAIL: Timeout of 30 minutes has been hit, script stopped\n")
            sys.exit(0)
        elif "Fail" in data['Message'] or "fail" in data['Message'] or "fail" in data['JobState'] or "Fail" in data['JobState']:
            logging.error("- FAIL: job ID %s failed" % job_id)
            sys.exit(0)
        elif "completed successfully" in data['Message'].lower() or "successfully completed" in data['Message'].lower():
            logging.info("\n- PASS, job ID %s successfully marked completed" % job_id)
            logging.info("\n- Final detailed job results -\n")
            for i in data.items():
                pprint(i)
            logging.info("\n- JOB ID %s completed in %s" % (job_id, current_time))
            sys.exit(0)
        else:
            logging.info("- INFO, JobStatus not completed, current status: \"%s\", execution time: \"%s\"" % (data['Message'].rstrip("."), current_time))
            time.sleep(1)

def oem_ac_power_cycle():
    if args["x"]:
         response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1?$select=PowerState' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1?$select=PowerState' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.warning("\n- WARNING, GET request failed to get current server power state, status code %s returned." % response.status_code)
        logging.warning(data)
        sys.exit(0)
    if data["PowerState"].lower() == "off":
        logging.info("- INFO, server already in OFF state, skipping power off operation")
        return
    url = "https://%s/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset" % idrac_ip
    payload = {"ResetType": "ForceOff"}
    if args["x"]:
        headers = {"content-type": "application/json", "X-Auth-Token": args["x"]}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
    else:
        headers = {"content-type": "application/json"}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert, auth=(idrac_username, idrac_password))
    if response.status_code == 204:
        logging.info("\n- PASS, POST command passed to power off the server")
        time.sleep(10)
    else:
        logging.error("\n- FAIL, POST command failed, status code %s returned\n" % response.status_code)
        logging.error(response.json())
        sys.exit(1) 
    url = 'https://%s/redfish/v1/Chassis/System.Embedded.1/Actions/Oem/DellOemChassis.ExtendedReset' % idrac_ip
    payload = {"ResetType": "PowerCycle", "FinalPowerState":"On"}   
    if args["x"]:
        headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
    else:
        headers = {'content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert, auth=(idrac_username, idrac_password))
    if response.status_code == 204:
        logging.info("\n- PASS, POST command passed to perform full virtual server a/c power cycle, status code %s returned" % response.status_code)
        logging.info("\n- INFO, wait a few minutes for the process to complete, server will automatically power back on")
    else:
        logging.error("\n- FAIL, POST command failed, status code %s returned\n" % response.status_code)
        logging.error(response.json())
        sys.exit(1)

def reboot_server():
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})   
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert,auth=(idrac_username, idrac_password))
    data = response.json()
    logging.info("- INFO, Current server power state is: %s" % data['PowerState'])
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
    if args["get"]:
        get_FW_inventory()
    elif args["location"]:
        get_idrac_version()
        download_image_create_update_job()
        check_job_status()
        if args["reboot"]:
            logging.info("- INFO, powering on or rebooting server to apply the firmware")
            loop_check_final_job_status()
        else:
            logging.info("- INFO, argument --reboot not detected. Update job is marked as scheduled and will be applied on next server reboot")
            sys.exit(0)
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
