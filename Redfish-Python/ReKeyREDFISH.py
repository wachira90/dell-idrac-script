#!/usr/bin/python3
#
# RekeyREDFISH. Python script using Redfish API with OEM extension to rekey or change the controller encryption key
#
# _author_ = Texas Roemer <Texas_Roemer@Dell.com>
# _version_ = 8.0
#
# Copyright (c) 2018, Dell, Inc.
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

parser=argparse.ArgumentParser(description="Python script using Redfish API with OEM extension to rekey or change the controller encryption key")
parser.add_argument('-ip',help='iDRAC IP address', required=False)
parser.add_argument('-u', help='iDRAC username', required=False)
parser.add_argument('-p', help='iDRAC password', required=False)
parser.add_argument('--ssl', help='Verify SSL certificate for all Redfish calls, pass in \"true\". This argument is optional, if you do not pass in this argument, all Redfish calls will ignore SSL cert checks.', required=False)
parser.add_argument('-x', help='Pass in iDRAC X-auth token session ID to execute all Redfish calls instead of passing in username/password', required=False)
parser.add_argument('--script-examples', help='Get executing script examples', action="store_true", dest="script_examples", required=False)
parser.add_argument('--get-controllers', help='Get server storage controller FQDDs', dest="get_controllers", action="store_true", required=False)
parser.add_argument('--get-controller-encryption', help='Get current controller encryption mode settings, pass in controller FQDD, Example RAID.Slot.6-1', dest="get_controller_encryption", required=False)
parser.add_argument('--rekey', help='Rekey the controller key, pass in controller FQDD, Example RAID.Slot.6-1', required=False)
parser.add_argument('--mode', help='Rekey the controller key, pass in encryption mode. Supported values are LKM (Local Key Management) and SEKM (Secure Enterprise Key Management). NOTE: If using LKM mode, you must also use arguments --oldkey, --newkey and -i', required=False)
parser.add_argument('--oldpassphrase', help='Pass in current(old) storage controller key passphrase', required=False)
parser.add_argument('--newpassphrase', help='Pass in the new storage controller key passphrase you want to set to. Note: Minimum length is 8 characters, must have at least 1 upper and 1 lowercase, 1 number and 1 special character Example \"Test123##\". Refer to Dell PERC documentation for more information.', required=False)
parser.add_argument('--keyid', help='Pass in the current controller key id or pass in a new key id string to set', required=False)

args=vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO) 

def script_examples():
    print("""\n- ReKeyREDFISH.py -ip 192.168.0.120 -u root -p calvin --get-controllers, this example will return storage controller FQDDs detected.
    \n- ReKeyREDFISH.py -ip 192.168.0.120 -x 82a57f88c4c7f339c1fb2ce105798bbc --get-controller-encryption RAID.Mezzanine.1-1 --ssl true, this example shows checking controller encryption mode settings and all Redfish calls will perform SSL cert validation and use X-auth token session.
    \n- ReKeyREDFISH.py -ip calvin -u root --rekey RAID.Mezzanine.1-1 --mode LKM --keyid H740_KEY, this example will prompt to enter iDRAC user password, current passphrase and new passphrase, then execute rekey command.
    \n- ReKeyREDFISH.py -ip 192.168.0.120 -u root -p calvin --rekey RAID.Slot.6-1 --oldpassphrase Test123## --newpassphrase Test123!! --keyid newkey --mode LKM, this example is going to change the controller LKM key along with changing the controller key id.""")
    sys.exit(0)

def check_supported_idrac_version():
    if args["x"]:
         response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Oem/Dell/DellRaidService' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Oem/Dell/DellRaidService' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code == 401:
        logging.warning("\n- WARNING, status code %s returned. Incorrect iDRAC username/password or invalid privilege detected." % response.status_code)
        sys.exit(0)
    if response.status_code != 200:
        logging.warning("\n- WARNING, iDRAC version installed does not support this feature using Redfish API")
        sys.exit(0)

def get_storage_controllers():
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage' % idrac_ip,verify=verify_cert, headers={'X-Auth-Token': args["x"]})   
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage' % idrac_ip,verify=verify_cert,auth=(idrac_username, idrac_password))
    data = response.json()
    logging.info("\n- Server controller(s) detected -\n")
    controller_list=[]
    for i in data['Members']:
        controller_list.append(i['@odata.id'].split("/")[-1])
        print(i['@odata.id'].split("/")[-1])

def get_controller_encryption_setting():
    test_valid_controller_FQDD_string(args["get_controller_encryption"])
    if args["x"]:
         response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s' % (idrac_ip, args["get_controller_encryption"]), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s' % (idrac_ip, args["get_controller_encryption"]), verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.warning("\n- WARNING, GET request failed to get controller encryption mode details, status code %s returned" % response.status_code)
        logging.error(data)
        sys.exit(0)
    logging.info("\n- Encryption Details for Controller %s -\n" % args["get_controller_encryption"])
    for i in data["Oem"]["Dell"]["DellController"].items():
        if i[0] == "EncryptionCapability" or i[0] == "EncryptionMode" or i[0] == "KeyID":
            print("%s: %s" % (i[0], i[1]))
    
def rekey_controller_key():
    global job_id
    test_valid_controller_FQDD_string(args["rekey"])
    method = "ReKey"
    if args["x"]:
         response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s' % (idrac_ip, args["rekey"]), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s' % (idrac_ip, args["rekey"]), verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if data['Oem']['Dell']['DellController']['SecurityStatus'] == "EncryptionNotCapable":
        logging.warning("\n- WARNING, storage controller %s does not support encryption" % args["rekey"])
        sys.exit(0)
    url = 'https://%s/redfish/v1/Systems/System.Embedded.1/Oem/Dell/DellRaidService/Actions/DellRaidService.ReKey' % (idrac_ip)
    if args["mode"].upper() == "LKM":
        if not args["oldpassphrase"] and not args["newpassphrase"]:
            args["oldpassphrase"] = getpass.getpass("\n- Argument --oldpassphrase not detected, pass in old(current) value: ")
            args["newpassphrase"] = getpass.getpass("\n- Argument --newpassphrase not detected, pass in new value: ")    
        payload={"Mode":"LKM","TargetFQDD":args["rekey"],"OldKey":args["oldpassphrase"],"NewKey":args["newpassphrase"],"Keyid":args["keyid"]}
    elif args["mode"].upper() == "SEKM":
        payload={"Mode":"SEKM","TargetFQDD":args["rekey"]}
    else:
        logging.error("- FAIL, missing required parameters(s)")
        sys.exit(0)
    if args["x"]:
        headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
    else:
        headers = {'content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
    data = response.json()
    if response.status_code == 202:
        logging.info("\n- PASS: POST command passed to rekey the controller for %s" % args["rekey"])
        try:
            job_id = response.headers['Location'].split("/")[-1]
        except:
            logging.error("- FAIL, unable to locate job ID in JSON headers output")
            sys.exit(0)
        logging.info("- Job ID %s successfully created for storage method \"%s\"" % (job_id, method)) 
    else:
        logging.error("\n- FAIL, POST command failed to set the controller key for controller %s" % args["rekey"])
        data = response.json()
        logging.error("\n- POST command failure results:\n %s" % data)
        sys.exit(0)

def loop_job_status():
    start_time = datetime.now()
    while True:
        if args["x"]:
            response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs/%s' % (idrac_ip, job_id), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
        else:
            response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs/%s' % (idrac_ip, job_id), verify=verify_cert,auth=(idrac_username, idrac_password))
        current_time = (datetime.now()-start_time)
        if response.status_code != 200:
            logging.error("\n- FAIL, GET command failed to check job status, return code is %s" % statusCode)
            logging.error("Extended Info Message: {0}".format(req.json()))
            sys.exit(0)
        data = response.json()
        if str(current_time)[0:7] >= "2:00:00":
            logging.error("\n- FAIL: Timeout of 2 hours has been hit, script stopped\n")
            sys.exit(0)
        elif "Fail" in data['Message'] or "fail" in data['Message'] or data['JobState'] == "Failed":
            logging.error("- FAIL: job ID %s failed, failed message is: %s" % (job_id, data['Message']))
            sys.exit(0)
        elif data['JobState'] == "Completed":
            logging.info("\n--- PASS, Final Detailed Job Status Results ---\n")
            for i in data.items():
                if "odata" not in i[0] or "MessageArgs" not in i[0] or "TargetSettingsURI" not in i[0]:
                    print("%s: %s" % (i[0],i[1]))
            break
        else:
            logging.info("- INFO, job status not completed, current status: \"%s\"" % data['Message'])
            time.sleep(3)

def test_valid_controller_FQDD_string(x):
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s' % (idrac_ip, x),verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s' % (idrac_ip, x),verify=verify_cert,auth=(idrac_username, idrac_password))
    if response.status_code != 200:
        logging.error("\n- FAIL, either controller FQDD does not exist or typo in FQDD string name (FQDD controller string value is case sensitive)")
        sys.exit(0)
    
if __name__ == "__main__":
    if args["script_examples"]:
        script_examples()
    if args["ip"] and args["ssl"] or args["u"] or args["p"] or args["x"]:
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
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
        sys.exit(0)
    if args["get_controllers"]:
        get_storage_controllers()
    elif args["get_controller_encryption"]:
        get_controller_encryption_setting()
    elif args["rekey"] and args["mode"]:
        rekey_controller_key()
        loop_job_status()
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
        sys.exit(0)
