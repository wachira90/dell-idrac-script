#!/usr/bin/python3
#
# BiosResetToDefaultsREDFISH. Python script using Redfish API DMTF action to reset BIOS to default settings
#
# _author_ = Texas Roemer <Texas_Roemer@Dell.com>
# _version_ = 5.0
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

parser=argparse.ArgumentParser(description="Python script using Redfish API DMTF action to reset BIOS to default settings")
parser.add_argument('-ip',help='iDRAC IP address', required=False)
parser.add_argument('-u', help='iDRAC username', required=False)
parser.add_argument('-p', help='iDRAC password. If you do not pass in argument -p, script will prompt to enter user password which will not be echoed to the screen.', required=False)
parser.add_argument('-x', help='Pass in X-Auth session token for executing Redfish calls. All Redfish calls will use X-Auth token instead of username/password', required=False)
parser.add_argument('--ssl', help='SSL cert verification for all Redfish calls, pass in value true or false. By default, this argument is not required and script ignores validating SSL cert for all Redfish calls.', required=False)
parser.add_argument('--script-examples', help='Get executing script examples', action="store_true", dest="script_examples", required=False)
parser.add_argument('--get', help='Get current flag setting for BIOS reset to defaults.', action="store_true", required=False)
parser.add_argument('--noreboot', help='Pass in this argument to not reboot the server now to reset BIOS to default settings. Flag will still be set and reset to defaults will happen on next server reboot.', action="store_true", required=False)

args=vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- BiosResetToDefaultsREDFISH.py -ip 192.168.0.120 -u root -p calvin, this example will reboot the server now to perform BIOS reset to defaults operation.
    \n- BiosResetToDefaultsREDFISH.py -ip 192.168.0.120 -u root -p calvin --get, this example will check current BIOS reset to default flag.
    \n- BiosResetToDefaultsREDFISH.py -ip 192.168.0.120 -x 7041fd6528bc5d9d88a34cdc14bf133a, this example using iDRAC X-auth token session will reboot the server now to perform BIOS reset to defaults operation.""")
    sys.exit(0)

def check_supported_idrac_version():
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Bios' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})   
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Bios' % idrac_ip, verify=verify_cert,auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code == 401:
        logging.warning("\n- WARNING, status code %s returned. Incorrect iDRAC username/password or invalid privilege detected." % response.status_code)
        sys.exit(0)
    if response.status_code != 200:
        logging.warning("\n- WARNING, iDRAC version installed does not support this feature using Redfish API")
        sys.exit(0)

def check_bios_rtd_flag():
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/LifecycleController.Embedded.1?$select=Attributes/LCAttributes.1.BIOSRTDRequested' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})   
    else:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/LifecycleController.Embedded.1?$select=Attributes/LCAttributes.1.BIOSRTDRequested' % idrac_ip, verify=verify_cert,auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.error("\n- FAIL, GET command failed to check BIOS reset to default flag, status code %s returned" % response.status_code)
        sys.exit(0)
    logging.info("\n- BIOS reset to default flag current setting: %s" % data["Attributes"]["LCAttributes.1.BIOSRTDRequested"])

def reset_bios():
    url = "https://%s/redfish/v1/Systems/System.Embedded.1/Bios/Actions/Bios.ResetBios" % idrac_ip
    payload = {}
    if args["x"]:
        headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
    else:
        headers = {'content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
    data = response.__dict__
    message_search = str(data['_content'])
    if response.status_code == 200:
        logging.info("\n- PASS: status code %s returned for POST command to reset BIOS to default settings" % response.status_code)
    else:
        logging.error("\n- FAIL, Command failed, status code is %s" % response.status_code)
        detail_message = str(response.__dict__)
        logging.error(detail_message)
        sys.exit(0)
                                                                          
def reboot_server():
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
            logging.info("- PASS, POST command passed to gracefully power OFF server, status code return is %s" % response.status_code)
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
                    logging.info("- PASS, POST command passed to perform forced shutdown, status code return is %s" % response.status_code)
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
            logging.info("- PASS, Command passed to power ON server, status code return is %s" % response.status_code)
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

if __name__ == "__main__":
    if args["script_examples"]:
        script_examples()
    if args["ip"] and args["ssl"] or args["u"] or args["p"] or args["x"]:
        idrac_ip=args["ip"]
        idrac_username=args["u"]
        if args["p"]:
            idrac_password=args["p"]
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
    if args["get"]:
        check_bios_rtd_flag()
    else:
        reset_bios()
        if args["noreboot"]:
            logging.info("- INFO, --noreboot argument detected. Rest to defaults flag is still set and will happen on next server manual reboot")
        else:
            logging.info("- INFO, rebooting server to perform BIOS reset to defaults operation")
            reboot_server()
