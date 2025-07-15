#!/usr/bin/python3
#
# DellSwitchConnectionCollectionREDFISH.py   Python script using Redfish API with OEM extension to get Dell switch network connections. 
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
import platform
import requests
import sys
import time
import warnings

from pprint import pprint

warnings.filterwarnings("ignore")

parser=argparse.ArgumentParser(description="Python script using Redfish API with OEM extension to get Dell switch network connections")
parser.add_argument('-ip',help='iDRAC IP address', required=False)
parser.add_argument('-u', help='iDRAC username', required=False)
parser.add_argument('-p', help='iDRAC password. If you do not pass in argument -p, script will prompt to enter user password which will not be echoed to the screen.', required=False)
parser.add_argument('-x', help='Pass in X-Auth session token for executing Redfish calls. All Redfish calls will use X-Auth token instead of username/password', required=False)
parser.add_argument('--ssl', help='SSL cert verification for all Redfish calls, pass in value \"true\" or \"false\". By default, this argument is not required and script ignores validating SSL cert for all Redfish calls.', required=False)
parser.add_argument('--script-examples', action="store_true", help='Prints script examples')

args=vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- DellSwitchConnectionCollectionREDFISH.py -ip 192.168.0.120 -u root -p calvin, this example will return Dell switch network connection details.""")
    sys.exit(0)

def check_supported_idrac_version():
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code == 401:
        logging.warning("\n- WARNING, status code %s returned. Incorrect iDRAC username/password or invalid privilege detected." % response.status_code)
        sys.exit(0)
    if response.status_code != 200:
        logging.warning("\n- WARNING, GET request failed to validate iDRAC connection.")
        print(data)
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

def get_Dell_switch_connections():
    if idrac_version == 9:
        if args["x"]:
            response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/NetworkPorts/Oem/Dell/DellSwitchConnections' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
        else:
            response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/NetworkPorts/Oem/Dell/DellSwitchConnections' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    elif idrac_version >= 9:
        if args["x"]:
            response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Oem/Dell/DellSwitchConnections' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
        else:
            response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Oem/Dell/DellSwitchConnections' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    else:
        logging.error("- WARNING, iDRAC version detected does not support this operation")
        sys.exit(0)
    data = response.json()
    if response.status_code != 200:
        logging.info("\n- FAIL, GET command failed to get Dell switch connection collection, status code %s, error is %s" % (response.status_code, data))
        sys.exit()
    else:
        logging.info("\n- Dell switch connection collection for iDRAC %s -\n" % idrac_ip)
    for i in data.items():
        pprint(i)
        print("\n")

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
        get_server_generation()
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
        sys.exit(0)
    get_Dell_switch_connections()
