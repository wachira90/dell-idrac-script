#!/usr/bin/python3
#
# InsertEjectVirtualMediaREDFISH. Python script using Redfish API DMTF to either get virtual media information, insert or eject virtual media
#
# _author_ = Texas Roemer <Texas_Roemer@Dell.com>
# _version_ = 7.0
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

parser=argparse.ArgumentParser(description="Python script using Redfish API DMTF to either get virtual media information, insert or eject virtual media. Starting in iDRAC 6.00.00 version, you are now allowed to attach up to 2 virtual devices at once. See examples for more details on how to perform this.")
parser.add_argument('-ip',help='iDRAC IP address', required=False)
parser.add_argument('-u', help='iDRAC username', required=False)
parser.add_argument('-p', help='iDRAC password. If you do not pass in argument -p, script will prompt to enter user password which will not be echoed to the screen.', required=False)
parser.add_argument('-x', help='Pass in X-Auth session token for executing Redfish calls. All Redfish calls will use X-Auth token instead of username/password', required=False)
parser.add_argument('--ssl', help='SSL cert verification for all Redfish calls, pass in value \"true\" or \"false\". By default, this argument is not required and script ignores validating SSL cert for all Redfish calls.', required=False)
parser.add_argument('--script-examples', help='Return script examples for iDRAC 5.10 or older and iDRAC 6.00 and newer', action="store_true", required=False)
parser.add_argument('--get', help='Get current virtual media information', required=False, action="store_true")
parser.add_argument('--action', help='Pass in the type of action you want to perform for virtual media. Possible values: insert and eject', required=False)
parser.add_argument('--device', help='Pass in the device you want to insert or eject. Possible values: cd and removabledisk. This argument is only required/supported for iDRAC version 5.10 or older', required=False)
parser.add_argument('--index', help='Pass in remote device index. Pass in 1 for first device or 2 for second device. This argument is only required/supported for iDRAC version 6.00.00 or newer', required=False)
parser.add_argument('--uripath', help='Insert (attach) virtual media , pass in the HTTP or HTTPS URI path of the remote image. If using CIFS or NFS, pass in the remote image share path for mount. Note: If attaching removable disk, only supported file type is .img', required=False)
parser.add_argument('--username', help='Pass in the share username if using CIFS or secured HTTPS. Note if domain name required for CIFS share use the following syntax and surround the value with double quotes "DOMAIN_NAME/username"', required=False)
parser.add_argument('--password', help='Pass in the share username password if using CIFS or secured HTTPS. Note if your password is using special characters surround the string value with double quotes', required=False)
parser.add_argument('--write-protected', help='Write protect attached virtual media image, supported values: true and false. Pass in true to make attached virtual media read only or false to make attached virtual media read write. Note: If you do not pass in this argument, default value for write protected with be true.', dest="write_protected", required=False)
args = vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- InsertEjectVirtualMediaREDFISH.py -ip 192.168.0.120 -u root -p calvin --get, this example will get current virtual media devices status.
    \n- InsertEjectVirtualMediaREDFISH.py -ip 192.168.0.120 -u root -p calvin --action insert --index 1 --uripath //192.168.0.130/cifs/idsdm.img --username administrator --password P@ssword, this example shows attaching IMG image for virtual device index 1 (this example is only valid for iDRAC9 6.00 or newer and iDRAC10).
    \n- InsertEjectVirtualMediaREDFISH.py -ip 192.168.0.120 -u root -p calvin --action insert --index 2 --uripath //192.168.0.130/cifs/VMware-700-A01.iso --username administrator --password P@ssword, this example shows attaching CD ISO image for virtual device index 2 (this example is only valid for iDRAC9 6.00 or newer and iDRAC10)
    \n- InsertEjectVirtualMediaREDFISH.py -ip 192.168.0.120 -u root -p calvin --action insert --uripath //192.168.0.130/cifs/VMware-700-A01.iso --username administrator --password P@ssword- --device cd, this example shows attaching CD ISO image (this example is only valid for iDRAC9 5.10 or older).
    \n- InsertEjectVirtualMediaREDFISH.py -ip 192.168.0.120 -u root -p calvin --action insert --uripath //192.168.0.130/cifs/idsdm.img --username administrator --password P@ssword- --device removabledisk, this example shows attaching IMG image (this example is only valid for iDRAC9 5.10 or older).
    \n- InsertEjectVirtualMediaREDFISH.py -ip 192.168.0.120 -u root -p calvin --action eject --index 1, this example shows ejecting virtual media device index 1 (this example is only valid for iDRAC9 6.00 or newer and iDRAC10). 
    \n- InsertEjectVirtualMediaREDFISH.py -ip 192.168.0.120 -u root -p calvin --action eject --device cd, this example shows ejecting virtual media CD ISO image (this example is only valid for iDRAC9 5.10 or older). 
    \n- InsertEjectVirtualMediaREDFISH.py -ip 192.168.0.120 -u root -p calvin --action insert --index 1 --uripath http://192.168.0.130:8080/http_share/RHEL-9.1.x86_64-dvd1.iso --write-protected false, this example shows mounting HTTP share ISO as read write (this example is only valid for iDRAC9 6.00 or newer and iDRAC10).""")
    sys.exit(0)

def get_iDRAC_version():
    global iDRAC_version
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1?$select=FirmwareVersion' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1?$select=FirmwareVersion' % idrac_ip, verify=False,auth=(idrac_username,idrac_password))
    data = response.json()
    if response.status_code == 401:
        logging.error("\n- ERROR, status code 401 detected, check to make sure your iDRAC script session has correct username/password credentials or if using X-auth token, confirm the session is still active.")
        sys.exit(0)
    elif response.status_code != 200:
        logging.warning("\n- WARNING, unable to get current iDRAC version installed, status code %s returned" % response.status_code)
        sys.exit(0)
    iDRAC_version = int(data["FirmwareVersion"].split(".")[0])

def get_server_generation():
    global server_generation
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1?$select=Oem/Dell/DellSystem/SystemGeneration' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1?$select=Oem/Dell/DellSystem/SystemGeneration' % idrac_ip, verify=False,auth=(idrac_username,idrac_password))
    data = response.json()
    if response.status_code == 401:
        logging.error("- ERROR, status code 401 detected, check to make sure your iDRAC script session has correct username/password credentials or if using X-auth token, confirm the session is still active.")
        return
    elif response.status_code != 200:
        logging.warning("\n- WARNING, unable to get server generation, error: \n%s" % data)
        sys.exit(0)
    try:
        server_generation = data["Oem"]["Dell"]["DellSystem"]["SystemGeneration"]
    except:
        logging.error("- FAIL, unable to get server generation from JSON output")
        sys.exit(0)
            
def get_virtual_media_info():
    if iDRAC_version < 6 and "14G" in server_generation or iDRAC_version < 6 and "15G" in server_generation or iDRAC_version < 6 and "16G" in server_generation:
        if args["x"]:
            response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia?$expand=*($levels=1)' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
        else:
            response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia?$expand=*($levels=1)' % idrac_ip, verify=False,auth=(idrac_username,idrac_password))
    else:
        if args["x"]:
            response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/VirtualMedia?$expand=*($levels=1)' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
        else:
            response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/VirtualMedia?$expand=*($levels=1)' % idrac_ip, verify=False,auth=(idrac_username,idrac_password))
    if response.status_code == 401:
        logging.error("- ERROR, status code 401 detected, check to make sure your iDRAC script session has correct username/password credentials or if using X-auth token, confirm the session is still active.")
        return
    elif response.status_code != 200:
        logging.warning("\n- WARNING, unable to get current iDRAC version installed, status code %s returned" % response.status_code)
        data = response.json()
        print(data)
        sys.exit(0)
    data = response.json()
    print("\n - Virtual Media Device Details -\n")
    for i in data['Members']:
        pprint(i)
        print("\n")
        
def insert_virtual_media():
    if iDRAC_version < 6 and "14G" in server_generation or iDRAC_version < 6 and "15G" in server_generation or iDRAC_version < 6 and "16G" in server_generation:
        if args["index"]:
            logging.error("\n- ERROR, argument --index detected but not supported for current iDRAC version. See help text and examples for more details")
            sys.exit(0)
        elif args["action"].lower() == "insert" and args["device"].lower() == "cd":
            url = "https://%s/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/CD/Actions/VirtualMedia.InsertMedia" % idrac_ip
        elif args["action"].lower() == "insert" and args["device"].lower() == "removabledisk":
            url = "https://%s/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/RemovableDisk/Actions/VirtualMedia.InsertMedia" % idrac_ip
        else:
            logging.error("- FAIL, invalid value passed in for action or device argument")
            sys.exit(0)
    else:
        if args["device"]:
            logging.error("\n- ERROR, argument --device detected but not supported for current iDRAC version. See help text and examples for more details")
            sys.exit(0)
        else:
            url = "https://%s/redfish/v1/Systems/System.Embedded.1/VirtualMedia/%s/Actions/VirtualMedia.InsertMedia" % (idrac_ip, args["index"])
    if args["write_protected"]:
        if args["write_protected"].lower() == "true":
            write_protected_value = True
        elif args["write_protected"].lower() == "false":
            write_protected_value = False
    else:
        write_protected_value = True
    payload = {'Image': args["uripath"], 'Inserted':True,'WriteProtected':write_protected_value}
    if args["username"]:
        payload["UserName"] = args["username"]
    if args["password"]:
        payload["Password"] = args["password"]
    if args["x"]:
        headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
    else:
        headers = {'content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
    data = response.__dict__
    if response.status_code != 204:
        logging.error("\n- FAIL, POST command InsertMedia action failed, detailed error message: %s" % response._content)
        sys.exit(0)
    else:
        logging.info("\n- PASS, POST command passed to successfully insert virtual media, status code %s returned" % response.status_code)

def eject_virtual_media():
    if iDRAC_version < 6 and "14G" in server_generation or iDRAC_version < 6 and "15G" in server_generation or iDRAC_version < 6 and "16G" in server_generation:
        if args["index"]:
            logging.error("\n- ERROR, argument --index detected but not supported for current iDRAC version. See help text and examples for more details")
            sys.exit(0)
        elif args["action"].lower() == "eject" and args["device"].lower() == "cd":
            url = "https://%s/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/CD/Actions/VirtualMedia.EjectMedia" % idrac_ip
        elif args["action"].lower() == "eject" and args["device"].lower() == "removabledisk":
            url = "https://%s/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/RemovableDisk/Actions/VirtualMedia.EjectMedia" % idrac_ip
    else:
        if args["device"]:
            logging.error("\n- ERROR, argument --device detected but not supported for current iDRAC version. See help text and examples for more details")
            sys.exit(0)
        else:
            url = "https://%s/redfish/v1/Systems/System.Embedded.1/VirtualMedia/%s/Actions/VirtualMedia.EjectMedia" % (idrac_ip, args["index"])
    payload = {}
    if args["x"]:
        headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
    else:
        headers = {'content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
    data = response.__dict__
    if response.status_code != 204:
        logging.error("\n- FAIL, POST command EjectMedia action failed, detailed error message: %s" % response._content)
        sys.exit(0)
    else:
        logging.info("\n- PASS, POST command passed to successfully eject virtual media, status code %s returned" % response.status_code)
   
if __name__ == "__main__":
    if args["script_examples"]:
        script_examples()
    if args["ip"] or args["ssl"] or args["u"] or args["p"] or args["x"]:
        idrac_ip = args["ip"]
        idrac_username = args["u"]
        if args["p"]:
            idrac_password = args["p"]
        if not args["p"] and not args["x"] and args["u"]:
            idrac_password = getpass.getpass("\n- INFO, argument -p not detected, pass in iDRAC user %s password: " % args["u"])
        if args["ssl"]:
            if args["ssl"].lower() == "true":
                verify_cert = True
            elif args["ssl"].lower() == "false":
                verify_cert = False
            else:
                verify_cert = False
        else:
            verify_cert = False
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
        sys.exit(0)
    get_iDRAC_version()
    get_server_generation()
    if args["get"]:
        get_virtual_media_info()
    elif args["action"].lower() == "insert":
        insert_virtual_media()
    elif args["action"].lower() == "eject":
        eject_virtual_media()
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
