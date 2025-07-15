#!/usr/bin/python3
#
# CreateDeleteIdracUsersREDFISH.py Python script using Redfish API to either create or delete iDRAC user account.
#
# _author_ = Texas Roemer <Texas_Roemer@Dell.com>
# _version_ = 9.0
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

parser = argparse.ArgumentParser(description='Python script using Redfish API to either get user account details, create or delete iDRAC user account.')
parser.add_argument('-ip',help='iDRAC IP address', required=False)
parser.add_argument('-u', help='iDRAC username', required=False)
parser.add_argument('-p', help='iDRAC password. If you do not pass in argument -p, script will prompt to enter user password which will not be echoed to the screen.', required=False)
parser.add_argument('-x', help='Pass in X-Auth session token for executing Redfish calls. All Redfish calls will use X-Auth token instead of username/password', required=False)
parser.add_argument('--ssl', help='SSL cert verification for all Redfish calls, pass in value \"true\" or \"false\". By default, this argument is not required and script ignores validating SSL cert for all Redfish calls.', required=False)
parser.add_argument('--script-examples', help='Get executing script examples', action="store_true", dest="script_examples", required=False)
parser.add_argument('--get', help='Get current iDRAC user account information for all iDRAC ids.', action="store_true", required=False)
parser.add_argument('--get-custom-roles', help='Get current custom roles created. Note custom roles are only supported for iDRAC10 or newer versions.', action="store_true", dest="get_custom_roles", required=False)
parser.add_argument('--user-id', help='Pass in the iDRAC user account ID you want to create. Supported values are 2 to 16. Note on iDRAC10 this argument is optional, if you do not pass in argument new user created will get assigned the first available id.', dest="user_id", required=False)
parser.add_argument('--new-user', help='Pass in the name of the iDRAC user you want to create', dest="new_user", required=False)
parser.add_argument('--new-pwd', help='Pass in the password of the iDRAC user you are creating. If you do not pass in this argument, script will prompt you enter password.', dest="new_pwd", required=False)
parser.add_argument('--privilege-role', help='Pass in the privilege role for the user you are creating. Supported values are 1 for Administrator, 2 for Operator, 3 for ReadOnly for 4 for None. Note: (4)None value is only supported for iDRAC9 or older versions. Note iDRAC10 allows you to pass in a custom role for privilege, run --get-custom-roles argument to see if any custom roles are created. If custom role created pass in custom role string name.', dest="privilege_role", required=False)
parser.add_argument('--enable', help='Enable the new user you are creating, pass in \"y\" to enable, \"n\" to disable', required=False)
parser.add_argument('--delete', help='Delete iDRAC user, pass in the iDRAC user account id', required=False)

args=vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- CreateDeleteIdracUsersREDFISH..py -ip 192.168.0.120 -u root -p calvin --get, this example will get all iDRAC user account details.
    \n- CreateDeleteIdracUsersREDFISH.py -ip 192.168.0.120 -u root --user-id 3 --new-user tester --privilege-role 1 --enable y, this example will first prompt to enter password for user root. Then prompt to enter new password for user ID 3 and create this user.
    \n- CreateDeleteIdracUsersREDFISH.py -ip 192.168.0.120 -u root -p calvin --user-id 3 --new-user user3 --new-pwd test123 --privilege-role 2 --enable y, this example will create iDRAC user for id 3, enable and set privileges to operator.
    \n- CreateDeleteIdracUsersREDFISH.py -ip 192.168.0.120 -u root -p calvin --new-user tester --new-pwd test123 --privilege-role 1 --enable y, this example will create iDRAC user and assign first available ID, enable and set privileges to administrator. Note this example is only valid for iDRAC10 or newer.
    \n- CreateDeleteIdracUsersREDFISH.py -ip 192.168.0.120 -u root -p calvin --delete 3, this example will delete iDRAC user id 3.
    \n- CreateDeleteIdracUsersREDFISH.py -ip 192.168.0.120 -x c09c44e17e09372536428a6369bfa1b2 --delete 7, this example shows deleting user id 7 account using X-auth token session.""")
    sys.exit(0)

def check_supported_idrac_version():
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})   
    else:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1' % idrac_ip, verify=verify_cert,auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code == 401:
        logging.warning("\n- WARNING, status code %s returned. Incorrect iDRAC username/password or invalid privilege detected." % response.status_code)
        sys.exit(0)
    if response.status_code != 200:
        logging.warning("\n- WARNING, iDRAC version installed does not support this feature using Redfish API")
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

def get_current_custom_roles():
    uri = "redfish/v1/AccountService/Roles"
    if args["x"]:
        response = requests.get('https://%s/%s' % (idrac_ip, uri), verify=verify_cert, headers={'X-Auth-Token': args["x"]})   
    else:
        response = requests.get('https://%s/%s' % (idrac_ip, uri), verify=verify_cert,auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.error("\n- FAIL, status code %s returned for GET command. Detail error results: \n%s" % (statusCode, data))
        sys.exit(0)
    custom_role_uris = []
    for i in data["Members"]:
        for ii in i.items():
            if args["x"]:
                response = requests.get('https://%s%s' % (idrac_ip, ii[1]), verify=verify_cert, headers={'X-Auth-Token': args["x"]})   
            else:
                response = requests.get('https://%s%s' % (idrac_ip, ii[1]), verify=verify_cert,auth=(idrac_username, idrac_password))
            data = response.json()
            if response.status_code != 200:
                logging.error("\n- FAIL, status code %s returned for GET command. Detail error results: \n%s" % (statusCode, data))
                sys.exit(0)
            if data["Description"] == "Custom User Role":
                custom_role_uris.append(ii[1])
    if custom_role_uris == []:
        logging.warning("\n- WARNING, no custom roles detected")
    else:
        logging.info("\n- INFO custom iDRAC user role(s) detected\n")
        for i in custom_role_uris:
            if args["x"]:
                response = requests.get('https://%s%s' % (idrac_ip, i), verify=verify_cert, headers={'X-Auth-Token': args["x"]})   
            else:
                response = requests.get('https://%s%s' % (idrac_ip, i), verify=verify_cert,auth=(idrac_username, idrac_password))
            data = response.json()
            if response.status_code != 200:
                logging.error("\n- FAIL, status code %s returned for GET command. Detail error results: \n%s" % (statusCode, data))
                sys.exit(0)
            pprint(data)
            print("\n")

def create_idrac_user_password():
    payload = {"UserName":args["new_user"], "Password":args["new_pwd"]}
    if idrac_version >= 10:
        url = 'https://%s/redfish/v1/AccountService/Accounts' % idrac_ip
        if args["user_id"]:
            payload["Id"] = args["user_id"]
    else:
        url = 'https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Accounts/%s' % (idrac_ip, args["user_id"])
    if not args["new_pwd"]:
        args["new_pwd"] = getpass.getpass("\n- Argument --new-pwd not detected, pass in password for new user: ")
    if args["privilege_role"] == "1":
        payload["RoleId"] = "Administrator"
    elif args["privilege_role"] == "2":
        payload["RoleId"] = "Operator"
    elif args["privilege_role"] == "3":
        payload["RoleId"] = "ReadOnly"
    elif args["privilege_role"] == "4":
        payload["RoleId"] = "None"
    else:
        payload["RoleId"] =  args["privilege_role"]
    if args["enable"].lower() == "y":
        payload["Enabled"] = True
    elif args["enable"].lower() == "n":
        payload["Enabled"] = False
    else:
        logging.error("- FAIL, invalid value passed in for argument --enable")
        sys.exit(0)
    if idrac_version >= 10:
        if args["x"]:
            headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
            response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
        else:
            headers = {'content-type': 'application/json'}
            response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
        if "error" in response.json().keys():
            logging.error("\n- FAIL, POST command failed, detailed error results: \n%s" % response.json()["error"])
            sys.exit(0)
        if response.status_code == 201:
            logging.info("\n- PASS, status code %s returned for POST command to create iDRAC user \"%s\"" % (response.status_code, args["new_user"]))
        else:
            logging.error("\n- FAIL, POST command failed to create new user, status code %s returned" % response.status_code)
            print(response.json())
            sys.exit(0)   
    else:
        if args["x"]:
            headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
            response = requests.patch(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
        else:
            headers = {'content-type': 'application/json'}
            response = requests.patch(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
        if "error" in response.json().keys():
            logging.error("- FAIL, PATCH command failed, detailed error results: \n%s" % response.json()["error"])
            sys.exit(0)
        if response.status_code == 200:
            logging.info("\n- PASS, status code %s returned for PATCH command to create iDRAC user \"%s\"" % (response.status_code, args["new_user"]))
        else:
            logging.error("\n- FAIL, PATCH command failed to create new user, status code %s returned" % response.status_code)
            print(response.json())
            sys.exit(0)

def delete_idrac_user():
    if idrac_version >= 10:
        url = 'https://%s/redfish/v1/AccountService/Accounts/%s' % (idrac_ip, args["delete"])
        if args["x"]:
            headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
            response = requests.delete(url, headers=headers, verify=verify_cert)
        else:
            headers = {'content-type': 'application/json'}
            response = requests.delete(url, headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
        if response.status_code == 204:
            logging.info("\n- PASS: DELETE command passed to delete iDRAC user account, status code 204 returned")
        else:
            logging.error("\n- FAIL, DELETE command failed to delete iDRAC user account, status code %s returned" % response.status_code)
            data = response.json()
            logging.error("\n- DELETE command failure:\n %s" % data)
            sys.exit(0)
    elif idrac_version == 9:
        url = 'https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1' % (idrac_ip)
        payload = {"Attributes":{"Users.%s.UserName" % args["delete"]:"","Users.%s.Privilege" % args["delete"]:0,"Users.%s.Enable" % args["delete"]:"Disabled","Users.%s.IPMIKey" % args["delete"]:"","Users.%s.MD5v3Key" % args["delete"]:"","Users.%s.SHA1v3Key" % args["delete"]:"","Users.%s.SHA256PasswordSalt" % args["delete"]:""}}
        if args["x"]:
            headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
            response = requests.patch(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
        else:
            headers = {'content-type': 'application/json'}
            response = requests.patch(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
        data = response.json()
        if response.status_code != 200:
            logging.info("\n- FAIL, PATCH command failed to delete iDRAC user, status code %s returned. Detailed error results %s" % (response.status_code, data))
            sys.exit(0)
        else:
            logging.info("\n- PASS, iDRAC user id %s successfully deleted" % args["delete"])
    else:
        url = 'https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Accounts/%s' % (idrac_ip, args["delete"])
        payload = {"Enabled":False,"RoleId":"None"}
        if args["x"]:
            headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
            response = requests.patch(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
        else:
            headers = {'content-type': 'application/json'}
            response = requests.patch(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
        data = response.json()
        if response.status_code != 200:
            logging.info("\n- FAIL, status code %s returned, iDRAC user not deleted. Detailed error results %s" % (response.status_code, data))
            sys.exit(0)
        payload = {"UserName":""}
        if args["x"]:
            headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
            response = requests.patch(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
        else:
            headers = {'content-type': 'application/json'}
            response = requests.patch(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
        data = response.json()
        if response.status_code == 200:
            logging.info("\n- PASS, iDRAC user id %s successfully deleted" % args["delete"])
        else:
            logging.error("\n- FAIL, status code %s returned, iDRAC user not deleted. Detailed error results %s" % (response.status_code, data))
            sys.exit(0)

def get_iDRAC_user_account_info():
    if idrac_version >= 10:
        uri = "redfish/v1/AccountService/Accounts?$expand=*($levels=1)"
    else:
        uri = "redfish/v1/Managers/iDRAC.Embedded.1/Accounts?$expand=*($levels=1)"
    if args["x"]:
        response = requests.get('https://%s/%s' % (idrac_ip, uri), verify=verify_cert, headers={'X-Auth-Token': args["x"]})   
    else:
        response = requests.get('https://%s/%s' % (idrac_ip, uri), verify=verify_cert,auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.error("\n- FAIL, status code %s returned for GET command. Detail error results: \n%s" % (statusCode, data))
        sys.exit(0)
    logging.info("\n- iDRAC User Account Information -")
    for i in data["Members"]:
        pprint(i)
        print("\n")
        
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
        get_server_generation()
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
        sys.exit(0)
    if args["new_user"] and args["new_pwd"]:
        create_idrac_user_password()
    elif args["delete"]:
        delete_idrac_user()
    elif args["get_custom_roles"]:
        get_current_custom_roles()
    elif args["get"]:
        get_iDRAC_user_account_info()   
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
