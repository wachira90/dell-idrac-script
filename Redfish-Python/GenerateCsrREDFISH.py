#!/usr/bin/python3
#
# _author_ = Texas Roemer <Texas_Roemer@Dell.com>
# _version_ = 7.0
#
# Copyright (c) 2021, Dell, Inc.
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

parser=argparse.ArgumentParser(description="Python script using Redfish API to either get current iDRAC certs or generate CSR for iDRAC.")
parser.add_argument('-ip',help='iDRAC IP address', required=False)
parser.add_argument('-u', help='iDRAC username', required=False)
parser.add_argument('-p', help='iDRAC password. If you do not pass in argument -p, script will prompt to enter user password which will not be echoed to the screen.', required=False)
parser.add_argument('-x', help='Pass in X-Auth session token for executing Redfish calls. All Redfish calls will use X-Auth token instead of username/password', required=False)
parser.add_argument('--ssl', help='SSL cert verification for all Redfish calls, pass in value \"true\" or \"false\". By default, this argument is not required and script ignores validating SSL cert for all Redfish calls.', required=False)
parser.add_argument('--script-examples', action="store_true", help='Prints script examples')
parser.add_argument('--get', help='Get current iDRAC certs', action="store_true", required=False)
parser.add_argument('--generate', help='Generate iDRAC CSR. You must also pass in arguments city, state, commonname, country, email, org, orgunit for generating CSR.', action="store_true", required=False)
parser.add_argument('--city', help='Generate iDRAC CSR, pass in city string value', required=False)
parser.add_argument('--state', help='Generate iDRAC CSR, pass in state string value', required=False)
parser.add_argument('--commonname', help='Generate iDRAC CSR, pass in common name string value', required=False)
parser.add_argument('--country', help='Generate iDRAC CSR, pass in common name string value', required=False)
parser.add_argument('--email', help='Generate iDRAC CSR, pass in email string value. Note: This argument is optional for generate CSR.', required=False)
parser.add_argument('--org', help='Generate iDRAC CSR, pass in organization string value', required=False)
parser.add_argument('--orgunit', help='Generate iDRAC CSR, pass in organization unit string value', required=False)
parser.add_argument('--sub-alt-name', help='Generate iDRAC CSR, pass in subject alternative name string value. Note: If passing in multiple values for subject alt name use a comma separator.', dest="sub_alt_name", required=False)
parser.add_argument('--export', help='Save the new generated CSR to any location, pass in complete directory path and unique CSR filename.', required=False)

args=vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- GenerateCsrREDFISH.py -ip 192.168.0.120 -u root -p calvin --get, this example will get current iDRAC cert(s).
    \n- GenerateCsrREDFISH.py -ip 192.168.0.120 -u root -p calvin --generate --city Austin --commonname idrac_tester --country US --email tester@dell.com --org test --orgunit "test group" --state Texas, this example shows generating CSR.
    \n- GenerateCsrREDFISH.py -ip 192.168.0.120 -u root -p calvin --generate --city Austin --commonname idrac_tester --country US --email tester@dell.com --org test --orgunit "test group" --state Texas --export C:\\Users\\Administrator\\Downloads\\R650_iDRAC.csr, this example shows generating CSR and exporting the CSR to a file in a specific directory.
    \n- GenerateCsrREDFISH.py -ip 192.168.0.120 -u root -p calvin --generate --city 'Round Rock' --state 'Texas' --country US --common 'Dell Inc' --org 'product test' --orgunit test --sub-alt-name 'altnametest.example.com,altname2test.good.com' --email 'tester@dell.com', this example shows generating CSR with multiple subject alt names.""")
    sys.exit(0)

def check_supported_idrac_version():
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/CertificateService' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/CertificateService' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code == 401:
        logging.warning("\n- WARNING, status code %s returned, check your iDRAC username/password is correct or iDRAC user has correct privileges to execute Redfish commands" % response.status_code)
        sys.exit(0)
    if response.status_code != 200:
        logging.warning("\n- WARNING, GET command failed to check supported iDRAC version, status code %s returned" % response.status_code)
        sys.exit(0)

def get_current_iDRAC_certs():
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/CertificateService/CertificateLocations?$expand=*($levels=1)' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/CertificateService/CertificateLocations?$expand=*($levels=1)' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.error("\n- ERROR, status code %s detected, detailed error results: \n%s" % (response.status_code, data))
        sys.exit(0)
    logging.info("\n- Current certificates installed for iDRAC %s -\n" % idrac_ip)
    for i in data.items():
        pprint(i)

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

def generate_CSR():
    logging.info("\n- INFO, generating CSR for iDRAC %s, this may take 10-20 seconds to complete\n" % idrac_ip)
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1?$select=FirmwareVersion' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1?$select=FirmwareVersion' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        logging.warning("\n- WARNING, unable to get iDRAC version, status code %s detected, detailed error results: \n%s" % (response.status_code, data))
        sys.exit(0)
    url = 'https://%s/redfish/v1/CertificateService/Actions/CertificateService.GenerateCSR' % (idrac_ip)   
    if int(data["FirmwareVersion"].replace(".","")) <= 5000000 and idrac_version == 9 or idrac_version == 8:
        payload = {"CertificateCollection":"/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol/HTTPS/Certificates","City":args["city"],"CommonName":args["commonname"],"Country":args["country"],"Organization":args["org"],"OrganizationalUnit":args["orgunit"],"State":args["state"]}   
    else:
        payload = {"CertificateCollection":{"@odata.id":"/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol/HTTPS/Certificates"},"City":args["city"],"CommonName":args["commonname"],"Country":args["country"],"Organization":args["org"],"OrganizationalUnit":args["orgunit"],"State":args["state"]}

    if args["email"]:
        payload["Email"] = args["email"]
    if args["sub_alt_name"]:
        if "," in args["sub_alt_name"]:
            payload["AlternativeNames"] = args["sub_alt_name"].split(",")
        else:
            payload["AlternativeNames"] = [args["sub_alt_name"]]
    if args["x"]:
        headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
    else:
        headers = {'content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
    data_post = response.json()
    if response.status_code != 200:
        logging.error("- FAIL, generate CSR failed, status code %s returned, detailed error results: \n%s" % (response.status_code, data_post))
        sys.exit(0)
    logging.info("\n- INFO, CSR generated for iDRAC %s\n" % idrac_ip)
    logging.info(data_post["CSRString"])
    if args["export"]:
        filename = args["export"]
        with open(filename, "w") as open_file:
            open_file.writelines(data_post["CSRString"])
        logging.info("\n- INFO, Generated CSR also copied to file \"%s\"" % filename)
    else:
        if args["x"]:
            response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1' % idrac_ip, verify=verify_cert, headers={'X-Auth-Token': args["x"]})
        else:
            response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1' % idrac_ip, verify=verify_cert, auth=(idrac_username, idrac_password))
        data_get = response.json()
        if response.status_code == 200:
            model_name = data_get["Model"].replace(" ","")
            service_tag = data_get["SKU"]
            filename = model_name + "_" + service_tag + ".csr"
        else:
            logging.info("-INFO, unable to get model and service tag information, using iDRAC IP for filename")
            filename = "%s.csr" % idrac_ip
        try:
            os.remove(filename)
        except:
            logging.info("- INFO, unable to locate file %s to delete, skipping" % filename)
        with open(filename, "w") as open_file:
            open_file.writelines(data_post["CSRString"])
        logging.info("\n- INFO, Generated CSR also copied to file \"%s\"" % filename)
    
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
    if args["generate"] and args["city"] and args["state"] and args["commonname"] and args["country"] and args["org"] and args["orgunit"]:
        generate_CSR()
    elif args["get"]:
        get_current_iDRAC_certs()
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
