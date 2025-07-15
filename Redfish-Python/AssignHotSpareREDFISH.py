#!/usr/bin/python3
#
# AssignHotSpareREDFISH. Python script using Redfish API to either assign dedicated or global hot spare
#
# _author_ = Texas Roemer <Texas_Roemer@Dell.com>
# _version_ = 7.0
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

parser = argparse.ArgumentParser(description="Python script using Redfish API with OEM extension to assign either dedicated or global hot spare. Supported ways to execute the script are: passing in iDRAC username/password (arguments -u and -p), pass in only iDRAC username (argument -u only) which will prompt to the screen to enter iDRAC password, will not be returned in clear text or use X-Auth token session (argument -x). By default, the script ignores SSL cert verification. Use --ssl argument if you want to perform SSL cert verification for all Redfish calls.")
parser.add_argument('-ip',help='iDRAC IP address', required=False)
parser.add_argument('-u', help='iDRAC username', required=False)
parser.add_argument('-p', help='iDRAC password', required=False)
parser.add_argument('-x', help='Pass in X-Auth session token for executing Redfish calls. All Redfish calls will use X-Auth token instead of username/password', required=False)
parser.add_argument('--ssl', help='SSL cert verification for all Redfish calls, pass in value true or false. By default, this argument is not required and script ignores validating SSL cert for all Redfish calls.', required=False)
parser.add_argument('--script-examples', help='Get executing script examples', action="store_true", dest="script_examples", required=False)
parser.add_argument('--get-controllers', help='Get server storage controller FQDDs', action="store_true", dest="get_controllers", required=False)
parser.add_argument('--get-disks', help='Get server storage controller disk FQDDs only, pass in storage controller FQDD, Example RAID.Integrated.1-1', dest="get_disks", required=False)
parser.add_argument('--get-hotspare-drive', help='Get current hot spare type for each drive, pass in storage controller FQDD, Example RAID.Integrated.1-1', dest="get_hotspare_drive", required=False)
parser.add_argument('--get-virtualdisks', help='Get current server storage controller virtual disk(s) and virtual disk type, pass in storage controller FQDD, Example RAID.Integrated.1-1', dest="get_virtualdisks", required=False)
parser.add_argument('--get-virtualdisk-details', help='Get complete details for all virtual disks behind storage controller, pass in storage controller FQDD, Example RAID.Integrated.1-1', dest="get_virtualdisk_details", required=False)
parser.add_argument('--hotspare-type', help='Pass in the type of hot spare you want to assign. Supported values are dedicated and global', dest="hotspare_type", required=False)
parser.add_argument('--assign-disk', help='Assign global or dedicated hot spare, pass in disk FQDD, Example Disk.Bay.0:Enclosure.Internal.0-1:RAID.Slot.6-1', dest="assign_disk", required=False)
parser.add_argument('--assign-virtualdisk', help='Pass in virtual disk FQDD you want to assign the dedicated hot spare disk', dest="assign_virtualdisk", required=False)
args = vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO) 

def script_examples():
    print("""\n- AssignHotSpareREDFISH.py -ip 192.168.0.120 -u root -p calvin --get-controllers, this example will get current storage controllers.
    \n- AssignHotSpareREDFISH.py -ip 192.168.0.120 -u root --get-disks RAID.Integrated.1-1, this example will prompt to the screen asking for iDRAC username password which will not be passed in clear text. Command will then execute to get current disks for this controller FQDD.
    \n- AssignHotSpareREDFISH.py -ip 192.168.0.120 -x 72f5baabc31b3c72f88aef64dec2450c --get-virtualdisks RAID.Integrated.1-1, this example will use X-auth token session to get current virtual disks for storage controller RAID.Integrated.1-1.
    \n- AssignHotSpareREDFISH.py -ip 192.168.0.120 -x 78f5baabc31b3c72f88aef64dec2450c --assign-disk Disk.Bay.3:Enclosure.Internal.0-1:RAID.Integrated.1-1 --hotspare-type dedicated --assign-virtualdisk Disk.Virtual.0:RAID.Integrated.1-1 --ssl y, this example using X-auth token session and validating SSL cert will assign disk 3 as dedicated hotspare to VD 0.
    \n- AssignHotSpareREDFISH.py -ip 192.168.0.120 -u root -p calvin --get-hotspare-drive RAID.Mezzanine.1-1, this example will return hotspare status for each drive.
    \n- AssignHotSpareREDFISH.py -ip 192.168.0.120 -u root -p calvin --assign Disk.Bay.4:Enclosure.Internal.0-1:RAID.Integrated.1-1 --hotspare-type global, this example will assign disk 4 as global hotspare.""")
    sys.exit(0)
    
def check_supported_idrac_version():
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Oem/Dell/DellRaidService' % idrac_ip,verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Oem/Dell/DellRaidService' % idrac_ip,verify=verify_cert,auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code == 401:
        logging.warning("\n- WARNING, status code %s returned. Incorrect iDRAC username/password or invalid privilege detected." % response.status_code)
        sys.exit(0)
    elif response.status_code != 200:
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

def get_pdisks():
    disk_used_created_vds=[]
    available_disks=[]
    test_valid_controller_FQDD_string(args["get_disks"])
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s' % (idrac_ip, args["get_disks"]),verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s' % (idrac_ip, args["get_disks"]),verify=verify_cert,auth=(idrac_username, idrac_password))
    data = response.json()
    drive_list=[]
    if data['Drives'] == []:
        logging.warning("\n- WARNING, no drives detected for %s" % args["get_disks"])
        sys.exit(0)
    else:
        logging.info("\n- Drive(s) detected for %s -\n" % args["get_disks"])
        for i in data['Drives']:
            drive_list.append(i['@odata.id'].split("/")[-1])
            print(i['@odata.id'].split("/")[-1])

def get_pdisks_hot_spare_type():
    disk_used_created_vds=[]
    available_disks=[]
    test_valid_controller_FQDD_string(args["get_hotspare_drive"])
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s' % (idrac_ip, args["get_hotspare_drive"]),verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s' % (idrac_ip, args["get_hotspare_drive"]),verify=verify_cert,auth=(idrac_username, idrac_password))
    data = response.json()
    drive_list_uris = []
    if data["Drives"] == []:
        logging.warning("\n- WARNING, no drives detected for %s" % args["get_hotspare_drive"])
        sys.exit(0)
    for i in data["Drives"]:
        for ii in i.items():
            drive_list_uris.append(ii[1])
    logging.info("\n- Drive FQDDs/Hot Spare Type for Controller %s -\n" % args["get_hotspare_drive"])
    for i in drive_list_uris:
        if args["x"]:
            response = requests.get('https://%s%s?$select=HotspareType' % (idrac_ip, i),verify=verify_cert, headers={'X-Auth-Token': args["x"]})
        else:
            response = requests.get('https://%s%s?$select=HotspareType' % (idrac_ip, i),verify=verify_cert,auth=(idrac_username, idrac_password))
        data = response.json()
        print("%s: HotspareType: %s" % (i.split("/")[-1], data["HotspareType"]))

def get_virtual_disks():
    test_valid_controller_FQDD_string(args["get_virtualdisks"])
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s/Volumes' % (idrac_ip, args["get_virtualdisks"]),verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s/Volumes' % (idrac_ip, args["get_virtualdisks"]),verify=verify_cert,auth=(idrac_username, idrac_password))
    data = response.json()
    vd_list=[]
    if data['Members'] == []:
        logging.warning("\n- WARNING, no volume(s) detected for %s" % args["get_virtualdisks"])
        sys.exit(0)
    else:
        for i in data['Members']:
            vd_list.append(i['@odata.id'].split("/")[-1])
    logging.info("\n- Volume(s) detected for %s controller -\n" % args["get_virtualdisks"])
    for ii in vd_list:
        if args["x"]:
            response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s/Volumes/%s' % (idrac_ip, args["get_virtualdisks"], ii),verify=verify_cert, headers={'X-Auth-Token': args["x"]})
        else:
            response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s/Volumes/%s' % (idrac_ip, args["get_virtualdisks"], ii),verify=verify_cert, auth=(idrac_username, idrac_password))
        data = response.json()
        for i in data.items():
            if i[0] == "VolumeType":
                print("%s, Volume type: %s" % (ii, i[1]))

def get_virtual_disks_details():
    test_valid_controller_FQDD_string(args["get_virtualdisk_details"])
    if args["x"]:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s/Volumes' % (idrac_ip, args["get_virtualdisk_details"]),verify=verify_cert, headers={'X-Auth-Token': args["x"]})
    else:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s/Volumes' % (idrac_ip, args["get_virtualdisk_details"]),verify=verify_cert, auth=(idrac_username, idrac_password))
    data = response.json()
    vd_list = []
    if data['Members'] == []:
        logging.error("\n- WARNING, no volume(s) detected for %s" % args["get_virtualdisk_details"])
        sys.exit(0)
    else:
        logging.info("\n- Volume(s) detected for %s controller -\n" % args["get_virtualdisk_details"])
        for i in data['Members']:
            vd_list.append(i['@odata.id'].split("/")[-1])
            print(i['@odata.id'].split("/")[-1])
    for ii in vd_list:
        if args["x"]:
            response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s/Volumes/%s' % (idrac_ip, args["get_virtualdisk_details"], ii),verify=verify_cert, headers={'X-Auth-Token': args["x"]})
        else:
            response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s/Volumes/%s' % (idrac_ip, args["get_virtualdisk_details"], ii),verify=verify_cert, auth=(idrac_username, idrac_password))
        data = response.json()
        logging.info("\n----- Detailed Volume information for %s -----\n" % ii)
        for i in data.items():
            pprint(i)
        print("\n")

def assign_spare():
    global job_id
    method = "AssignSpare"
    url = 'https://%s/redfish/v1/Systems/System.Embedded.1/Oem/Dell/DellRaidService/Actions/DellRaidService.AssignSpare' % (idrac_ip)
    if args["hotspare_type"].lower() == "global":
        payload = {"TargetFQDD":args["assign_disk"]}
    elif args["hotspare_type"].lower() == "dedicated":
        payload = {"TargetFQDD":args["assign_disk"],"VirtualDiskArray":[args["assign_virtualdisk"]]}
    if args["x"]:
        headers = {'content-type': 'application/json', 'X-Auth-Token': args["x"]}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert)
    else:
        headers = {'content-type': 'application/json'}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify_cert,auth=(idrac_username,idrac_password))
    data = response.json()
    if response.status_code == 202:
        logging.info("\n- PASS: POST command passed to set disk \"%s\" as \"%s\" hot spare" % (args["assign_disk"], args["hotspare_type"]))
        try:
            job_id = response.headers['Location'].split("/")[-1]
        except:
            logging.error("- FAIL, unable to locate job ID in JSON headers output")
            sys.exit(0)
        logging.info("- Job ID %s successfully created for storage method \"%s\"" % (job_id, method))
    else:
        logging.info("\n- FAIL, POST command failed to set hotspare")
        data = response.json()
        logging.info("\n- POST command failure results:\n %s" % data)
        sys.exit(0)

def loop_job_status():
    start_time = datetime.now()
    while True:
        if args["x"]:
            response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs/%s' % (idrac_ip, job_id), verify=verify_cert, headers={'X-Auth-Token': args["x"]})
        else:
            response = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs/%s' % (idrac_ip, job_id), verify=verify_cert,auth=(idrac_username, idrac_password))
        current_time = (datetime.now()-start_time)
        if response.status_code == 200 or response.status_code == 202:
            logging.debug("- PASS, GET request passed to check job status")
        else:
            logging.error("\n- FAIL, GET command failed to check job status, return code is %s" % response.status_code)
            data = response.json()
            print(data)
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

def main():
    global idrac_ip
    global idrac_username
    global idrac_password
    global verify_cert
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
    if args["get_controllers"]:
        get_storage_controllers()
    elif args["get_disks"]:
        get_pdisks()
    elif args["get_hotspare_drive"]:
        get_pdisks_hot_spare_type()
    elif args["get_virtualdisks"]:
        get_virtual_disks()
    elif args["get_virtualdisk_details"]:
        get_virtual_disks_details()
    elif args["assign_disk"] or args["assign_virtualdisk"] and args["hotspare_type"]:
        assign_spare()
        loop_job_status()
    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
        sys.exit(0)

if __name__ == "__main__":
    main()  
