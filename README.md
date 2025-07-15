# iDRAC-Redfish-Scripting

Python and PowerShell scripting for Dell PowerEdge iDRAC REST API with DMTF Redfish.

Sample scripts written in Python and PowerShell that illustrate using the integrated Dell Remote Access Controller (iDRAC) REST API with Redfish to manage Dell PowerEdge servers. 

Powershell cmdlets can also be installed from Powershell gallery using Install-Module. Recommended to install IdracRedfishSupport module which will import all iDRAC cmdlets. 

For Python, you can leverage either individual python scripts or install iDRAC Python Redfish module. This module is an interactive session with an iDRAC which allows you to perform multiple workflows like firwmare updates or configuration changes to BIOS, NIC or Storage. You can install this module by running "pip3 install IdracRedfishSupport". 

NOTE: When installing IdracRedfishSupport module using pip3, this will also install all standalone python scripts from the GitHub Python directory. 

When executing any script or cmdlet, if your username or password has special characters or passing in domain name along with username, make sure to surround the argument value with double quotes. 

Examples:

"testdomain.i\aduser",
"testdomain.i/aduser",
"aduser@testdomain.i"

## Redfish Overview

There are various Out-of-Band (OOB) systems management standards available in the industry today. However, there is no single standard that can be easily used within emerging programming standards, can be readily implemented within embedded systems, and can meet the demands of today’s evolving IT solution models.  New IT solutions models have placed new demands on systems management solutions to support expanded scale, higher security, and multi-vendor openness, while also aligning with modern DevOps tools and processes. 
Recognizing these needs, Dell EMC and other IT solutions leaders within the Distributed Management Task Force (DMTF) undertook the creation of a new management interface standard. After a multi-year effort, the new standard, Redfish v1.0, was announced in July, 2015. 

Redfish’s key benefits include:
 
*	Increased simplicity and usability
*	Encrypted connections and generally heightened security
*	A programmatic interface that can easily be controlled through scripts
*	Based on widely-used standards for web APIs and data formats

Redfish has been designed to support the full range of server architectures from monolithic servers to converged infrastructure and hyper-scale architecture. The Redfish data model, which defines the structure and format of data representing server status, inventory and available operational functions, is vendor-neutral. Administrators can then create management automation scripts that can manage any Redfish compliant server. This is crucial for the efficient operation of a heterogonous server fleet. 

Using Redfish also has significant security benefits: unlike legacy management protocols, Redfish utilizes HTTPS encryption for secure and reliable communication. All Redfish network traffic, including event notifications, can be sent encrypted across the network. 

Redfish provides a highly organized and easily accessible method to interact with a server using scripting tools. The web interface employed by Redfish is supported by many programming languages, and its tree-like structure makes information easier to locate. Data returned from a Redfish query can be turned into a searchable dictionary consisting of key-value-pairs. By looking at the values in the dictionary, it is easy to locate settings and current status of a Redfish managed system. These settings can then be updated and actions issued to one or multiple systems.

## iDRAC with Lifecycle Controller Overview

The Integrated Dell Remote Access Controller (iDRAC) is designed to enhance the productivity of server administrators and improve the overall availability of PowerEdge servers. iDRAC alerts administrators to server problems, enabling remote server management, and reducing the need for an administrator to physically visit the server.
iDRAC with Lifecycle Controller allows administrators to deploy, update, monitor and manage Dell servers from any location without the use of agents in a one-to-one or one-to-many method. This out-of-band management allows configuration changes and firmware updates to be managed from Dell EMC, appropriate third-party consoles, and custom scripting directly to iDRAC with Lifecycle Controller using supported industry-standard API’s.
To support the Redfish standard, the iDRAC with Lifecycle Controller includes support for the iDRAC REST API in addition to support for the IPMI, SNMP, and WS-Man standard APIs. The iDRAC REST API builds upon the Redfish standard to provide a RESTful interface for Dell EMC value-add operations including:

*	Information on all iDRAC with Lifecycle Controller out-of-band services—web server, SNMP, virtual media, SSH, Telnet, IPMI, and KVM
*	Expanded storage subsystem reporting covering controllers, enclosures, and drives
*	For the PowerEdge FX2 modular server, detailed chassis information covering power supplies, temperatures, and fans
*	With the iDRAC Service Module (iSM) installed under the server OS, the API provides detailed inventory and status reporting for host network interfaces including such details as IP address, subnet mask, and gateway for the Host OS.

## Learning more about iDRAC and Redfish

For complete information concerning iDRAC with Lifecycle Controller, see the documents at http://www.dell.com/idracmanuals .

See iDRAC whitepapers below for more information about overview of Redfish support, detailed workflow examples or commonly asked questions:

- [iDRAC Server Configuration Profile Reference Guide](https://infohub.delltechnologies.com/en-us/t/server-configuration-profiles-reference-guide/)
- [iDRAC RACADM to Redfish Mapping](https://dl.dell.com/content/manual9969682-idrac9-racadm-to-redfish-mapping.pdf?language=en-us)
- [iDRAC User Interface to Redfish Mapping](https://dl.dell.com/content/manual25212104-idrac9-user-interface-to-redfish-mapping.pdf?language=en-us)
- [iDRAC Redfish FAQ](https://dl.dell.com/content/manual16004247-idrac-redfish-faq.pdf?language=en-us)
- [iDRAC Redfish API Guide](https://developer.dell.com/apis/2978/versions/7.xx/docs/0WhatsNew.md)
- [Manage iDRAC Virtual Media Using Redfish](https://dl.dell.com/content/manual18261993-manage-idrac-virtual-media-using-redfish.pdf?language=en-us)
- [Remotely Update Firmware Using Redfish](https://dl.dell.com/content/manual26835562-remotely-update-firmware-on-poweredge-servers-using-redfish-apis.pdf?language=en-us)

For details on the DMTF Redfish standard, visit https://www.dmtf.org/standards/redfish 

## Simulating iDRAC Redfish Environment Using Redfish Mockup Server

Redfish mockup server is an effective method to simulate Redfish iDRAC environment without using a physical server or iDRAC. Leveraging Redfish mockup server can solve the following issues:

* Do not have access to a physical server or iDRAC.
* Do have access to a server and you must test Redfish PATCH or POST calls without being destructive.
* Train many team members on Redfish without the necessity of physical servers or iDRAC.
* Do not have iDRAC user privileges to make Redfish calls.

See whitepaper below for more details about how to use this simulation:

- [Simulate an iDRAC Redfish Environment Using Redfish Mockup Server](https://dl.dell.com/content/manual25104995-simulate-idrac-redfish-environment-using-a-redfish-mockup-server.pdf?language=en-us)


## iDRAC REST API with Redfish Scripting Library

This GitHub library contains example Python and PowerShell scripts that illustrate the usage of the iDRAC REST API with Redfish to perform many different workflows which include:

BIOS operations
*	Get / Set BIOS attributes
*	Get / Set BIOS boot order, boot source state
*	Set next one-time boot device
*	Set BIOS to default settings

iDRAC operations
*	Change an iDRAC user password
*	Set iDRAC to default settings
*	Get iDRAC Lifecycle Controller logs
*	Get / Set iDRAC, Lifecycle Controller, and System Attributes

Firmware operations
*	Get server firmware inventory
*	Perform a single server device firmware update

Server operations
*	Export / Import Server Configuration Profile (SCP)
*	Preview SCP Import
*	Get / Set server power state
*	Get server storage inventory

Storage operations
*	Create virtual disk
*	Reset controller
*	Set / Rekey / Remove controller encryption
* Assign / Unassign DHS / GHS 

Prerequisites
*	PowerEdge 12G/13G/14G/15G/16G/17G servers
*	Minimum iDRAC 7/8 FW 2.40.40.40, iDRAC9 FW 3.00.00.00, iDRAC10 FW 1.10.17.00
*	Python 3.x
*	PowerShell 5.0 or later

## Report problems or provide feedback

If you run into any problems or would like to provide feedback, please open an issue here https://github.com/dell/idrac-Redfish-Scripting/issues 

