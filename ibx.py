#!/usr/bin/python3

# Main file - Start from here

# Let's import all we need globaly 

import argparse, logging, signal, requests, json
from requests.auth import HTTPBasicAuth
from src import sanitize

#Disable Warning for Insecure SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    # Parse CLI e set Options globally
    global options
    options = cliparser()
    
    # URL Validation 
    if not options.api_url.endswith('/'):
        quit('API URL must ends with /')

    # Creating and Configuring Logger
    if options.debug:
        debuglevel = logging.DEBUG
    else:
        debuglevel = logging.INFO
    Log_Format = "%(levelname)s %(asctime)s - %(message)s"

    logging.basicConfig(filename = options.logfile,
                        filemode = "a",
                        format = Log_Format, 
                        level = debuglevel)
    global logger 
    logger = logging.getLogger()

    # Let's start
    if options.api_test:
        api_test()
        exit()
    # Unmanaged to Managed Script
    if options.u_to_m:
        utom()
        exit()

def api_test():
    url = options.api_url + "grid"
    response = requests.get(url, verify=False, auth = HTTPBasicAuth(options.api_user, options.api_pass))
    if response.ok:
        show("The connection test was successful")
    else:
        error("Couldn't connect to the API URL")
        
def utom():
    show('Starting Script: Unmanaged to Managed Converter')
    show('This script will find IPs unmanaged by Infoblox and will create a Host Record with the information')
    # get all networks
    show('Collecting all networks')
    networklist = []
    baseurl = options.api_url + "network?_paging=1&_max_results=100&_return_as_object=1"
    url = baseurl

    while True:
        response = requests.get(url, verify=False, auth = HTTPBasicAuth(options.api_user, options.api_pass))
        networks = response.json().get('result')
        networklist.extend(networks)
        if response.json().get('next_page_id'):
            url = baseurl + '&_page_id=' + response.json().get('next_page_id')
        else:
            break
    show(f'{len(networklist)} networks collected!')
   
    # Backup networklist
    with open('backup/networklist.json', 'w', encoding='utf-8') as f:
        json.dump(networklist, f, ensure_ascii=False, indent=4)
   
    # for each network, find unmanaged IPs
    show("We are now searching for UNMANAGED IPs")
    requestlist = []
    unmanagedips = []
    for item in networklist:
        network = item['network']
        networkview = item['network_view']
        request = {"method": "GET","object": "ipv4address","data": {"network": network,"network_view": networkview,"types": "UNMANAGED"},"args": {"_return_fields": "ip_address,discovered_data"}}
        requestlist.append(request)
        if len(requestlist)==20:
            url = options.api_url + 'request'
            response = requests.post(url, verify=False, auth = HTTPBasicAuth(options.api_user, options.api_pass), json=requestlist)
            unmanagedips.extend(response.json())
            requestlist = []  
    url = options.api_url + 'request'
    response = requests.post(url, verify=False, auth = HTTPBasicAuth(options.api_user, options.api_pass), json=requestlist)
    unmanagedips.extend(response.json())
    
    # Backup unmanagedips
    with open('backup/unmanagedips.json', 'w', encoding='utf-8') as f:
        json.dump(unmanagedips, f, ensure_ascii=False, indent=4)
    
    # Check if the IPs can be converted
    convertcount = 0
    convertdict = {}
    for item in unmanagedips:
        for subitem in item:
            if subitem['discovered_data']['mac_address'] and subitem['discovered_data']['vmi_id'] and subitem['discovered_data']['vmi_name']:
                if subitem['discovered_data']['vmi_id'] not in convertdict:
                    convertdict[subitem['discovered_data']['vmi_id']] = []
                convertdict[subitem['discovered_data']['vmi_id']].append({"ip": subitem['ip_address'],"mac": subitem['discovered_data']['mac_address'], "name": sanitize.hostname(subitem['discovered_data']['vmi_name'])})
                convertcount+=1
    show(f"{convertcount} IPs will be converted to {len(convertdict)} Host Records")
 
    # Backup convertdict
    with open('backup/convertdict.json', 'w', encoding='utf-8') as f:
        json.dump(convertdict, f, ensure_ascii=False, indent=4)

    # Create Host Record with the IPs we found
    for index, vmid in enumerate(convertdict):
        vmname = convertdict[vmid][0]['name']
        hostrecord = { "name":vmname, "configure_for_dns": False, "extattrs": { "VM ID": {"value": vmid}}}
        ipaddrs = []
        for ip in convertdict[vmid]:
            ipaddrs.append({ "ipv4addr": ip['ip'], "configure_for_dhcp": False, "mac":ip['mac'] })
        hostrecord['ipv4addrs'] = ipaddrs
        show(f"[{index+1}/{len(convertdict)}] Creating host {vmname}:", type="start")
        url = options.api_url + 'record:host'
        response = requests.post(url, verify=False, auth = HTTPBasicAuth(options.api_user, options.api_pass), json=hostrecord)
        if response.ok: show(" OK!", type="end")
    show("Done!")
    



def cliparser():
    parser = argparse.ArgumentParser(description='Infoblox Scripts by Stefan Braitti')

    # Default section
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1')

    # Connection section
    connection = parser.add_argument_group('API Connection')
    connection.add_argument('--url', '-U', action='store', dest='api_url', help='URI for the Infoblox API', required=True)
    connection.add_argument('--user', '-u', action='store', dest='api_user', help='Username for the Infoblox API', required=True)
    connection.add_argument('--pass', '-p', action='store', dest='api_pass', help='Password for the Infoblox API', required=True)
    connection.add_argument('--test', action='store_true', dest='api_test', help='Test the connection with Infoblox API')

    # Unmanaged to Managed
    utom = parser.add_argument_group('Unmanaged to Managed')
    utom.add_argument('-1', action='store_true', dest='u_to_m', help='Activate script Unmanaged to Managed')
   
    # Log section
    log_group = parser.add_argument_group('Log Options')
    log_group.add_argument('--logfile', action="store", dest="logfile", help="Log file name (Default: logfile.log)", default="logfile.log")
    log_group.add_argument('--debug', action="store_true", dest="debug", help="Log debug")

    args = parser.parse_args()
    return args

def show(msg, type="normal"):
    if type == "start":
        print("[INFO] "+msg, end="")
    elif type =="end":
        print(msg)   
    else: 
        print("[INFO] "+msg)
    logger.info(msg)

def error(msg):
    logger.error(msg)
    quit()

def exit_gracefully(signum, frame):
    # restore the original signal handler as otherwise evil things will happen
    # in raw_input when CTRL+C is pressed, and our signal handler is not re-entrant
    signal.signal(signal.SIGINT, original_sigint)

    try:
        if input("\nReally quit? (y/n)> ").lower().startswith('y'):
            logger.info("Stopped by user")
            exit("Quitting")

    except KeyboardInterrupt:
        logger.info("Stopped by user")
        exit("Ok ok, quitting")

    # restore the exit gracefully handler here    
    signal.signal(signal.SIGINT, exit_gracefully)
if __name__ == '__main__':
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exit_gracefully)
    main()