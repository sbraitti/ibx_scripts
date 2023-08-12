#!/usr/bin/python3

# Main file - Start from here

# Let's import all we need globaly 

import argparse, logging, signal, requests

def main():
    # Parse CLI e set Options globally
    global options
    options = cliparser()

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

def api_test():
    url = options.api_url + "/grid"
    response = requests.get(url, verify=False, auth = HTTPBasicAuth(options.api_user, options.api_pass))
    if response.ok:
        show("The connection test was successful")
    else:
        show("Couldn't connect to the API URL")
        


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

    # Log section
    log_group = parser.add_argument_group('Log Options')
    log_group.add_argument('--logfile', action="store", dest="logfile", help="Log file name (Default: logfile.log)", default="logfile.log")
    log_group.add_argument('--debug', action="store_true", dest="debug", help="Log debug")

    args = parser.parse_args()
    return args

def show(msg):
    print("[INFO] "+msg)
    logger.info(msg)
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