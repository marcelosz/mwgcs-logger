#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""mwgcs-logger.py - 
  This script can be used to collect logs from McAfee Web Gateway Cloud Service's API.
  More info about the API: https://docs.mcafee.com/bundle/web-gateway-cloud-service-product-guide/page/GUID-BDF3E4F1-1625-4569-BE80-D528CE521BC1.html
  MWGCS Message API version 5 in use by this script.
"""
__author__ = "Marcelo Souza"
__license__ = "GPL"

import sys, logging, argparse, textwrap
import time
import requests
from requests.auth import HTTPBasicAuth
import StringIO
import cgi
import csv
import re

# Enable logging for the script itself
log_formatter = logging.Formatter('%(asctime)s mwgcs-logger (%(name)s) %(levelname)s: %(message)s')
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger = logging.getLogger()
logger.addHandler(console_handler)

# Config
from configobj import ConfigObj, ConfigObjError
import conf_util

def create_arg_parser():
    """
    Parses command line arguments.
    
    Returns:
        An ArgumentParser object.
    """

    epilog = """\
       TODO *** Descriptive text ***
    """
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent(epilog))
    parser.add_argument("-c", "--configfile", help="Configuration file. Default is mwgcs-logger.conf", default="mwgcs-logger.conf")
    parser.add_argument("-l", "--loglevel", help="Logging level (DEBUG, INFO or ERROR). Default is INFO.", default="INFO")
    parser.add_argument("-r", "--resultfilter", help="Collect logs with specified result. Result can be OBSERVED or DENIED. Default is to leave this filter blank.", default=None)    
    parser.add_argument("-t", "--timestamp", help="Timestamp (in Epoch) to use as the \"requestTimestampTo\" as the API filter. That is, the logs collected will be no newer than this parameter. Default is current time (\"Now\").", default=0)
    parser.add_argument("-u", "--userfilter", help="Filter logs related to specific user. Needs to match the authentication scheme in use (e-mail, domain\user or IP address).", default=None)
    parser.add_argument("-w", "--window", help="Time window (in seconds) to collect logs. This will be used to build \"requestTimestampFrom\". That is, how far back from the \"timestamp\" parameter the logs should be. Default is 60 seconds.", default=60)
    return parser

def set_logging_level(lg, level):
    """
    Set the level of verbosity of a logger instance.
    """
    # Configure logging level
    if level == 'DEBUG':
        lg.setLevel(logging.DEBUG)
    elif level == 'INFO':
        lg.setLevel(logging.INFO)
    elif level == 'WARNING':
        lg.setLevel(logging.WARNING)   
    else:
        lg.setLevel(logging.ERROR)

def main(argv):
    # parse the args
    arg_parser = create_arg_parser()
    args = arg_parser.parse_args()

    # set logging level
    set_logging_level(logger, args.loglevel)
    # configure local logger for requests (Urllib3) and set its level
    set_logging_level(logging.getLogger("urllib3"), args.loglevel)
    
    logger.info("Starting MWGCS Logger...")

    # read main cfg file
    conf_util.cfg = conf_util.read_cfg(args.configfile)
    if not conf_util.cfg:
        logger.error("Error reading main config file!")
        exit(1)

    #
    # Start building the request URL
    #
    if not args.timestamp :
        requestTimestampTo = int(time.time()) # Now
    else :
        requestTimestampTo = args.timestamp

    requestTimestampFrom = requestTimestampTo - int(args.window)

    # build the filter, starting by the timestamps
    mwgcsFilter = "filter.requestTimestampFrom=" + str(requestTimestampFrom) + "&amp;filter.requestTimestampTo=" + str(requestTimestampTo)
    enabledFilters = 0
    if args.userfilter:
        enabledFilters += 1
        escapedUserFilter = cgi.escape("\"" + args.userfilter + "\"")
        mwgcsFilter += "&amp;filter.userName=" + str(escapedUserFilter)
    if args.resultfilter:
        enabledFilters += 1        
        mwgcsFilter += "&amp;filter.result=" + str(args.resultfilter)
    mwgcsFilter += "&amp;order.0.requestTimestamp=asc"   
    mwgcsURL = 'https://' + conf_util.cfg['MWGCS']['Host'] + '/mwg/api/reporting/forensic/' + conf_util.cfg['MWGCS']['CustomerID'] + "?" + mwgcsFilter
    logger.debug("URL:" + mwgcsURL)

    try:
        # request header for CSV download and API version        
        requestHeaders = {'user-agent': 'mwgcs-logger/0.0.0.0', 'Accept': 'text/csv', 'x-mwg-api-version': '5'}
        logger.info("Connecting to MWGCS to collect logs...")
        r = requests.get(mwgcsURL, headers=requestHeaders, auth=HTTPBasicAuth(conf_util.cfg['MWGCS']['UserID'], conf_util.cfg['MWGCS']['Password']), timeout=float(conf_util.cfg['MWGCS']['ConnectionTimeout']))

        # put response into variable
        output = StringIO.StringIO(r.text.encode('utf-8'))
 
        logger.debug("Request status code: " + str(r.status_code))
        if r.status_code != 200:
            logger.debug("Response code: " + str(r.text))
            raise ValueError('Invalid response status: ' + str(r.status_code))

        responseLines = output.read().splitlines()
        # if response is valid but has only 1 line, then it's just a header and should be ignored.
        nLines = responseLines.__len__()
        if nLines <= 1:
            logger.error("No log collected!")
            exit(1)

        # header for API 5 responses
        csvHeader = '"user_id","username","source_ip","http_action","server_to_client_bytes","client_to_server_bytes","requested_host","requested_path","result","virus","request_timestamp_epoch","request_timestamp","uri_scheme","category","media_type","application_type","reputation","last_rule","http_status_code","client_ip","location","block_reason","user_agent_product","user_agent_version","user_agent_comment","process_name","destination_ip","destination_port"'
        if responseLines[0] != csvHeader:
            logger.error("Invalid first line from response: " + responseLines[0])

        # print the collected logs - for some reason there are 2 empty lines, plus the header (that's why the number 3 here)
        logger.info("Total number of log entries collected: " + str(nLines - 3))
        logger.info("Now printing logs that match filter parameters (if any)...")
        logger.info("Header: " + csvHeader)
        #print '"request_timestamp" "username" "source_ip" "http_action" "requested_host" "requested_path" "category" "reputation" "last_rule" "result" "block_reason" "process_name" "destination_ip" "destination_port"'

        csvDict = csv.DictReader(responseLines)
        logLines = responseLines[1:]
        nRow = 0
        for row, line in zip(csvDict, logLines):
            filterMatch = 0
            if args.userfilter:
                if (re.search(args.userfilter, row['username'])):
                    filterMatch += 1
            if args.resultfilter:
                if (re.search(args.resultfilter, row['result'])):
                    filterMatch += 1
            if not enabledFilters or enabledFilters == filterMatch :
                nRow += 1
                print line
                #print str(nRow) + ": " + row['request_timestamp'], row ['username'], row['source_ip'], row['http_action'], row['requested_host'], row['requested_path'], \
                #row['category'], row['reputation'], row['last_rule'], row['result'], row['block_reason'], row['process_name'], row ['destination_ip'], row['destination_port']
           
    except Exception as e:
        logger.error(str(e))
        exit(1)

    exit(0)

if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        # TODO - gracefully exit
        logger.info("Caught keyboard interrupt signal. Exiting...")
        exit(0)