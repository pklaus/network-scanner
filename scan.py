#!/usr/bin/env python

import nmap
import ipaddress
from datetime import datetime as dt
import random
import pdb
import shelve

DATA = None
VERBOSE = False

def random_hex(length=6):
    CHARS = '0123456789ABCDEF'
    return ''.join(random.sample(CHARS,length))

def log_scan(nm, d):
    hid = random_hex()
    # Let's store the context of this run
    index = d['index']
    index[hid] = {
        'utcnow': dt.utcnow().isoformat(),
        'command': nm.command_line(),
        'scaninfo': nm.scaninfo(),
        'all_hosts': nm.all_hosts(),
    }
    d['index'] = index
    # We pull the entries out of nm:
    hosts = {}
    for host in nm.all_hosts():
        hosts[host] = nm[host]
    d[hid] = {'hosts': hosts}

def ensure_structure(d):
    try:
        DATA['index']
    except KeyError:
        DATA['index'] = dict()
    
def main():
    global DATA, VERBOSE

    import argparse
    parser = argparse.ArgumentParser(description='Scan a network')
    parser.add_argument('--extensive', '-e', action='store_true', help='Start an extensive nmap scan.')
    parser.add_argument('--shelvefile', '-s', help='File to store the run in.')
    parser.add_argument('--verbose', '-v', action='store_true', help='Make the tool more verbose.')
    parser.add_argument('networks', metavar='NETWORK', nargs='+', help='A network to be scanned.')
    args = parser.parse_args()

    # Check 'networks' arguments
    try:
        networks = [ipaddress.ip_network(network) for network in args.networks]
    except:
        parser.error('Did not understand the network(s) provided.')

    if args.verbose: VERBOSE = True

    # Check the --shelvefile parameter
    if args.shelvefile:
        try:
            DATA = shelve.open(args.shelvefile)
        except:
            parser.error('Could not open the shelvefile!.')
        ensure_structure(DATA)

    # Start scanning
    nm = nmap.PortScanner()
    for network in networks:
        #nm.scan(hosts=network, arguments='-n -sP -PE -PA21,23,80,3389')
        nm.scan(hosts=str(network), arguments='-A -v -v')
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        for host, status in hosts_list:
            if VERBOSE: print('{0}:{1}'.format(host, status))
        #pdb.set_trace()
        if DATA:
            log_scan(nm, DATA)

    if DATA: DATA.close()

if __name__ == "__main__":
    main()

