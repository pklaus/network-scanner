#!/usr/bin/env python

import ipaddress
from datetime import datetime as dt
import pdb
import shelve

DATA = None

def main():
    global DATA

    import argparse
    parser = argparse.ArgumentParser(description='Analyze a scan file')
    parser.add_argument('--details', '-d', action='store_true', help='Show more details in output.')
    parser.add_argument('--shelvefile', '-s', help='File to store the run in.', required=True)
    args = parser.parse_args()

    # Check the --shelvefile parameter
    if args.shelvefile:
        try:
            DATA = shelve.open(args.shelvefile)
        except:
            parser.error('Could not open the shelvefile!.')

    # Start scanning
    try:
        index = DATA['index']
    except KeyError:
        parser.error("This file doesn't seem like a shelvefile I'd expect.")

    for hid in index:
        ientry = index[hid]
        results = DATA[hid]
        hosts_up = [host for host in results['hosts'] if results['hosts'][host]['status']['state']=='up']
        num_all = len(ientry['all_hosts'])
        print("{} | {} | Command: {} | {:d} of {:d} host found to be up".format(hid, ientry['utcnow'], ientry['command'], len(hosts_up), num_all))
        if args.details:
            # Sort the hosts by their IP
            hosts_up = [(ipaddress.ip_address(host), host) for host in hosts_up]
            hosts_up.sort()
            hosts_up = [host[1] for host in hosts_up]
            # And print detailed output for each of them
            for host in hosts_up:
                hostname = results['hosts'][host]['hostname']
                try:
                    ports = list(results['hosts'][host]['tcp'].keys())
                except KeyError:
                    ports = []
                print("  |-> {:16s} {:35s} | TCP ports: {!s}".format(host, hostname, ports))

    pdb.set_trace()

    if DATA: DATA.close()

if __name__ == "__main__":
    main()

