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
        num_up = len([host for host in results['hosts'] if results['hosts'][host]['status']['state']=='up'])
        num_all = len(ientry['all_hosts'])
        print("{} | {} | Command: {} | {:d} of {:d} host found to be up".format(hid, ientry['utcnow'], ientry['command'], num_up, num_all))

    #pdb.set_trace()

    if DATA: DATA.close()

if __name__ == "__main__":
    main()

