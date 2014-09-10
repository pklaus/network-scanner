#!/usr/bin/env python

import ipaddress
from datetime import datetime as dt
import pdb
import shelve
from plugins import PLUGINS, UNAVAILABLE_PLUGINS

DATA = None

def main():
    global DATA

    import argparse
    parser = argparse.ArgumentParser(description='Analyze a scan file')
    parser.add_argument('--detailed', '-d', action='store_true', help='Show more details in output.')
    parser.add_argument('--shelvefile', '-s', help='File where the scans are storeed in.', required=True)
    args = parser.parse_args()

    # Check the --shelvefile parameter
    if args.shelvefile:
        try:
            DATA = shelve.open(args.shelvefile)
        except:
            parser.error('Could not open the shelvefile!.')

    # Start interpretation
    try:
        index = DATA['index']
    except KeyError:
        parser.error("This file doesn't seem like a shelvefile I'd expect.")

    for hid in index:
        ientry = index[hid]
        print(ientry)
        results = DATA[hid]
        PLUGINS[ientry['plugin']].analyze(results, detailed=args.detailed)

        pdb.set_trace()

    if DATA: DATA.close()

if __name__ == "__main__":
    main()

