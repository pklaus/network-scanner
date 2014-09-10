#!/usr/bin/env python

import ipaddress
import pdb
import shelve

from plugins import PLUGINS, UNAVAILABLE_PLUGINS

DATA = None
VERBOSE = False

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
    parser.add_argument('--netbios', '-n', action='store_true', help='Start a netbios nmap scan.')
    parser.add_argument('--shelvefile', '-s', help='File to store the run in.')
    parser.add_argument('--plugin', '-p', default='libnmap', help='Backend plugin and an scan type.')
    parser.add_argument('--verbose', '-v', action='store_true', help='Make the tool more verbose.')
    parser.add_argument('networks', metavar='NETWORK', nargs='+', help='A network to be scanned.')
    args = parser.parse_args()

    # Check 'networks' arguments
    try:
        # Try to interpret each argument as an IP network
        networks = [ipaddress.ip_network(network, strict=False) for network in args.networks]
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

    # Check the parameters to pre-set the nmap arguments
    arguments = '-sn -PE -PA21,23,80,3389'
    if args.extensive:
        arguments = '-A -v -v -T aggressive'
    if args.netbios:
        arguments = '-sU -p 137,5353 --script nbstat,dns-service-discovery -T aggressive'

    # Check the --plugin parameter
    if args.plugin:
        plugin_name = args.plugin.partition(':')[0]
        plugin_arguments = args.plugin.partition(':')[2]
        if plugin_name in UNAVAILABLE_PLUGINS:
            parser.error("Sorry, the plugin {} is currently not available. Please install its requirements.".format(plugin_name))
        if plugin_name not in PLUGINS:
            parser.error("Sorry, the plugin {} does not exist.".format(plugin_name))
        scanner = PLUGINS[plugin_name]()
        if plugin_arguments:
            arguments = plugin_arguments

    # Start scanning
    scanner.scan(networks=networks, arguments=arguments, verbose=VERBOSE)
    #pdb.set_trace()
    if DATA:
        scanner.log_scan(DATA)

    if DATA: DATA.close()

if __name__ == "__main__":
    main()

