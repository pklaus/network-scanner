
try:
    import nmap
    NMAP_IMPORT = True
except ImportError:
    NMAP_IMPORT = False
from pprint import pprint
import random
from datetime import datetime as dt

PLUGINS = dict()
UNAVAILABLE_PLUGINS = []

class NmapPlugin(object):
    name = None

def random_hex(length=6):
    CHARS = '0123456789ABCDEF'
    return ''.join(random.sample(CHARS,length))

class nmap_scanner(NmapPlugin):
    name = 'nmap'

    def __init__(self):
        self.nm = nmap.PortScanner()

    @classmethod
    def is_available(cls):
        return NMAP_IMPORT

    def scan(self, networks, arguments, verbose=False):
        hosts = " ".join([str(network) for network in networks])
        self.scan_result = self.nm.scan(hosts=hosts, arguments=arguments)
        hosts_list = [(x, self.nm[x]['status']['state']) for x in self.nm.all_hosts()]
        if verbose:
            hosts_list = [(x, self.nm[x]['status']['state']) for x in self.nm.all_hosts()]
            for host, status in hosts_list:
                print('{0}:{1}'.format(host, status))

    def log_scan(self, d):
        hid = random_hex()
        # Let's store the context of this run
        index = d['index']
        index[hid] = {
            'utcnow': dt.utcnow().isoformat(),
            'command': self.nm.command_line(),
            'scaninfo': self.nm.scaninfo(),
            'all_hosts': self.nm.all_hosts(),
            'plugin': self.name,
        }
        d['index'] = index
        d[hid] = self.scan_result

    @classmethod
    def analyze(cls, result, detailed=False):
        pprint(result)
        if True: return
        try:
            hosts_up = [host for host in result['hosts'] if result['hosts'][host]['status']['state']=='up']
        except:
            hosts_up = ientry['all_hosts']
        num_all = len(ientry['all_hosts'])
        print("{} | {} | Command: {} | {:d} of {:d} host found to be up".format(hid, ientry['utcnow'], ientry['command'], len(hosts_up), num_all))
        if args.details:
            # Sort the hosts by their IP
            hosts_up = [(ipaddress.ip_network(host), host) for host in hosts_up]
            hosts_up.sort()
            hosts_up = [host[1] for host in hosts_up]
            # And print detailed output for each of them
            for host in hosts_up:
                hostname = result['hosts'][host]['hostname']
                try:
                    ports = list(result['hosts'][host]['tcp'].keys())
                except KeyError:
                    ports = []
                print("  |-> {:16s} {:35s} | TCP ports: {!s}".format(host, hostname, ports))

for plugin in [nmap_scanner,]:
    if plugin.is_available():
        PLUGINS[plugin.name] = plugin
    else:
        UNAVAILABLE_PLUGINS.append(plugin.name)

