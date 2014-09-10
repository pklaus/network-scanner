
try:
    import nmap
    NMAP_IMPORT = True
except ImportError:
    NMAP_IMPORT = False
try:
    from libnmap.process import NmapProcess
    from libnmap.parser import NmapParserException, NmapParser
    from time import sleep
    LIBNMAP_IMPORT = True
except ImportError:
    LIBNMAP_IMPORT = False
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

class libnmap_scanner(NmapPlugin):
    name = 'libnmap'

    @classmethod
    def is_available(cls):
        return LIBNMAP_IMPORT

    def scan(self, networks, arguments, verbose=False):
        targets = " ".join([str(network) for network in networks])
        self.process = NmapProcess(targets=targets, options=arguments)
        self.process.run_background()
        while self.process.is_running():
            if verbose: print("Nmap Scan running: ETR: {0} DONE: {1}%".format(float(self.process.etc) - dt.now().timestamp(), self.process.progress))
            sleep(2)
        if verbose: print("rc: {0} output: {1}".format(self.process.rc, self.process.summary))

        try:
            self.report = NmapParser.parse(self.process.stdout)
        except NmapParserException as e:
            NameError("Exception raised while parsing scan: {0}".format(e.msg))

        if not verbose:
            return
        for host in self.report.hosts:
            if len(host.hostnames):
                tmp_host = host.hostnames.pop()
            else:
                tmp_host = host.address

            print("Nmap scan report for {0} ({1})".format(
                tmp_host,
                host.address))
            print("Host is {0}.".format(host.status))
            print("  PORT     STATE         SERVICE")

            for serv in host.services:
                pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                        str(serv.port),
                        serv.protocol,
                        serv.state,
                        serv.service)
                if len(serv.banner):
                    pserv += " ({0})".format(serv.banner)
                print(pserv)
        print(self.process.summary)

    def log_scan(self, d):
        hid = random_hex()
        # Let's store the context of this run
        index = d['index']
        index[hid] = {
            'utcnow': dt.utcnow().isoformat(),
            'command': self.process.command,
            'scaninfo': self.process.summary,
            'all_hosts': [host.address for host in self.report.hosts],
            'plugin': self.name,
        }
        d['index'] = index
        d[hid] = self.report

    @classmethod
    def analyze(cls, report, detailed=False):
        try:
            pprint(report.get_dict())
        except:
            print("Sorry, get_dict() failed!")
        if not detailed: return
        for h in report.hosts:
            print("{} {} {} {} {} {} {} {}".format(
              h.address,
              h._starttime,
              h._endtime,
              h._hostnames,
              h._status,
              h._services,
              h._extras,
              h._osfingerprinted,
            ))

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

for plugin in [libnmap_scanner, nmap_scanner]:
    if plugin.is_available():
        PLUGINS[plugin.name] = plugin
    else:
        UNAVAILABLE_PLUGINS.append(plugin.name)

