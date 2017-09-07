import multiprocessing
import os
import re
import sys

# external modules
from modules.engines.engines import Engines
from modules.subbrute import subbrute
from modules.util.portscanner import PortScanner
from modules.util.util import Util
from modules.bfac import bfac

# Python 2.x and 3.x compatibility
if sys.version >= '3':
    import urllib.parse as urlparse
else:
    import urlparse

# Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')

# In case you cannot install some of the required development packages
# there's also an option to disable the SSL warning:
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass


class SubScann3r:
    def __init__(self, domain, logger, arguments):
        self.logger = logger
        self.domain = domain
        self.arguments = arguments
        self.util = Util()

    def scan(self):
        bruteforce_list = set()
        search_list = set()

        if is_windows:
            subdomains_queue = list()
        else:
            subdomains_queue = multiprocessing.Manager().list()

        # Validate domain
        domain_check = re.compile("^(http|https)?[a-zA-Z0-9]+([\-.][a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
        if not domain_check.match(self.domain):
            if not self.arguments.silent:
                print(self.logger.R + "Error: Please enter a valid domain" + self.logger.W)
            return []

        if not self.domain.startswith('http://') and not self.domain.startswith('https://'):
            self.domain = 'http://' + self.domain

        parsed_domain = urlparse.urlparse(self.domain)

        if not self.arguments.silent:
            print(self.logger.B + "[-] Enumerating subdomains now for %s" % parsed_domain.netloc + self.logger.W)

        if self.arguments.verbose and not self.arguments.silent:
            print(self.logger.Y + "[-] Verbosity is enabled, will show the subdomains results in realtime" + self.logger.W)

        chosenEnums = []

        if self.arguments.engines is None:
            chosenEnums = Engines.supported_engines.values()
        else:
            engines = self.arguments.engines.split(',')
            for engine in engines:
                if engine.lower() in Engines.supported_engines:
                    chosenEnums.append(Engines.supported_engines[engine.lower()])

        # Start the engines enumeration
        enums = [enum(self.domain, [], q=subdomains_queue, silent=self.arguments.silent, logger=self.logger) for enum in chosenEnums]
        for enum in enums:
            enum.start()
        for enum in enums:
            enum.join()

        subdomains = set(subdomains_queue)
        for subdomain in subdomains:
            search_list.add(subdomain)

        if self.arguments.bruteforce:
            if not self.arguments.silent:
                print(self.logger.G + "[-] Starting bruteforce module now using subbrute.." + self.logger.W)
            record_type = False
            path_to_file = os.path.dirname(os.path.realpath(__file__))
            subs = os.path.join(path_to_file, 'subbrute', 'all.txt')
            resolvers = os.path.join(path_to_file, 'subbrute', 'resolvers.txt')
            process_count = self.arguments.threads
            output = False
            json_output = False
            bruteforce_list = subbrute.print_target(parsed_domain.netloc, record_type, subs, resolvers, process_count,
                                                    output, json_output, search_list, self.arguments.verbose)

        subdomains = search_list.union(bruteforce_list)

        if subdomains:
            subdomains = sorted(subdomains, key=self.util.subdomain_sorting_key)

            if self.arguments.output:
                print("%s[-] Saving results to file: %s%s%s%s" % (self.logger. Y, self.logger.W, self.logger.R, self.arguments.output, self.logger.W))
                self.util.write_file(self.arguments.output, subdomains, self.arguments.findip)

            if not self.arguments.silent:
                print(self.logger.Y + "[-] Total unique subdomains found: %s" % len(subdomains) + self.logger.W)

            if self.arguments.takeover:
                print(self.logger.G + "[-] Checking for subdomains pointing to unregistered services" + self.logger.W)
                for subdomain in subdomains:
                    if self.arguments.verbose:
                        print(self.logger.G + "[-] Checking " + subdomain + self.logger.W)

                    services = self.util.get_url_signatures("http://" + subdomain)
                    if len(services) > 0:
                        for service in services:
                            print(
                                self.logger.Y + "[-] Found unregistered service \"" + service + "\" on subdomain " + subdomain + self.logger.W)

            if self.arguments.ports:
                if not self.arguments.silent:
                    print(self.logger.G + "[-] Starting port scan for the following ports: %s%s" % (self.logger.Y, self.arguments.portss) + self.logger.W)
                ports = self.arguments.ports.split(',')
                pscan = PortScanner(subdomains, ports)
                pscan.run()

            elif not self.arguments.silent:
                num = 1
                for subdomain in subdomains:
                    if self.arguments.findip:
                        ip = self.util.get_host_by_name(subdomain)
                        if ip is not "0.0.0.0":
                            print("{}[{}/{}] {} ({}){}".format(self.logger.G, num, len(subdomains), subdomain, ip, self.logger.W))
                    else:
                        print("{}[{}/{}] {} {}".format(self.logger.G, num, len(subdomains), subdomain, self.logger.W))
                    num +=1

                    if self.arguments.findings:
                        excluded_status_code = [301, 302, 404, 400, 500, 502, 503]
                        http_subdomain = "http://{}".format(subdomain)
                        results = bfac.check_findings(http_subdomain, excluded_status_codes=excluded_status_code)
                        if None in (results):
                            pass
                        else:
                            for r in results:
                                if r['status_code'] is 200:
                                    print("{}HTTP {} (C={}; L={}) {}".format(self.logger.Y, r['url'], r['status_code'], r['content_length'], self.logger.W))

                        http_subdomain = "https://{}".format(subdomain)
                        results = bfac.check_findings(http_subdomain, excluded_status_codes=excluded_status_code)
                        if None in (results):
                            pass
                        else:
                            for r in results:
                                if r['status_code'] is 200:
                                    print("{}HTTP {} (C={}; L={}) {}".format(self.logger.Y, r['url'], r['status_code'], r['content_length'], self.logger.W))

            return subdomains
