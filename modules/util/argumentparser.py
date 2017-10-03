import argparse

class ArgumentParser(object):
    """
    Class for parsing the arguments
    """
    def __init__(self, script_path):
        self.script_path = script_path
        parser = argparse.ArgumentParser(epilog='\tExample: \r\npython {0} -d google.com'.format(self.script_path))
        parser._optionals.title = "Options"
        parser.add_argument('-d',
                            '--domain',
                            help="Domain name to enumerate it's subdomains",
                            required=True)
        parser.add_argument('-b',
                            '--bruteforce',
                            help='Enable the subbrute bruteforce module',
                            nargs='?',
                            default=False)
        parser.add_argument('-v',
                            '--verbose',
                            help='Enable Verbosity and display results in realtime',
                            nargs='?',
                            default=False)
        parser.add_argument('-t',
                            '--threads',
                            help='Number of threads to use for subbrute bruteforce (default: 30)',
                            nargs='?',
                            type=int,
                            default=30)
        parser.add_argument('-e', 
                            '--engines', 
                            help='Specify a comma-separated list of search engines')
        parser.add_argument('-to',
                            '--takeover',
                            help='Scan for subdomain takeover issues',
                            nargs='?',
                            default=False)
        parser.add_argument('-o',
                            '--output',
                            help='Save the results to text file',
                            nargs='?',
                            default=False)
        parser.add_argument('-i',
                            '--findip',
                            help='Find IP address of each subdomain',
                            action='store_true')
        parser.add_argument('-f',
                            '--findings',
                            nargs='?',
                            help='Find files and directories senstivies',
                            default=False)

        self.args = parser.parse_args()

        if self.args.verbose or self.args.verbose is None:
            self.args.verbose = True

        if self.args.takeover or self.args.takeover is None:
            self.args.takeover = True

        if self.args.findings or self.args.findings is None:
            self.args.findings = True
        
        self.args.__setattr__('silent', False)