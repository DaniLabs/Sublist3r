#!/usr/bin/env python
# coding: utf-8
# Sublist3r v1.0p (Plazmaz's Fork)
# By Ahmed Aboul-Ela - https://www.twitter.com/aboul3la
# Based on fork by Dylan Katz - https://www.twitter.com/Plazmaz
# Modified by DaniLabs - https://www.twitter.com/DaniLabs

# modules in standard library
import os
import sys

# external modules
from modules.util.argumentparser import ArgumentParser
from modules.subscann3r import SubScann3r
from modules.util.logger import Logger

class Sublist3r(object):
    """
    Main class Sublist3r
    """

    def __init__(self):
        self.script_path = (os.path.dirname(os.path.realpath(__file__)))
        self.arguments = ArgumentParser(self.script_path)
        # Check if we are running this on windows platform
        is_windows = sys.platform.startswith('win')
        self.logger = Logger(is_windows, False)
        self.logger.is_verbose = self.arguments.args.verbose

    def run(self):
        scanner = SubScann3r(self.arguments.args.domain, self.logger, self.arguments.args)
        return scanner.scan()

if __name__ == '__main__':
    main = Sublist3r()
    main.run()
