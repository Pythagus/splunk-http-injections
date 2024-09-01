import os
import re

# Global variables.
CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
LOOKUP_PATH = CURRENT_DIR + "/../injections-app/lookups/WAF_Rules.csv"
#LOOKUP_PATH = CURRENT_DIR + "/../../lookups/WAF_Rules.csv"

class RegexMatcher(object):

    def __init__(self, patterns: dict = None):
        self.regex = {}

        if patterns:
            self.append(patterns)

    def append(self, patterns: dict):
        for key in patterns:
            self.regex[key] = re.compile(patterns[key])

    def match(self, input: str):
        for key in self.regex:
            if self.regex[key].search(input) is not None:
                return key
            
        return False


def _getRegexFromLookups():

    pass

def buildPatternPythonFile():
    regex = _getRegexFromLookups()

    pass

# URL patterns.
url = None

# Other HTTP parameters.
useragent = None
language = None
xff = None

def build():
    global url
    url = RegexMatcher()

    # Build the URL patterns.
    url.append(patterns_lfi)
    url.append(patterns_sqli)
    url.append(patterns_xss)
    url.append(patterns_rce)
    url.append(patterns_wordpress)

    # Build HTTP header patterns.
    global useragent
    useragent = re.compile(pattern_useragent)

    global language
    language = re.compile(pattern_language)

    global xff
    xff = re.compile(pattern_xff)