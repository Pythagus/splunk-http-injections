import re

# Common regex-es instances. It is initialized in the build function.
url = None
user_agent = None
accept_language = None
content_type = None
cookie = None
xff = None
worthless_asset = None
# #


# Exception raised when a regex compilation failed.
class HttpInjectionRegexCompilationFailure(RuntimeError):
    def __init__(self, regex_key: str):
        self.regex_key = regex_key


# This function is a wrapper used for catching
# a regex compilation issue and send a message
# to the end-user using the command.
def _compile_regex(key, regex = None):
    if regex is None:
        return None
    
    try:
        return re.compile(regex)
    except re.error:
        raise HttpInjectionRegexCompilationFailure(regex_key=key)

# This class will help to manage a list of regex-es to
# match to the given strings.
class RegexMatcher(object):

    # Build the regex matcher instance.
    def __init__(self, patterns: dict = None, deep = False):
        self.regex = {}
        self.deep = deep

        if patterns:
            self.append(patterns)

    # Append new regex-es to the current ones.
    def append(self, patterns: dict):
        for key in patterns:
            self.regex[key] = _compile_regex(key, patterns[key])

    # This method will return the id of the first rule that
    # matched the given input or False if no rule triggered.
    def match(self, input: str):
        rules = []

        for key in self.regex:
            if self.regex[key].search(input) is not None:
                rules.append(key)

                if not self.deep:
                    break
            
        return False if len(rules) == 0 else rules


# Load the rules from the storage facility
# and transform them in the appropriate way.
def _transform_rules(rules):
    new_rules = {}

    for rule_id in rules:
        rule = rules[rule_id]
        
        if rule["type"] not in new_rules:
            new_rules[rule["type"]] = {}

        new_rules[rule["type"]][rule_id] = rule["rule"]

    return new_rules


# Build the regexes.
# This is not done when the file is loaded to let Splunk
# decide when is the appropriate time (when the command 
# calls the prepare() method).
def build(rules, deep=False):
    rules = _transform_rules(rules)

    # Build the URL patterns.
    global url
    url = RegexMatcher(deep=deep)
    url.append(rules.get("LFI", []))
    url.append(rules.get("SQLI", []))
    url.append(rules.get("XSS", []))
    url.append(rules.get("RCE", []))

    http_rules = dict(rules.get("HTTP"))

    # If no rules were found, then it's a failure.
    if http_rules is None:
        return
    
    # So that we can update global variables.
    global user_agent, accept_language, content_type, xff, worthless_asset, cookie
    
    # Build HTTP header patterns.
    user_agent      = _compile_regex("USER_AGENT", http_rules.get("USER_AGENT"))
    accept_language = _compile_regex("ACCEPT_LANGUAGE", http_rules.get("ACCEPT_LANGUAGE"))
    content_type    = _compile_regex("CONTENT_TYPE", http_rules.get("CONTENT_TYPE"))
    cookie          = _compile_regex("COOKIE", http_rules.get("COOKIE"))
    xff             = _compile_regex("XFF", http_rules.get("XFF"))
    worthless_asset = _compile_regex("WORTHLESS_ASSET_URL", http_rules.get("WORTHLESS_ASSET_URL"))