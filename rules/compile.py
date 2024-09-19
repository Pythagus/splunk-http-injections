import patterns
import os

# Global variables.
CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
GLOBAL_DELIMITER = "|"
RULE_DELIMITER = "#"

def _encode_str(string: str):
    return string.encode("utf-8").hex()

# This function encodes a rule / set of rules using
# the delimiter.
def encode(type, id, rule):
    if isinstance(rule, str):
        return type + RULE_DELIMITER + id + RULE_DELIMITER + _encode_str(rule)
    
    output = ""
    for var in rule:
        output = output + GLOBAL_DELIMITER + encode(type, var, rule[var])

    return output


# Compile all the rules contained in the patterns.py file in
# a way that can be treated by Splunk.
def compile():
    output = "version=" + str(patterns.version)

    # Suspicious URL.
    output += encode("LFI", None, patterns.patterns_lfi)
    output += encode("XSS", None, patterns.patterns_xss)
    output += encode("RCE", None, patterns.patterns_rce)
    output += encode("SQLI", None, patterns.patterns_sqli)

    # HTTP headers regex.
    output += GLOBAL_DELIMITER + encode("HTTP", "USER_AGENT", patterns.pattern_user_agent)
    output += GLOBAL_DELIMITER + encode("HTTP", "XFF", patterns.pattern_xff)
    output += GLOBAL_DELIMITER + encode("HTTP", "ACCEPT_LANGUAGE", patterns.pattern_accept_language)
    output += GLOBAL_DELIMITER + encode("HTTP", "WORTHLESS_ASSET_URL", patterns.pattern_worthless_asset_url)

    return output


# Finally, output the compiled rules in the compiled file.
with open(CURRENT_DIR + "/compiled", 'w') as fd:
    fd.writelines(compile())