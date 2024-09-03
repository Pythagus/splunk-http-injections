import patterns
import os

# Global variables.
CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
DELIMITER = "###"


# This function encodes a rule / set of rules using
# the delimiter.
def encode(type, id, input):
    if isinstance(input, str):
        return type + DELIMITER + id + DELIMITER + input
    
    output = ""
    for var in input:
        output = output + "\n" + encode(type, var, input[var])

    return output


# Compile all the rules contained in the patterns.py file in
# a way that can be treated by Splunk.
def compile():
    output = "version=" + str(patterns.version) + "\ndelim=" + DELIMITER

    # Suspicious URL.
    output += encode("LFI", None, patterns.patterns_lfi)
    output += encode("XSS", None, patterns.patterns_xss)
    output += encode("RCE", None, patterns.patterns_rce)
    output += encode("SQLI", None, patterns.patterns_sqli)

    # HTTP headers regex.
    output += "\n" + encode("HTTP", "USER_AGENT", patterns.pattern_user_agent)
    output += "\n" + encode("HTTP", "XFF", patterns.pattern_xff)
    output += "\n" + encode("HTTP", "ACCEPT_LANGUAGE", patterns.pattern_accept_language)
    output += "\n" + encode("HTTP", "WORTHLESS_ASSET_URL", patterns.pattern_worthless_asset_url)

    return output


# Finally, output the compiled rules in the compiled file.
with open(CURRENT_DIR + "/compiled", 'w') as fd:
    fd.writelines(compile())