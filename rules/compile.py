import patterns
import os

# Global variables.
CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
GLOBAL_DELIMITER = "|"
RULE_DELIMITER = "###"


# This function encodes a rule / set of rules using
# the delimiter.
def encode(type, id, input):
    if isinstance(input, str):
        return str(type + RULE_DELIMITER + id + RULE_DELIMITER + input).encode("utf-8").hex()
    
    output = ""
    for var in input:
        output = output + GLOBAL_DELIMITER + encode(type, var, input[var])

    return output


# Compile all the rules contained in the patterns.py file in
# a way that can be treated by Splunk.
def compile():
    output = "version=" + str(patterns.version) + GLOBAL_DELIMITER + "delim=" + RULE_DELIMITER

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

    # Encode the specific-applications patterns.
    products = patterns.patterns_custom_apps
    for product in products:
        for type in products[product]:
            output += encode(product + "." + str(type).upper(), None, products[product][type])

    return output


# Finally, output the compiled rules in the compiled file.
with open(CURRENT_DIR + "/compiled", 'w') as fd:
    fd.writelines(compile())