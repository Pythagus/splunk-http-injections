#
# Special thanks to the authors of the following Github repositories:
# - RCE payload: https://github.com/payloadbox/command-injection-payload-list
# - SQL injection: https://github.com/payloadbox/sql-injection-payload-list
# - XSS: https://github.com/payloadbox/xss-payload-list
# - LFI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion/Intruders
#

import csv
import sys
import os

# Include the librairy to the Python lib path.
CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(1, CURRENT_DIR + "/../http-injections-app/bin")

# Now we can import the injection librairy.
from injection import patterns
from injection import http


# This is a global variable used to determine whether
# we will display the failed strings.
print_failures = False


# Compile the rules in a json-like format. This is
# used to imitate Splunk KV-store output, so that we
# can test the patterns in local environment.
def get_compiled_rules_as_json():
    compiled_json = {}
    version = None

    with open(CURRENT_DIR + "/../rules/compiled", 'r') as fd:
        file_content = next(fd).split("|")
    
        i = 0
        for line in file_content:
            if i == 0:
                version = int(line.split("=")[1])
            else:
                line = line.split("#")

                rule_id = str(line[1])
                compiled_json[rule_id] = {
                    "type": line[0],
                    "id": rule_id,
                    "rule": bytes.fromhex(line[2]).decode('utf-8'),
                    "version": version,
                    "state": 1,
                }

            i += 1
            
    return compiled_json


# Run a test among the content of the given file.
# key: string to recognize the type of the test
# file: file name storred in the tests/data folder
# match: lambda function to determine whether the line of
#        the file passes the test.
# must_match: should the line match the test.
def test_from_file(key: str, file: str, match, must_match = None):
    with open(CURRENT_DIR + '/data/' + file, 'r') as fd:
        is_csv = file.endswith('.csv')
        
        if is_csv:
            reader = csv.reader(fd)
        else:
            reader = fd

        total = 0
        failures = 0
        ignored = 0

        for line in reader:
            total += 1

            is_suspicious = match(line[0] if is_csv else line)

            if is_suspicious is None:
                ignored = ignored + 1
                continue

            is_suspicious = True if isinstance(is_suspicious, str) else is_suspicious

            expected = (1 - int(line[1])) if is_csv else int(must_match)
            if is_suspicious != expected:
                failures += 1

                if is_csv or print_failures:
                    log = (line[0] if is_csv else line).strip("\n")
                    print("Failed:", log, " ==> ", http.clean_url(log))

    # Display the results.
    print("[%s]" % key)
    print(("Successes: %4s (%s" % (total - failures, round(100 * (total - failures) / total, 2))) + "%)")
    print(("Failures : %4s (%s" % (failures, round(100 * failures / total, 2))) + "%)")
    print("Ignored  : %4s" % ignored)
    print( "Total    : %4s" % total)
    print()


# Test all the exploits.
patterns.build(rules=get_compiled_rules_as_json())
test_from_file("RCE", "rce.txt", match=lambda x: http.is_suspicious_url(x), must_match=True)
test_from_file("XSS", "xss.txt", match=lambda x: http.is_suspicious_url(x), must_match=True)
test_from_file("LFI", "lfi.txt", match=lambda x: http.is_suspicious_url(x), must_match=True)
test_from_file("SQLI", "sqli.txt", match=lambda x: http.is_suspicious_url(x), must_match=True)
test_from_file("XFF", "xff.csv", match=lambda x: http.is_suspicious_xff(x))
test_from_file("ACCEPT_LANGUAGE", "accept_language.csv", match=lambda x: http.is_suspicious_accept_language(x))
