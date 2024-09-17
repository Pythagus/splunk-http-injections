#!/usr/bin/env python

import sys
from splunklib.client import Service
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from injection import patterns
from injection import http


# Name of the KV-store used to store the HTTP rules.
KVSTORE_NAME = "HttpInjections_Rules"

# Multiple error codes used to know where the
# script failed and raised an error.
ERR_KVSTORE_RULES_RETRIEVAL = 40
ERR_REGEX_COMPILATION = 41


# Get the rules storred in the KV-store.
def get_rules_from_kvstore(service: Service):
    kvstore = service.kvstore[KVSTORE_NAME]
    _entries = kvstore.data.query()

    entries = {}
    for entry in _entries:
        rule_id = entry["rule_id"]
        version = int(entry["version"])
        actual_version = None if rule_id not in entries else int(entries[rule_id]["version"])

        if entry["status"] and (actual_version is None or actual_version < version):
            entries[rule_id] = {
                "type": entry["rule_type"],
                "id": entry["rule_id"],
                "rule": bytes.fromhex(entry["rule"]).decode('utf-8'),
                "version": version
            }

    return entries


@Configuration()
class CheckInjectionCommand(StreamingCommand):

    hostname = Option(
        doc='''
            **Syntax:** **hostname=***<str>*
            **Description:** Field containing the web server hostname like google.com''',
        require=False)

    url = Option(
        doc='''
            **Syntax:** **url=***<str>*
            **Description:** Field containing the accessed URL''',
        require=False)

    useragent = Option(
        doc='''
            **Syntax:** **useragent=***<str>*
            **Description:** User agent used for the HTTP request ''',
        require=False)

    language = Option(
        doc='''
            **Syntax:** **language=***<str>*
            **Description:** HTTP Accept-Language parameter given by the client ''',
        require=False)
    
    # Determine whether the command has defined
    # the given parameter.
    def hasParameter(self, param: str):
        return getattr(self, param) is not None
    
    # Get a parameter from the event if it exists, or
    # from the command otherwise.
    def getParamValue(self, param: str, event = None):
        self_value = getattr(self, param)

        if event is not None and self_value in event:
            return event[self_value]
        
        return self_value

    # This method is called by splunkd before the
    # command executes. It is used to get the configuration
    # data from Splunk.
    def prepare(self):
        # Try to get the rules from the KV-store.
        try:
            http_rules = get_rules_from_kvstore(self.service)
        except Exception as e:
            self.write_error(repr(e))
            exit(1)
        #except:
        #    self.write_error("HttpInjections: Failed to load rules from KV-Store (%s)" % KVSTORE_NAME, e)
        #    exit(ERR_KVSTORE_RULES_RETRIEVAL)

        # Build the regexes and local stuff.
        try:
            patterns.build(rules=http_rules)
        except patterns.HttpInjectionRegexCompilationFailure as e:
            self.write_error(repr(e))
            self.write_error("HttpInjections: Failed to compile regex: %s" % e.regex_key)
            exit(ERR_REGEX_COMPILATION)

    # This is the method treating all the events.
    def stream(self, events):
        for event in events:
            rules_triggered = []

            if self.hasParameter('useragent') and http.is_suspicious_user_agent(self.getParamValue('useragent', event)):
                rules_triggered.append("USER_AGENT")

            if self.hasParameter('language') and http.is_suspicious_accept_language(self.getParamValue('language', event)):
                rules_triggered.append("ACCEPT_LANGUAGE")

            if self.hasParameter('url'):
                suspicious_url_rule = http.is_suspicious_url(self.getParamValue('url', event))

                if suspicious_url_rule:
                    rules_triggered.append(suspicious_url_rule)

            event["rules_triggered"] = rules_triggered

            yield event


# Finally, say to Splunk that this command exists.
dispatch(CheckInjectionCommand, sys.argv, sys.stdin, sys.stdout, __name__)