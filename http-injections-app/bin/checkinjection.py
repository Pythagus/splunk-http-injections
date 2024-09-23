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

    deep = Option(
        doc='''
            **Syntax:** **deep=***<str>*
            **Description:** Determine whether all rules must be checked, or if we stop the checks when a rule matches''',
        require=False, default=False, validate=validators.Boolean())

    url = Option(
        doc='''
            **Syntax:** **url=***<str>*
            **Description:** Field containing the accessed URL''',
        require=False, validate=validators.Fieldname())

    useragent = Option(
        doc='''
            **Syntax:** **useragent=***<str>*
            **Description:** User agent used for the HTTP request''',
        require=False, validate=validators.Fieldname())

    acceptlanguage = Option(
        doc='''
            **Syntax:** **acceptlanguage=***<str>*
            **Description:** HTTP Accept-Language parameter given by the client''',
        require=False, validate=validators.Fieldname())
    
    contenttype = Option(
        doc='''
            **Syntax:** **contenttype=***<str>*
            **Description:** HTTP Content-Type parameter given by the client''',
        require=False, validate=validators.Fieldname())
    
    cookie = Option(
        doc='''
            **Syntax:** **cookie=***<str>*
            **Description:** HTTP Cookie set in the request header''',
        require=False, validate=validators.Fieldname())

    xforwardedfor = Option(
        doc='''
            **Syntax:** **xforwardedfor=***<str>*
            **Description:** HTTP X-Forwarded-For set in the request header''',
        require=False, validate=validators.Fieldname())
    
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
    
    # Determine whether the analysis shouldn't stop at
    # first match, but check all rules.
    def isDeepAnalysis(self):
        return getattr(self, 'deep') or False

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
            patterns.build(rules=http_rules, deep=self.isDeepAnalysis())
        except patterns.HttpInjectionRegexCompilationFailure as e:
            self.write_error(repr(e))
            self.write_error("HttpInjections: Failed to compile regex: %s" % e.regex_key)
            exit(ERR_REGEX_COMPILATION)

    # Determine whether the event matches one of the suspicious
    # rules in place.
    def check_rules(self, event):
        deep = self.isDeepAnalysis()
        rules_triggered = []
        should_continue = True

        # Check the User-Agent.
        if self.hasParameter('useragent') and http.is_suspicious_user_agent(self.getParamValue('useragent', event)):
            rules_triggered.append("USER_AGENT")
            should_continue = deep

        # Check the Accept-Language.
        if should_continue and self.hasParameter('acceptlanguage') and http.is_suspicious_accept_language(self.getParamValue('acceptlanguage', event)):
            rules_triggered.append("ACCEPT_LANGUAGE")
            should_continue = deep

        # Check the Content-Type.
        if should_continue and self.hasParameter('contenttype') and http.is_suspicious_content_type(self.getParamValue('contenttype', event)):
            rules_triggered.append("CONTENT_TYPE")
            should_continue = deep

        # Check the Cookie.
        if should_continue and self.hasParameter('cookie') and http.is_suspicious_cookie(self.getParamValue('cookie', event)):
            rules_triggered.append("COOKIE")
            should_continue = deep

        # Check the X-Forwarded-For.
        if should_continue and self.hasParameter('xforwardedfor') and http.is_suspicious_xff(self.getParamValue('xforwardedfor', event)):
            rules_triggered.append("X_FORWARDED_FOR")
            should_continue = deep

        # Check the URL.
        if should_continue and self.hasParameter('url'):
            suspicious_url_rule = http.is_suspicious_url(self.getParamValue('url', event))

            if suspicious_url_rule:
                if isinstance(suspicious_url_rule, list):
                    rules_triggered = rules_triggered + suspicious_url_rule 
                else:
                    rules_triggered.append(suspicious_url_rule)
                    
                should_continue = deep
        
        return rules_triggered

    # This is the method treating all the events.
    def stream(self, events):
        if self.isDeepAnalysis():
            msg = "HttpInjections: Deep analysis takes more time!"
            self.write_warning(msg)
            self.logger.warning(msg)

        for event in events:
            event["rules_triggered"] = self.check_rules(event)

            yield event


# Finally, say to Splunk that this command exists.
dispatch(CheckInjectionCommand, sys.argv, sys.stdin, sys.stdout, __name__)