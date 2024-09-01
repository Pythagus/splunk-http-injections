from injection import patterns

# For cleaning the inputs.
import html
try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote


# This function takes an URL in parameter and
# determines whether this URL contains a suspicious
# pattern like XSS, SQL-injection, etc.
def is_suspicious_url(url: str):
    cleaned = clean_url(url)

    # cleaned can be none if it is a worthless url.
    # We also don't want to check a legitimate asset access.
    if cleaned is None or is_legitimate_asset_url(cleaned):
        return None
    
    # Sometimes, bad actors will try a very-long URL composed
    # by the same character (i.e. 'A') to test the server's 
    # capacity to handle such a request.
    if is_suspicious_long_url(cleaned):
        return None
    
    # Let the magic happen here: check trace of any injection.
    return patterns.url.match(cleaned)


# This will check whether the URL is long enough
# to be a possible HTTP exhaustion attack (Denial
# of services or Buffer Overflow)
#
# See https://docs.imperva.com/bundle/on-premises-knowledgebase-reference-guide/page/abnormally_long_url.htm
def is_suspicious_long_url(url: str):
    if len(url) > 256:
        for c in set(url):
            # If the URL contains at least 128 times the same character.
            if url.count(c) > 128:
                return True
            
    return False


# Determine whether the given user agent is suspicious.
# For now, this is only based on a blacklist and not on
# the format of the user agent because there is no official
# standard. So, that's not an easy topic. WIP.
def is_suspicious_useragent(useragent: str):
    useragent = useragent.strip()

    return len(useragent) > 0 and patterns.useragent.search(useragent) is not None


# Determine whether the given X-Forwarded-For value is
# suspicious. This field should only contain an IP or an
# array of IP.
def is_suspicious_xff(xff: str):
    xff = xff.strip()

    return len(xff) > 0 and patterns.xff.search(xff) is None


# This function check whether the Accept-Language parameter
# is appropriate, meaning that it follows the convention.
#
# See https://datatracker.ietf.org/doc/html/rfc3282
def is_suspicious_language(language: str):
    language = language.strip()

    return len(language) > 0 and patterns.language.search(language) is None
    

# This function will clean the accessed HTTP url to remove
# the unicode characters, and return a lowercase field, so
# that the next functions don't have to deal with the
# case sensitivity.
def clean_url(input: str):
    cleaned = input.strip()

    # If it is a worthless URL, then do nothing!
    if is_worthless_url(cleaned):
        return None
    
    # If the input is a full URL like https://example.com/this-is-a-test?query=something-suspicious-here
    if cleaned.startswith("http"):
        cleaned = cleaned.strip("https://").strip("http://")
        index_of_first_slash = cleaned.find("/")

        if index_of_first_slash == -1:
            return ""
        
        cleaned = cleaned[index_of_first_slash:]

    cleaned = html.unescape(cleaned)
    cleaned = unquote(cleaned)

    # If the URL still contains a "%", then it was
    # at least double-encoded. We don't do that in
    # a while loop because it is time consuming, and
    # it is mostly not understood by web servers anyway.
    if "%" in cleaned:
        cleaned = unquote(cleaned)

    cleaned = cleaned.lower().strip() # This is for case-insensitivity.

    # We check again if the URL is worthless after the encoding part.
    return None if is_worthless_url(cleaned) else cleaned


# Determine whether the URL is not worth checking
# because it is a well-known legitimate URL.
def is_worthless_url(input: str):
    return input in ["", "/"] or len(input) <= 5


# This function will determine whether the given URL
# is a legitimate asset access. It is one of the major
# accesses that your applications will generate. So, it's
# a major optimization.
def is_legitimate_asset_url(input: str):
    return input.endswith(('.ttf', '.png', '.jpg', '.jpeg', '.ico', '.css', '.gif')) and patterns.worthless_asset.search(input) is not None