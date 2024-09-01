from injection import patterns

# For cleaning the inputs.
import html
try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote

# TODO to be improved
import re
worthless_asset_url_regex = re.compile(r"^([a-zA-Z0-9\/\-\._]+)$")


def build():
    patterns.build()


def is_suspicious_url(url: str):
    cleaned = clean_url(url)

    if cleaned is None or is_legitimate_asset_url(cleaned):
        return None
    
    # Sometimes, bad actors will try a very-long URL composed
    # by the same character (i.e. 'A') to test the server's 
    # capacity to handle such a request.
    if is_suspicious_long_url(cleaned):
        return None
    
    return patterns.url.match(cleaned)


def is_suspicious_long_url(url: str):
    if len(url) > 256:
        for c in set(url):
            if url.count(c) > 256:
                return True
            
    return False


def is_suspicious_useragent(useragent: str):
    useragent = useragent.strip()

    return len(useragent) > 0 and patterns.useragent.search(useragent) is not None


def is_suspicious_xff(xff: str):
    xff = xff.strip()

    return len(xff) > 0 and patterns.xff.search(xff) is None


def is_suspicious_language(language: str):
    language = language.strip()

    return len(language) > 0 and patterns.language.search(language) is None
    

def clean_url(input: str):
    cleaned = input.strip()

    # Worthless url;
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

    if "%" in cleaned:
        cleaned = unquote(cleaned)

    cleaned = cleaned.lower().strip() # This is for case-insensitivity.

    return None if is_worthless_url(cleaned) else cleaned


def is_worthless_url(input: str):
    return input in ["", "/"] or len(input) <= 5

def is_legitimate_asset_url(input: str):
    return input.endswith(('.ttf', '.png', '.jpg', '.jpeg', '.ico', '.css', '.gif')) and worthless_asset_url_regex.search(input) is not None