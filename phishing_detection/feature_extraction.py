from urllib.parse import urlparse
import re

def extract_features(url):
    parsed = urlparse(url)

    features = [
        len(url),                                  # url_length
        1 if parsed.scheme in ["http", "https"] else 0,  # valid_url
        url.count("@"),                            # at_symbol
        len(re.findall(r"login|verify|bank|secure", url.lower())), # sensitive_words_count
        len(parsed.path),                          # path_length
        1 if parsed.scheme == "https" else 0,      # isHttps
        url.count("."),                            # nb_dots
        url.count("-"),                            # nb_hyphens
        url.lower().count("and"),                  # nb_and
        url.lower().count("or"),                   # nb_or
        url.lower().count("www"),                  # nb_www
        url.lower().count("com"),                  # nb_com
        url.count("_")                             # nb_underscore
    ]

    return features
