import whois
from datetime import datetime
from urllib.parse import urlparse

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc.lower()

def domain_age_check(url):
    try:
        domain = extract_domain(url)
        w = whois.whois(domain)
        creation_date = w.creation_date

        if not creation_date:
            return 0.3, "Domain creation date not available"

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age_days = (datetime.utcnow() - creation_date.replace(tzinfo=None)).days

        if age_days < 180:
            return 0.8, f"Domain newly registered ({age_days} days old)"

        return 0.0, f"Domain age is {age_days} days"

    except Exception:
        return 0.4, "WHOIS lookup failed"
