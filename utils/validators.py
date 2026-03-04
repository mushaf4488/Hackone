from urllib.parse import urlparse
import validators as py_validators

def validate_url(url):
    return py_validators.url(url)

def validate_domain(domain):
    return py_validators.domain(domain)
