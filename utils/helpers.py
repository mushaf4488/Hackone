import requests
from urllib.parse import urlparse
import socket

def get_domain_from_url(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

def get_ip_from_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def make_request(url, method="GET", headers=None, data=None, timeout=10, verify=False):
    try:
        response = requests.request(method, url, headers=headers, data=data, timeout=timeout, verify=verify)
        return response
    except requests.exceptions.RequestException as e:
        return None
