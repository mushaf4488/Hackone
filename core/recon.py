from utils.logger import logger
from .port_scanner import PortScanner

class Recon:
    def __init__(self, target_url, config):
        self.target_url = target_url
        self.config = config
        self.results = {}

    def run(self, status_callback=None):
        logger.info("Starting Reconnaissance phase...")
        if status_callback: 
            status_callback("Tools Active: Custom Subdomain Enum (crt.sh API) & TCP Socket Port Scanner")
        
        # Subdomain enumeration using HackerTarget + crt.sh fallback
        self.results['subdomains'] = []
        from urllib.parse import urlparse
        import requests
        
        domain = urlparse(self.target_url).netloc
        if ':' in domain:
            domain = domain.split(':')[0]
            
        base_domain = domain
        if base_domain.startswith('www.'):
            base_domain = base_domain[4:]
            
        if status_callback:
            status_callback(f"[Subdomain Enum] Enumerating subdomains for '{base_domain}'...")
            
        try:
            subdomains = set()
            # Try HackerTarget first as it is generally more stable
            try:
                hk_req = requests.get(f"https://api.hackertarget.com/hostsearch/?q={base_domain}", timeout=10)
                if hk_req.status_code == 200 and "error" not in hk_req.text.lower():
                    for line in hk_req.text.split('\n'):
                        if ',' in line:
                            sub = line.split(',')[0].strip()
                            if sub:
                                subdomains.add(sub)
            except Exception as e:
                logger.debug(f"HackerTarget API failed: {e}")

            # Try crt.sh as fallback or complement
            try:
                crt_req = requests.get(f"https://crt.sh/?q=%25.{base_domain}&output=json", timeout=10)
                if crt_req.status_code == 200:
                    data = crt_req.json()
                    for cert in data:
                        name_value = cert.get('name_value', '')
                        if '\n' in name_value:
                            for sub in name_value.split('\n'):
                                subdomains.add(sub)
                        else:
                            subdomains.add(name_value)
            except Exception as e:
                logger.debug(f"crt.sh API failed: {e}")
                
            self.results['subdomains'] = list(subdomains)
            if status_callback:
                status_callback(f"[Subdomain Enum] Successfully found {len(subdomains)} subdomains.")
        except Exception as e:
            logger.error(f"Error fetching subdomains: {e}")
            if status_callback:
                status_callback(f"[Subdomain Enum] Network error occurred during enumeration.")
        
        # Port Scanning
        if status_callback:
            status_callback(f"[Port Scan] Scanning common TCP ports on {domain}...")
        port_scanner = PortScanner(domain, self.config)
        self.results['open_ports'] = port_scanner.scan_ports()
        
        if status_callback:
            status_callback(f"[Port Scan] Found {len(self.results['open_ports'])} open ports.")
            
        # Tech Stack Fingerprinting
        self.results['tech_stack'] = []
        if status_callback:
            status_callback(f"[Tech Stack] Fingerprinting {self.target_url}...")
        try:
            resp = requests.head(self.target_url, timeout=5, allow_redirects=True)
            headers = resp.headers
            if 'Server' in headers:
                self.results['tech_stack'].append(f"Server: {headers['Server']}")
            if 'X-Powered-By' in headers:
                self.results['tech_stack'].append(f"Powered By: {headers['X-Powered-By']}")
            if 'X-AspNet-Version' in headers:
                self.results['tech_stack'].append(f"ASP.NET: {headers['X-AspNet-Version']}")
            if not self.results['tech_stack']:
                self.results['tech_stack'].append("No distinct tech stack headers found.")
            if status_callback:
                status_callback(f"[Tech Stack] Analyzed HTTP headers.")
        except Exception as e:
            logger.error(f"Error fingerprinting tech stack: {e}")
            self.results['tech_stack'].append("Error determining tech stack.")

        # IP & Network Info (IP Finder)
        self.results['ip_info'] = {}
        if status_callback:
            status_callback(f"[IP/Network Finder] Resolving network mapping for {base_domain}...")
        try:
            ip_req = requests.get(f"http://ip-api.com/json/{base_domain}", timeout=5)
            if ip_req.status_code == 200:
                ip_data = ip_req.json()
                if ip_data.get('status') == 'success':
                    self.results['ip_info'] = {
                        "IP Address": ip_data.get("query"),
                        "ISP": ip_data.get("isp"),
                        "Organization": ip_data.get("org"),
                        "Location": f"{ip_data.get('city')}, {ip_data.get('country')}"
                    }
                else:
                    self.results['ip_info'] = {"Error": "Could not resolve IP location."}
            if status_callback:
                status_callback(f"[IP/Network Finder] Successfully mapped IP and ISP info.")
        except Exception as e:
            logger.error(f"Error finding IP info: {e}")
            self.results['ip_info'] = {"Error": "Network error during IP lookup."}

        # DNS Enumeration
        self.results['dns_enum'] = []
        if status_callback:
            status_callback(f"[DNS Enum] Retrieving DNS records for {base_domain}...")
        try:
            dns_records = []
            for dtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                req = requests.get(f"https://dns.google/resolve?name={base_domain}&type={dtype}", timeout=3)
                if req.status_code == 200:
                    ans = req.json().get('Answer', [])
                    for record in ans:
                        dns_records.append({'type': dtype, 'data': record['data']})
            self.results['dns_enum'] = dns_records
            if status_callback:
                status_callback(f"[DNS Enum] Found {len(dns_records)} DNS records.")
        except Exception as e:
            logger.error(f"Error enumerating DNS: {e}")
            self.results['dns_enum'] = []

        return self.results
