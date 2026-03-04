import socket
from urllib.parse import urlparse
from .base_plugin import BasePlugin
from utils.logger import logger

class ExposedDatabasePlugin(BasePlugin):
    def scan(self):
        logger.info(f"Starting Exposed Database scan on {self.target_url}")
        
        # Strip port if necessary
        domain = urlparse(self.target_url).netloc
        if ':' in domain:
            domain = domain.split(':')[0]
            
        findings = []
        port = 3306
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        
        try:
            # Check if port is open
            result = sock.connect_ex((domain, port))
            if result == 0:
                # Basic Enumeration: Grab the MySQL banner quietly
                banner = ""
                try:
                    raw_data = sock.recv(1024)
                    if raw_data:
                        # Extract printable characters from the binary protocol response
                        banner = ''.join(c for c in raw_data.decode('latin-1', errors='ignore') if c.isprintable())
                except socket.timeout:
                    banner = "Timeout fetching banner"

                findings.append({
                    "type": "Exposed Database Server",
                    "description": "MySQL/MariaDB database port 3306 is exposed to the internet, creating a significant security risk. Strong firewall configurations and access control policies should be implemented to restrict access only to trusted application servers.",
                    "severity": "High",
                    "location": f"{domain}:{port}",
                    "proof_of_concept": f"Socket connection successful on {domain}:3306. Server Response: {banner}"
                })
        except Exception as e:
            logger.error(f"Error checking for exposed database: {e}")
        finally:
            sock.close()

        self.results = findings
        return findings
