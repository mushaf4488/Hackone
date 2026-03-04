import ssl
import socket
from urllib.parse import urlparse
from utils.logger import logger

class SSLAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.port = 443

    def analyze(self):
        logger.info(f"Starting SSL analysis for {self.domain}")
        
        context = ssl.create_default_context()
        try:
            with socket.create_connection((self.domain, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    return {
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "subject": dict(x[0] for x in cert['subject']),
                        "version": version,
                        "cipher": cipher,
                        "expiry": cert['notAfter']
                    }
        except Exception as e:
            logger.error(f"SSL Analysis failed: {e}")
            return None
