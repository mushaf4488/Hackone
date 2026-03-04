import socket
from utils.logger import logger
from utils.helpers import get_ip_from_domain

class PortScanner:
    def __init__(self, target_domain, config):
        self.target_domain = target_domain
        self.config = config
        self.open_ports = []

    def scan_ports(self):
        logger.info(f"Starting port scan on {self.target_domain}")
        target_ip = get_ip_from_domain(self.target_domain)
        
        if not target_ip:
            logger.error(f"Could not resolve IP for {self.target_domain}")
            return []
            
        ports = self.config['recon']['ports']
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                logger.info(f"Port {port} is OPEN")
                self.open_ports.append(port)
            sock.close()
            
        return self.open_ports
