import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from utils.logger import logger
from utils.helpers import make_request
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Crawler:
    def __init__(self, start_url, config):
        self.start_url = start_url
        self.config = config
        self.visited_endpoints = set() # Store tuples of (url, method)
        self.urls_to_visit = [start_url]
        self.domain = urlparse(start_url).netloc

    def crawl(self, status_callback=None):
        logger.info(f"Starting crawler on {self.start_url}")
        if status_callback:
            status_callback(f"Tool Active: Custom Multi-Threaded/BFS Crawler spidering {self.domain}...")
        
        # Override to act unlimited
        max_depth = self.config.get('crawler', {}).get('max_depth', 3)
        max_pages = 99999  # User requested unlimited
        
        while self.urls_to_visit and len(self.visited_endpoints) < max_pages:
            current_url = self.urls_to_visit.pop(0)
            
            if (current_url, 'GET') in self.visited_endpoints:
                continue
                
            self.visited_endpoints.add((current_url, 'GET'))
            
            # Emit callback
            if status_callback and (len(self.visited_endpoints) <= 3 or len(self.visited_endpoints) % 10 == 0):
                status_callback(f"[Crawler] Discovered {len(self.visited_endpoints)} endpoints (GET/POST/PUT/DELETE)...")
            
            # Conduct an HTTP OPTIONS probe to find supported methods natively on this path
            try:
                options_resp = requests.options(current_url, timeout=5, verify=False)
                if 'Allow' in options_resp.headers:
                    allowed_methods = options_resp.headers['Allow'].split(',')
                    for method in allowed_methods:
                        m = method.strip().upper()
                        if m and m != 'GET':  # We already added GET
                            if (current_url, m) not in self.visited_endpoints:
                                self.visited_endpoints.add((current_url, m))
            except Exception as e:
                logger.debug(f"OPTIONS probe failed on {current_url}")

            response = make_request(current_url)
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all GET links via <a>
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(current_url, href)
                    
                    if self.domain in urlparse(full_url).netloc:
                        # Extract specialized data attributes (like Rails data-method)
                        data_method = link.get('data-method', '').upper()
                        if data_method in ['PUT', 'DELETE', 'POST', 'PATCH']:
                            if (full_url, data_method) not in self.visited_endpoints:
                                self.visited_endpoints.add((full_url, data_method))

                        if (full_url, 'GET') not in self.visited_endpoints:
                            self.urls_to_visit.append(full_url)
                            self.visited_endpoints.add((full_url, 'GET'))

                # Find all form actions via <form>
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = form.get('method', 'GET').upper()
                    
                    # Detect overridden methods through hidden inputs (like _method)
                    hidden_input = form.find('input', {'name': '_method'})
                    if hidden_input:
                        method = hidden_input.get('value', method).upper()
                        
                    full_url = urljoin(current_url, action)
                    
                    if self.domain in urlparse(full_url).netloc:
                        if (full_url, method) not in self.visited_endpoints:
                            self.visited_endpoints.add((full_url, method))
                            if method == 'GET' and (full_url, 'GET') not in self.visited_endpoints:
                                self.urls_to_visit.append(full_url)
                        
        logger.info(f"Crawling finished. Found {len(self.visited_endpoints)} endpoints.")
        if status_callback:
            status_callback(f"[Crawler] Completed. Acquired {len(self.visited_endpoints)} distinct methods/endpoints.")
        
        return [{"url": u, "method": m} for u, m in self.visited_endpoints]
