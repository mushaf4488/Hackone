import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.scanner_engine import ScannerEngine
from vulnerabilities.sqli import SQLInjectionPlugin
from vulnerabilities.xss import XSSPlugin
from core.crawler import Crawler

class TestWebSecurityScanner(unittest.TestCase):
    
    def setUp(self):
        self.config = {
            'vulnerabilities': {
                'sqli_payloads': ["'"],
                'xss_payloads': ["<script>"]
            },
            'crawler': {
                'max_depth': 1,
                'max_pages': 2
            },
            'recon': {
                'ports': [80]
            }
        }
        self.target = "http://test.com"

    @patch('vulnerabilities.sqli.make_request')
    def test_sqli_detection(self, mock_request):
        # Mock a vulnerable response
        mock_response = MagicMock()
        mock_response.text = "SQL syntax error"
        mock_request.return_value = mock_response
        
        plugin = SQLInjectionPlugin(self.target, self.config)
        findings = plugin.scan()
        
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]['title'], "SQL Injection")
        print("\n[+] SQL Injection Module: PASSED")

    @patch('vulnerabilities.xss.make_request')
    def test_xss_detection(self, mock_request):
        # Mock a vulnerable response
        mock_response = MagicMock()
        mock_response.text = "<html><script>alert(1)</script></html>"
        mock_request.return_value = mock_response
        
        plugin = XSSPlugin(self.target, self.config)
        findings = plugin.scan()
        
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]['title'], "Reflected Cross-Site Scripting (XSS)")
        print("[+] XSS Module: PASSED")

    @patch('core.crawler.make_request')
    def test_crawler(self, mock_request):
        # Mock HTML with links
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '<a href="/page1">Page 1</a><a href="/page2">Page 2</a>'
        mock_request.return_value = mock_response
        
        crawler = Crawler(self.target, self.config)
        urls = crawler.crawl()
        
        # Should find start_url + 2 links (but limited by max_pages=2 in setup or logic)
        self.assertTrue(len(urls) >= 1)
        print(f"[+] Crawler Module: PASSED (Found {len(urls)} URLs)")

    @patch('core.recon.PortScanner')
    def test_scanner_engine_flow(self, mock_port_scanner):
        # Mock dependencies
        mock_port_scanner.return_value.scan_ports.return_value = [80, 443]
        
        with patch('core.scanner_engine.Crawler') as MockCrawler:
            MockCrawler.return_value.crawl.return_value = ["http://test.com"]
            
            with patch('core.scanner_engine.SSLAnalyzer') as MockSSL:
                MockSSL.return_value.analyze.return_value = {"version": "TLS 1.2"}
                
                # Mock plugins to return empty lists to avoid complex mocking
                with patch('vulnerabilities.sqli.SQLInjectionPlugin.scan', return_value=[]):
                    with patch('vulnerabilities.xss.XSSPlugin.scan', return_value=[]):
                         with patch('vulnerabilities.misconfiguration.MisconfigurationPlugin.scan', return_value=[]):
                            
                            engine = ScannerEngine(self.target, self.config)
                            results = engine.start_scan(status_callback=lambda x: None)
                            
                            self.assertEqual(results['target'], self.target)
                            self.assertEqual(results['recon']['open_ports'], [80, 443])
                            print("[+] Scanner Engine Orchestration: PASSED")

if __name__ == '__main__':
    unittest.main()
