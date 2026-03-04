from .base_plugin import BasePlugin
from utils.logger import logger
from utils.helpers import make_request
from intelligence.knowledge_base import KnowledgeBase
from core.risk_scoring import RiskScoring

class MisconfigurationPlugin(BasePlugin):
    def scan(self):
        logger.info(f"Starting Misconfiguration scan on {self.target_url}")
        
        response = make_request(self.target_url)
        findings = []
        
        if response:
            headers = response.headers
            missing_headers = []
            
            security_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Content-Security-Policy",
                "Strict-Transport-Security"
            ]
            
            for header in security_headers:
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                info = KnowledgeBase.get_vulnerability_info("MISSING_HEADERS")
                findings.append({
                    "title": info["name"],
                    "description": f"Missing security headers: {', '.join(missing_headers)}",
                    "severity": "Low",
                    "risk_score": RiskScoring.calculate_risk_score("Low"),
                    "affected_endpoint": self.target_url,
                    "proof": "Headers not present in response.",
                    "remediation": info["remediation"],
                    "owasp_category": info["owasp_category"]
                })
                
        self.results = findings
        return findings
