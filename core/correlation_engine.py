class CorrelationEngine:
    def __init__(self, findings):
        self.findings = findings

    def correlate(self):
        # Simplified correlation logic
        # In a real system, we would group findings by endpoint, type, etc.
        # and remove duplicates or combine related issues.
        
        unique_findings = []
        seen_keys = set()
        
        for finding in self.findings:
            key = f"{finding['title']}_{finding['affected_endpoint']}"
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(finding)
                
        return unique_findings
