class RiskScoring:
    SEVERITY_SCORES = {
        "Critical": 9.0,
        "High": 7.0,
        "Medium": 4.0,
        "Low": 2.0,
        "Informational": 0.0
    }

    @staticmethod
    def calculate_risk_score(severity, confidence="High"):
        base_score = RiskScoring.SEVERITY_SCORES.get(severity, 0.0)
        
        # Adjust based on confidence (simple multiplier for this version)
        confidence_multiplier = {
            "High": 1.0,
            "Medium": 0.8,
            "Low": 0.5
        }
        
        return round(base_score * confidence_multiplier.get(confidence, 1.0), 1)

    @staticmethod
    def get_cvss_vector(vulnerability_type):
        # Placeholder for full CVSS vector generation
        # In a real implementation, this would map types to CVSS strings
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" 
