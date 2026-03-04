import os
from datetime import datetime

class HTMLReport:
    def __init__(self, data, output_dir="reports"):
        self.data = data
        self.output_dir = output_dir

    def generate(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/scan_report_{timestamp}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Web Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .summary {{ background-color: #f0f0f0; padding: 15px; border-radius: 5px; }}
                .finding {{ border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; border-radius: 5px; }}
                .high {{ border-left: 5px solid red; }}
                .medium {{ border-left: 5px solid orange; }}
                .low {{ border-left: 5px solid yellow; }}
                .info {{ border-left: 5px solid blue; }}
            </style>
        </head>
        <body>
            <h1>Web Security Scan Report</h1>
            <div class="summary">
                <p><strong>Target:</strong> {self.data['target']}</p>
                <p><strong>Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                <p><strong>Total Findings:</strong> {len(self.data['findings'])}</p>
            </div>
            
            <h2>Vulnerability Findings</h2>
            {''.join([self._format_finding(f) for f in self.data['findings']])}
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
            
        return filename

    def _format_finding(self, finding):
        severity_class = finding['severity'].lower()
        return f"""
        <div class="finding {severity_class}">
            <h3>{finding['title']} ({finding['severity']})</h3>
            <p><strong>Description:</strong> {finding['description']}</p>
            <p><strong>Endpoint:</strong> {finding['affected_endpoint']}</p>
            <p><strong>Remediation:</strong> {finding['remediation']}</p>
        </div>
        """
