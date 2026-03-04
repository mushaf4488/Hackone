import json
import os
from datetime import datetime

class JSONReport:
    def __init__(self, data, output_dir="reports"):
        self.data = data
        self.output_dir = output_dir

    def generate(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/scan_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=4)
            
        return filename
