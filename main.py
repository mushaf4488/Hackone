import argparse
import yaml
import sys
from utils.logger import logger
from utils.validators import validate_url
from core.scanner_engine import ScannerEngine
from reporting.json_report import JSONReport
from reporting.html_report import HTMLReport
from reporting.terminal_report import TerminalReport

def load_config(config_path="config/config.yaml"):
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Web Security Scanner Framework")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--config", default="config/config.yaml", help="Path to configuration file")
    
    args = parser.parse_args()
    
    # Validate Target URL
    if not validate_url(args.target):
        logger.error("Invalid target URL provided.")
        sys.exit(1)
        
    config = load_config(args.config)
    
    logger.info(f"Starting scan on target: {args.target}")
    
    # Initialize and run scanner engine
    engine = ScannerEngine(args.target, config)
    scan_results = engine.start_scan()
    
    # Generate Reports
    logger.info("Generating reports...")
    
    json_report = JSONReport(scan_results)
    json_file = json_report.generate()
    logger.info(f"JSON Report saved to: {json_file}")
    
    html_report = HTMLReport(scan_results)
    html_file = html_report.generate()
    logger.info(f"HTML Report saved to: {html_file}")
    
    terminal_report = TerminalReport(scan_results)
    terminal_report.print_report()
    
    logger.info("Scan completed successfully.")

if __name__ == "__main__":
    main()
