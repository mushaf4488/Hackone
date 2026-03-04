# Web Security Scanner Framework

## Overview
A professional, modular, research-grade Python-based Web Application Security Analysis Framework designed for authorized security testing. This framework performs multi-layer web application security analysis including reconnaissance, vulnerability detection, and risk scoring.

**Disclaimer: This tool is for authorized security testing only. The authors are not responsible for any misuse.**

## Features
- **Web Interface**: Hacker-themed Dashboard built with Flask & Bootstrap.
- **Real-time Logging**: Live scan progress updates via WebSockets.
- **Reconnaissance**: Subdomain enumeration, port scanning, service fingerprinting.
- **Vulnerability Detection**: SQL Injection, XSS, CSRF, Misconfigurations.
- **Crawling**: Dynamic crawler for endpoint discovery.
- **Reporting**: JSON, HTML, and Terminal reports.
- **Risk Scoring**: CVSS-inspired scoring logic.

## Installation
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Web Application (Recommended)
Run the Flask web server:
```bash
python app.py
```
Then open your browser and navigate to: `http://127.0.0.1:5000`

### Command Line Interface
Run the scanner from the terminal:
```bash
python main.py --target http://example.com
```

## Testing
To verify that all modules are working correctly, run the test suite:
```bash
python tests/test_modules.py
```

## Architecture
See the `docs/` folder for detailed architecture and MSc-level project documentation.
