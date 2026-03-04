class KnowledgeBase:
    VULNERABILITIES = {
        "SQL_INJECTION": {
            "name": "SQL Injection",
            "description": "SQL injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.",
            "remediation": "Use prepared statements (parameterized queries) instead of string concatenation to build SQL queries.",
            "owasp_category": "A03:2021-Injection",
            "cwe_id": "CWE-89"
        },
        "XSS_REFLECTED": {
            "name": "Reflected Cross-Site Scripting (XSS)",
            "description": "Reflected XSS occurs when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.",
            "remediation": "Output encode all user-controllable data before rendering it in the browser.",
            "owasp_category": "A03:2021-Injection",
            "cwe_id": "CWE-79"
        },
        "CSRF": {
            "name": "Cross-Site Request Forgery (CSRF)",
            "description": "CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they are currently authenticated.",
            "remediation": "Implement anti-CSRF tokens for all state-changing operations.",
            "owasp_category": "A01:2021-Broken Access Control",
            "cwe_id": "CWE-352"
        },
        "MISSING_HEADERS": {
            "name": "Missing Security Headers",
            "description": "The web application is missing important security headers that can protect against various attacks.",
            "remediation": "Configure the web server to send security headers like X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy.",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "cwe_id": "CWE-693"
        }
    }

    @staticmethod
    def get_vulnerability_info(vuln_key):
        return KnowledgeBase.VULNERABILITIES.get(vuln_key, {
            "name": "Unknown Vulnerability",
            "description": "No description available.",
            "remediation": "Investigate manually.",
            "owasp_category": "Unknown",
            "cwe_id": "Unknown"
        })
