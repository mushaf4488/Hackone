from colorama import Fore, Style

class TerminalReport:
    def __init__(self, data):
        self.data = data

    def print_report(self):
        print("\n" + "="*60)
        print(f"{Fore.CYAN}WEB SECURITY SCAN REPORT{Style.RESET_ALL}")
        print("="*60)
        print(f"Target: {self.data['target']}")
        print("-" * 60)
        
        if not self.data['findings']:
            print(f"{Fore.GREEN}No vulnerabilities found.{Style.RESET_ALL}")
        else:
            for finding in self.data['findings']:
                color = Fore.WHITE
                if finding['severity'] == "Critical": color = Fore.MAGENTA
                elif finding['severity'] == "High": color = Fore.RED
                elif finding['severity'] == "Medium": color = Fore.YELLOW
                elif finding['severity'] == "Low": color = Fore.BLUE
                
                print(f"[{color}{finding['severity']}{Style.RESET_ALL}] {finding['title']}")
                print(f"  Endpoint: {finding['affected_endpoint']}")
                print(f"  Description: {finding['description']}")
                print(f"  Remediation: {finding['remediation']}")
                print("-" * 40)
