import logging
import os
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class Logger:
    def __init__(self, name="WebSecurityScanner"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Determine logs directory relative to this file
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        logs_dir = os.path.join(base_dir, "logs")
        
        # Create logs directory if it doesn't exist
        try:
            if not os.path.exists(logs_dir):
                os.makedirs(logs_dir)
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = os.path.join(logs_dir, f"scan_{timestamp}.log")
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Could not set up file logging: {e}{Style.RESET_ALL}")
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(console_handler)

    def info(self, message):
        self.logger.info(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} {message}")

    def warning(self, message):
        self.logger.warning(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")

    def error(self, message):
        self.logger.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")

    def debug(self, message):
        self.logger.debug(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} {message}")

    def critical(self, message):
        self.logger.critical(f"{Fore.RED}{Style.BRIGHT}[CRITICAL]{Style.RESET_ALL} {message}")

# Singleton instance
logger = Logger()
