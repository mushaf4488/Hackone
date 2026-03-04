import socket
import ftplib
import time

class AuthScanner:
    def __init__(self, target, socketio_ref):
        self.target = target
        self.socketio = socketio_ref

    def log(self, msg, level='info'):
        # level can be info, warning, danger, success
        self.socketio.emit('auth_scan_update', {'message': msg, 'level': level})

    def run(self):
        self.log(f"Initializing Authentication & Auditing module against {self.target}...", "info")
        
        # 1. Check if FTP port is open
        self.log(f"Targeting {self.target}: Checking if FTP (Port 21) is accessible...", "info")
        if self.check_port(21):
            self.log("Port 21 is open. Proceeding with FTP access auditing...", "warning")
            self.test_ftp_anonymous()
            
            # Simulated dictionary demonstration
            self.log("Simulating dictionary attack pattern (Educational Mode)...", "warning")
            time.sleep(1)
            self.log("[!] Please note: For safety and ethical compliance, aggressive brute-forcing of passwords is not implemented. A framework for checking default configurations (e.g., anonymous access) is provided instead.", "info")
        else:
            self.log("Port 21 is closed or filtered. FTP service is not exposed.", "success")
            
        self.log("Authentication testing sequence terminated.", "info")
        
    def check_port(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            return s.connect_ex((self.target, port)) == 0
            
    def test_ftp_anonymous(self):
        self.log("Attempting FTP Anonymous Login check (admin/configuration audit)...", "warning")
        try:
            ftp = ftplib.FTP(timeout=5)
            ftp.connect(self.target, 21)
            ftp.login('anonymous', 'anonymous@example.com')
            
            self.log("VULNERABILITY DISCOVERED: Anonymous FTP login is ENABLED!", "danger")
            
            # List directory briefly
            files = []
            ftp.retrlines('LIST', files.append)
            
            if files:
                self.log(f"Anonymous access revealed {len(files)} file(s)/directory(s) in root:", "danger")
                for f in files[:5]: # show max 5 lines
                    self.log(f" -> {f}", "danger")
                if len(files) > 5:
                    self.log(" -> (...additional files truncated)", "danger")
            else:
                self.log("Anonymous access succeeded, but root directory appears empty.", "warning")
            
            ftp.quit()
        except ftplib.error_perm as e:
            self.log(f"Anonymous FTP login denied safely. ({e})", "success")
        except Exception as e:
            self.log(f"FTP connection error during login phase: {e}", "info")
