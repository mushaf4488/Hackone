import subprocess
import time

class WifiScanner:
    def __init__(self, socketio_ref):
        self.socketio = socketio_ref
        self.running = False

    def log(self, msg):
        self.socketio.emit('wifi_scan_update', {'message': msg})

    def stop(self):
        self.running = False
        self.log("Stopping wireless scanner...")

    def run(self):
        self.log("Initializing wireless interfaces...")
        self.running = True
        try:
            # Short delay for realistic UX in UI
            time.sleep(1)
            
            while self.running:
                self.log("Querying connected Interface properties...")
                if hasattr(subprocess, 'CREATE_NO_WINDOW'):
                    creation_flags = subprocess.CREATE_NO_WINDOW
                else:
                    creation_flags = 0

                # 1. Fetch Currently Connected Interface
                res_interface = subprocess.run(
                    ['netsh', 'wlan', 'show', 'interfaces'], 
                    capture_output=True, 
                    text=True, 
                    creationflags=creation_flags
                )
                iface_info = self.parse_interfaces_output(res_interface.stdout)
                self.socketio.emit('wifi_scan_interface', iface_info)
                
                if not self.running: break

                self.log("Scanning for broadcasting 802.11 access points...")
                
                # 2. Fetch Visible Networks
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], 
                    capture_output=True, 
                    text=True, 
                    creationflags=creation_flags
                )
                
                output = result.stdout
                networks = self.parse_netsh_output(output)
                
                if not self.running:
                    break
                    
                if not networks:
                    self.log("No WiFi networks found. Assure your wireless adapter is enabled and responsive.")
                else:
                    self.log(f"Extracted {len(networks)} visible access point(s). Updating UI...")
                    self.socketio.emit('wifi_scan_clear', {})
                    for net in networks:
                        if not self.running:
                            break
                        self.socketio.emit('wifi_scan_result', net)
                        time.sleep(0.05)  # Make the UI loading look smooth for large scans
                        
                # Wait 5 seconds before next scan, broken into smaller chunks to allow quick cancellation
                for _ in range(50):
                    if not self.running:
                        break
                    time.sleep(0.1)
                
            self.log("Wireless sweep sequence terminated.")
            
        except FileNotFoundError:
            self.log("Error: 'netsh' command not found. This module supports Windows OS.")
            self.running = False
        except Exception as e:
            self.log(f"Critical error during WiFi scan: {e}")
            self.running = False

    def parse_netsh_output(self, output):
        networks = []
        current_ssid = None
        auth = None
        encrypt = None
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if line.startswith('SSID'):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    ssid = parts[1].strip()
                    current_ssid = ssid if ssid else "Hidden Network (BSSID Only)"
                    auth = 'Unknown'
                    encrypt = 'Unknown'
                    
            elif line.startswith('Authentication'):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    auth = parts[1].strip()
                    
            elif line.startswith('Encryption'):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    encrypt = parts[1].strip()
                    
            elif line.startswith('BSSID'):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    bssid = parts[1].strip()
                    # Append each BSSID as its own completely separate row
                    networks.append({
                        'ssid': current_ssid,
                        'bssid': bssid,
                        'auth': auth,
                        'encrypt': encrypt,
                        'signal': '0%',
                        'channel': '?'
                    })
                    
            elif line.startswith('Signal'):
                parts = line.split(':', 1)
                if len(parts) > 1 and len(networks) > 0:
                    networks[-1]['signal'] = parts[1].strip()
                    
            elif line.startswith('Channel'):
                parts = line.split(':', 1)
                if len(parts) > 1 and len(networks) > 0:
                    networks[-1]['channel'] = parts[1].strip()
                    
        return networks

    def parse_interfaces_output(self, output):
        data = {
            'state': 'Disconnected',
            'ssid': '-',
            'bssid': '-',
            'radio': '-',
            'auth': '-',
            'rx': '-',
            'tx': '-',
            'signal': '-',
            'channel': '-'
        }
        for line in output.split('\n'):
            line = line.strip()
            if not line: continue
            if line.startswith('State'):
                parts = line.split(':', 1)
                if len(parts)>1: data['state'] = parts[1].strip()
            elif line.startswith('SSID'):
                parts = line.split(':', 1)
                if len(parts)>1: data['ssid'] = parts[1].strip()
            elif line.startswith('AP BSSID') or line.startswith('BSSID'):
                parts = line.split(':', 1)
                if len(parts)>1: data['bssid'] = parts[1].strip()
            elif line.startswith('Radio type'):
                parts = line.split(':', 1)
                if len(parts)>1: data['radio'] = parts[1].strip()
            elif line.startswith('Authentication'):
                parts = line.split(':', 1)
                if len(parts)>1: data['auth'] = parts[1].strip()
            elif line.startswith('Receive rate'):
                parts = line.split(':', 1)
                if len(parts)>1: data['rx'] = parts[1].strip() + ' Mbps'
            elif line.startswith('Transmit rate'):
                parts = line.split(':', 1)
                if len(parts)>1: data['tx'] = parts[1].strip() + ' Mbps'
            elif line.startswith('Signal'):
                parts = line.split(':', 1)
                if len(parts)>1: data['signal'] = parts[1].strip()
            elif line.startswith('Channel'):
                parts = line.split(':', 1)
                if len(parts)>1: data['channel'] = parts[1].strip()
        return data
