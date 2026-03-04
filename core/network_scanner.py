import socket
import ipaddress
import concurrent.futures
import asyncio

# Extended Top 75 list for much higher sweep value
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 135, 137, 138, 139, 143, 161, 162, 
    389, 443, 445, 465, 514, 515, 587, 631, 873, 993, 995, 1080, 1433, 1521, 1723, 2049, 
    2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 3306, 3389, 3690, 4333, 4444, 4567, 
    4848, 5000, 5001, 5432, 5900, 5901, 5984, 6379, 6667, 7000, 7001, 7002, 8000, 8008, 
    8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017, 27018
]

class NetworkScanner:
    def __init__(self, target, socketio_ref):
        self.target = target
        self.socketio = socketio_ref

    def log(self, msg):
        self.socketio.emit('net_scan_update', {'message': msg})

    def run(self):
        try:
            network = ipaddress.ip_network(self.target, strict=False)
            targets = list(network.hosts())
            if not targets:
                targets = [network.network_address]
        except ValueError:
            try:
                # Fallback: Treat as a single domain name and resolve it
                ip = socket.gethostbyname(self.target)
                targets = [ipaddress.ip_address(ip)]
            except Exception as e:
                self.log(f"Error: Invalid Network target format '{self.target}'")
                return
                
        if len(targets) > 256:
            self.log("Target subnet too large. Limiting to first 256 hosts for safety.")
            targets = targets[:256]

        self.log(f"Starting TCP Connect sweep across {len(targets)} host(s)...")
        
        outer_workers = 10 if len(targets) > 1 else 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=outer_workers) as executor:
            future_to_ip = {executor.submit(self.scan_host, ip): ip for ip in targets}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    res = future.result()
                    if res:
                        self.socketio.emit('net_scan_result', res)
                        self.log(f"Discovered active host: {res['ip']} (Ports: {', '.join(map(str, res['ports']))})")
                except Exception as e:
                    self.log(f"Error scanning {ip}: {e}")

        self.log("Network scan completed successfully.")

    async def _scan_port_async(self, ip, port, sem):
        async with sem:
            try:
                fut = asyncio.open_connection(str(ip), port)
                # Balanced timeout (0.5s) to prevent false negatives from slow TCP handshakes
                reader, writer = await asyncio.wait_for(fut, timeout=0.5)
                writer.close()
                await writer.wait_closed()
                return port
            except Exception:
                return None

    async def _scan_host_async(self, ip):
        sem = asyncio.Semaphore(1000)  # Safe high concurrency limit for Windows (~1000)
        tasks = [self._scan_port_async(ip, p, sem) for p in range(1, 50001)]
        open_ports = []
        
        # Use as_completed to avoid memory/CPU spikes holding all results
        for f in asyncio.as_completed(tasks):
            res = await f
            if res is not None:
                open_ports.append(res)
                
        return open_ports

    def scan_host(self, ip):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            open_ports = loop.run_until_complete(self._scan_host_async(ip))
            loop.close()

            if open_ports:
                return {"ip": str(ip), "status": "Up / Responsive", "ports": sorted(open_ports)}
        except Exception:
            pass
        return None
