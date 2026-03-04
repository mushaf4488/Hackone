from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import yaml
import threading
import json
import os
from core.scanner_engine import ScannerEngine
from core.controller import ScanController, ScanAbortedError
from core.network_scanner import NetworkScanner
from core.wifi_scanner import WifiScanner
from core.auth_scanner import AuthScanner
from utils.logger import logger

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
# Use threading mode for compatibility and to avoid Eventlet issues on Windows
socketio = SocketIO(app, async_mode='threading')

# Global variable to store scan results (in memory for demo)
scan_results = {}
current_scan_status = []
scan_controller = None
current_wifi_scanner = None

def load_config(config_path="config/config.yaml"):
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    global scan_controller
    target = request.form.get('target', '').strip()
    if not target:
        return jsonify({"error": "Target is required"}), 400
        
    # Autocorrect raw IPs or domains without schemes to http
    if not target.startswith('http://') and not target.startswith('https://'):
        target = 'http://' + target
    
    # Initialize a new controller map for this scan segment
    scan_controller = ScanController()
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan, args=(target, scan_controller))
    thread.start()
    
    return jsonify({"status": "Scan started", "target": target})

@app.route('/scan/<action>', methods=['POST'])
@app.route('/scan/<action>/<module_id>', methods=['POST'])
def control_scan(action, module_id=None):
    if not scan_controller:
        return jsonify({"error": "No scan running"}), 400
        
    if action == 'pause':
        scan_controller.pause(module_id)
        msg = f"Task '{module_id}' Paused by User." if module_id else "Global Scan Paused."
        socketio.emit('scan_update', {'message': msg, "state": "paused"})
        return jsonify({"status": "paused"})
    elif action == 'resume':
        scan_controller.resume(module_id)
        msg = f"Task '{module_id}' Resumed by User." if module_id else "Global Scan Resumed."
        socketio.emit('scan_update', {'message': msg, "state": "running"})
        return jsonify({"status": "resumed"})
    elif action == 'stop':
        scan_controller.stop(module_id)
        msg = f"Task '{module_id}' Stopped by User." if module_id else "Global Scan Stopped."
        socketio.emit('scan_update', {'message': msg, "state": "stopped"})
        return jsonify({"status": "stopped"})
        
    return jsonify({"error": "Invalid action"}), 400

@app.route('/network_scan', methods=['POST'])
def start_network_scan():
    target = request.form.get('target', '').strip()
    if not target:
        return jsonify({"error": "Target is required"}), 400
        
    def run_net_scan(t):
        ns = NetworkScanner(t, socketio)
        ns.run()
        
    thread = threading.Thread(target=run_net_scan, args=(target,))
    thread.start()
    return jsonify({"status": "Network Scan started", "target": target})

@app.route('/wifi_scan', methods=['POST'])
def start_wifi_scan():
    global current_wifi_scanner
    if current_wifi_scanner:
        current_wifi_scanner.stop()
        
    def run_wifi_scan():
        global current_wifi_scanner
        current_wifi_scanner = WifiScanner(socketio)
        current_wifi_scanner.run()
        
    thread = threading.Thread(target=run_wifi_scan)
    thread.start()
    return jsonify({"status": "WiFi Scan started"})

@app.route('/wifi_scan/stop', methods=['POST'])
def stop_wifi_scan():
    global current_wifi_scanner
    if current_wifi_scanner:
        current_wifi_scanner.stop()
    return jsonify({"status": "WiFi Scan stopped"})

@app.route('/auth_scan', methods=['POST'])
def start_auth_scan():
    target = request.form.get('target', '').strip()
    if not target:
        return jsonify({"error": "Target is required"}), 400
        
    def run_auth_scan(t):
        ns = AuthScanner(t, socketio)
        ns.run()
        
    thread = threading.Thread(target=run_auth_scan, args=(target,))
    thread.start()
    return jsonify({"status": "Auth Scan started", "target": target})

@app.route('/results')
def results():
    return render_template('results.html', results=scan_results)

def run_scan(target, controller):
    global scan_results
    config = load_config()
    
    def status_callback(msg, process_info=None, result_data=None):
        payload = {'message': msg}
        if process_info:
            payload['process_info'] = process_info
        if result_data:
            payload['result_data'] = result_data
        socketio.emit('scan_update', payload)
        
    engine = ScannerEngine(target, config, controller=controller)
    try:
        result = engine.start_scan(status_callback=status_callback)
        scan_results = result
        socketio.emit('scan_complete', {'result': result})
    except ScanAbortedError as e:
        status_callback(str(e))
        socketio.emit('scan_update', {'message': "WARNING: SCAN WAS ABORTED BEFORE COMPLETION."})

if __name__ == '__main__':
    socketio.run(app, debug=False, host='0.0.0.0', port=5000)
