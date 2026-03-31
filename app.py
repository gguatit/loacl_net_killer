from flask import Flask, render_template, jsonify
import json
import os
import threading
from datetime import datetime

from scanner import (
    get_local_info, 
    arp_scan, 
    scan_network
)

app = Flask(__name__)

API_BASE = "http://127.0.0.1:4622"
DATA_FILE = os.path.join(os.path.dirname(__file__), "새 텍스트 문서.txt")

scan_results = []
scan_status = "idle"
last_scan = None
scan_progress = 0

def load_network_data():
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        return {"ResponseStat": "ERROR", "error": str(e), "network_device": []}

def make_api_url(action, mac, value):
    return f"{API_BASE}/{action}/{mac}/{value}"

def scan_worker():
    global scan_results, scan_status, scan_progress, last_scan
    
    scan_status = "scanning"
    scan_progress = 0
    scan_results = []
    
    def on_device_found(device):
        global scan_results, scan_progress
        scan_results.append(device)
        scan_progress = len(scan_results)
    
    try:
        result = scan_network(callback=on_device_found)
        scan_results = result.get("devices", scan_results)
    except Exception as e:
        print(f"Scan error: {e}")
    
    last_scan = datetime.now().isoformat()
    scan_status = "completed"
    scan_progress = 100

@app.route('/')
def index():
    data = load_network_data()
    return render_template('index.html', data=data, api_base=API_BASE)

@app.route('/api/devices')
def api_devices():
    return jsonify(load_network_data())

@app.route('/api/local-info')
def api_local_info():
    return jsonify(get_local_info())

@app.route('/api/scan/start')
def api_scan_start():
    global scan_status
    
    if scan_status == "scanning":
        return jsonify({"status": "scanning", "devices": scan_results, "progress": scan_progress})
    
    thread = threading.Thread(target=scan_worker)
    thread.daemon = True
    thread.start()
    
    return jsonify({"status": "started", "message": "Network scan started"})

@app.route('/api/scan/status')
def api_scan_status():
    global scan_results, scan_status, last_scan, scan_progress
    local_info = get_local_info()
    
    return jsonify({
        "status": scan_status,
        "devices": scan_results,
        "local_info": local_info,
        "last_scan": last_scan,
        "progress": scan_progress
    })

@app.route('/api/scan/arp')
def api_scan_arp():
    return jsonify(arp_scan())

@app.route('/api/control/<action>/<mac>/<value>')
def api_control(action, mac, value):
    import urllib.request
    url = make_api_url(action, mac, value)
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            result = response.read().decode('utf-8')
            return jsonify({"success": True, "url": url, "response": result})
    except Exception as e:
        return jsonify({"success": False, "url": url, "error": str(e)}), 500

if __name__ == '__main__':
    print("=" * 60)
    print("       Network Device Controller Dashboard")
    print("=" * 60)
    
    local = get_local_info()
    print(f"  Hostname   : {local['hostname']}")
    print(f"  Local IP  : {local['local_ip']}")
    print(f"  Gateway    : {local['gateway'] or 'Auto-detecting...'}")
    print(f"  MAC        : {local['mac_address'] or 'Auto-detecting...'}")
    print(f"  OS         : {local['os']}")
    print("=" * 60)
    print("  Server     : http://localhost:5000")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
