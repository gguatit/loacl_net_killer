from flask import Flask, render_template, jsonify, Response
import urllib.parse
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

# If True, forward control calls to external API at `API_BASE`.
# Set to False to avoid making outbound connections and handle control locally (simulation).
USE_EXTERNAL_API = False

scan_results = []
scan_status = "idle"
last_scan = None
scan_progress = 0

# ARP 기반 속도 제어 상태 관리
arp_speed_control = {}  # {mac: {speed: kb/s, lag_out: ms, lag_in: ms, blocks: []}}
arp_devices = []  # ARP 스캔 결과
arp_last_scan = None

def load_network_data():
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        return {"ResponseStat": "ERROR", "error": str(e), "network_device": []}

def make_api_url(action, mac, value):
    # URL-encode mac and value to safely include characters like ':'
    mac_enc = urllib.parse.quote(mac, safe='')
    val_enc = urllib.parse.quote(str(value), safe='')
    return f"{API_BASE}/{urllib.parse.quote(action, safe='')}/{mac_enc}/{val_enc}"

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
    global arp_devices, arp_last_scan, arp_speed_control
    
    try:
        devices = arp_scan()
        arp_devices = devices
        arp_last_scan = datetime.now().isoformat()
        
        # ARP 스캔 결과에 속도 제어 상태 병합
        for device in devices:
            mac = device.get('mac', '')
            if mac not in arp_speed_control:
                arp_speed_control[mac] = {
                    "speed": -1,  # -1: unlimited
                    "lag_out": 0,
                    "lag_in": 0,
                    "blocks": []
                }
            device['control_state'] = arp_speed_control[mac]
        
        return jsonify(devices)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e), "devices": []}), 500

@app.route('/api/arp/speed/<mac>/<speed>')
def api_arp_speed(mac, speed):
    """ARP 기반 속도 제어"""
    global arp_speed_control
    
    try:
        speed_value = int(speed)
        
        if mac not in arp_speed_control:
            arp_speed_control[mac] = {
                "speed": -1,
                "lag_out": 0,
                "lag_in": 0,
                "blocks": []
            }
        
        arp_speed_control[mac]["speed"] = speed_value
        
        # 외부 API로도 전달 시도 (가능한 경우)
        if USE_EXTERNAL_API:
            url = make_api_url("speed", mac, speed)
            try:
                import urllib.request
                with urllib.request.urlopen(url, timeout=2) as resp:
                    resp.read()
            except:
                pass
        
        return jsonify({
            "success": True,
            "mac": mac,
            "speed": speed_value,
            "message": "속도 제한 적용됨" if speed_value > 0 else "인터넷 차단됨" if speed_value == 0 else "무제한"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/arp/lagswitch/<mac>/<direction>/<ms>')
def api_arp_lagswitch(mac, direction, ms):
    """ARP 기반 지연 스위치"""
    global arp_speed_control
    
    try:
        ms_value = int(ms)
        
        if mac not in arp_speed_control:
            arp_speed_control[mac] = {
                "speed": -1,
                "lag_out": 0,
                "lag_in": 0,
                "blocks": []
            }
        
        if direction == "out":
            arp_speed_control[mac]["lag_out"] = ms_value
            msg = f"출력 지연 {ms_value}ms 적용"
        elif direction == "in":
            arp_speed_control[mac]["lag_in"] = ms_value
            msg = f"입력 지연 {ms_value}ms 적용"
        else:
            return jsonify({"success": False, "error": "invalid direction"}), 400
        
        return jsonify({
            "success": True,
            "mac": mac,
            "direction": direction,
            "ms": ms_value,
            "message": msg
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/arp/block/<mac>/<block_type>/<state>')
def api_arp_block(mac, block_type, state):
    """ARP 기반 게임 차단"""
    global arp_speed_control
    
    try:
        if mac not in arp_speed_control:
            arp_speed_control[mac] = {
                "speed": -1,
                "lag_out": 0,
                "lag_in": 0,
                "blocks": []
            }
        
        blocks = arp_speed_control[mac]["blocks"]
        
        if state.lower() == "on":
            if block_type not in blocks:
                blocks.append(block_type)
            msg = f"{block_type} 차단 활성화"
        elif state.lower() == "off":
            if block_type in blocks:
                blocks.remove(block_type)
            msg = f"{block_type} 차단 해제"
        else:
            return jsonify({"success": False, "error": "invalid state"}), 400
        
        return jsonify({
            "success": True,
            "mac": mac,
            "block_type": block_type,
            "state": state,
            "blocks": blocks,
            "message": msg
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/arp/status/<mac>')
def api_arp_status(mac):
    """특정 MAC 주소의 제어 상태 조회"""
    global arp_speed_control
    
    if mac in arp_speed_control:
        return jsonify({
            "success": True,
            "mac": mac,
            "status": arp_speed_control[mac]
        })
    else:
        return jsonify({
            "success": False,
            "mac": mac,
            "message": "Device not found"
        }), 404

@app.route('/api/arp/reset/<mac>')
def api_arp_reset(mac):
    """특정 MAC 주소의 모든 제어 초기화"""
    global arp_speed_control
    
    try:
        arp_speed_control[mac] = {
            "speed": -1,
            "lag_out": 0,
            "lag_in": 0,
            "blocks": []
        }
        
        return jsonify({
            "success": True,
            "mac": mac,
            "message": "모든 제어 초기화됨"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/control/<action>/<mac>/<value>')
def api_control(action, mac, value):
    import urllib.request
    url = make_api_url(action, mac, value)
    # If external API usage is disabled, do not attempt outbound connection.
    if not USE_EXTERNAL_API:
        # Simulate control action locally: log and return success
        print(f"api_control: external API disabled, simulated {action} {mac} {value}")
        # Optionally, update in-memory scan_results to reflect change (best-effort)
        try:
            for d in scan_results:
                if d.get('mac') == mac or d.get('MAC') == mac:
                    d['last_control'] = {'action': action, 'value': value, 'timestamp': datetime.now().isoformat()}
        except Exception:
            pass
        return jsonify({"success": True, "url": None, "response": "simulated"})

    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            result = response.read().decode('utf-8')
            return jsonify({"success": True, "url": url, "response": result})
    except Exception as e:
        # Log full exception to server console for debugging
        print(f"api_control error calling {url}: {e}")
        return jsonify({"success": False, "url": url, "error": str(e)}), 500


@app.route('/favicon.ico')
def favicon():
    # avoid 404 for favicon requests
    return Response(status=204)

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
