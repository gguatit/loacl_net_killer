from flask import Flask, render_template, jsonify, Response, request
import threading
from datetime import datetime

from core.config import API_BASE, USE_EXTERNAL_API
from core.storage import load_network_data
from core.service_blocks import SERVICE_BLOCK_CATALOG
from core.control_api import make_api_url, is_external_api_available, call_external_api
import core.state as state

from scanner import (
    get_local_info, 
    arp_scan, 
    scan_network
)

app = Flask(__name__)

def scan_worker(mode="fast"):
    state.scan_mode = mode
    state.scan_status = "scanning"
    state.scan_cancel_requested = False
    state.scan_cancel_event.clear()
    state.scan_progress = 0
    state.scan_processed_hosts = 0
    state.scan_total_hosts = 0
    state.scan_results = []
    
    def on_scan_update(device=None, processed=0, total=0):
        if device:
            state.scan_results.append(device)
        state.scan_processed_hosts = processed or state.scan_processed_hosts
        state.scan_total_hosts = total or state.scan_total_hosts
        if state.scan_total_hosts > 0:
            pct = int((state.scan_processed_hosts / state.scan_total_hosts) * 100)
            state.scan_progress = max(0, min(99 if state.scan_status == "scanning" else 100, pct))
    
    try:
        result = scan_network(mode=mode, callback=on_scan_update, cancel_event=state.scan_cancel_event)
        state.scan_results = result.get("devices", state.scan_results)
        # ARP+Ping 병합 결과가 ping 대상 수보다 커질 수 있으므로 상태 지표를 보정한다.
        state.scan_total_hosts = max(state.scan_total_hosts, len(state.scan_results))
        if result.get("cancelled"):
            state.scan_status = "cancelled"
            state.last_scan = datetime.now().isoformat()
            return
    except Exception as e:
        print(f"Scan error: {e}")
    
    state.last_scan = datetime.now().isoformat()
    state.scan_status = "completed"
    state.scan_processed_hosts = state.scan_total_hosts or state.scan_processed_hosts
    state.scan_progress = 100

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
    mode = (request.args.get("mode", "fast") or "fast").lower()
    if mode not in ("fast", "deep"):
        mode = "fast"

    if state.scan_status == "scanning":
        return jsonify({
            "status": "scanning",
            "devices": state.scan_results,
            "progress": state.scan_progress,
            "mode": state.scan_mode,
            "cancel_requested": state.scan_cancel_requested
        })
    
    thread = threading.Thread(target=scan_worker, args=(mode,))
    thread.daemon = True
    thread.start()
    
    return jsonify({"status": "started", "message": "Network scan started", "mode": mode})


@app.route('/api/scan/cancel')
def api_scan_cancel():
    if state.scan_status != "scanning":
        return jsonify({
            "success": False,
            "status": state.scan_status,
            "message": "현재 진행 중인 스캔이 없습니다"
        }), 409

    state.scan_cancel_requested = True
    state.scan_status = "canceling"
    state.scan_cancel_event.set()
    return jsonify({"success": True, "status": "canceling", "message": "스캔 취소 요청됨"})

@app.route('/api/scan/status')
def api_scan_status():
    local_info = get_local_info()
    
    return jsonify({
        "status": state.scan_status,
        "devices": state.scan_results,
        "local_info": local_info,
        "last_scan": state.last_scan,
        "progress": state.scan_progress,
        "mode": state.scan_mode,
        "processed_hosts": state.scan_processed_hosts,
        "total_hosts": state.scan_total_hosts,
        "found_hosts": len(state.scan_results),
        "cancel_requested": state.scan_cancel_requested
    })

@app.route('/api/scan/arp')
def api_scan_arp():
    try:
        devices = arp_scan()
        state.arp_devices = devices
        state.arp_last_scan = datetime.now().isoformat()
        
        # ARP 스캔 결과에 속도 제어 상태 병합
        for device in devices:
            mac = device.get('mac', '')
            device['control_state'] = state.ensure_arp_state(mac)
        
        return jsonify(devices)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e), "devices": []}), 500

@app.route('/api/arp/speed/<mac>/<speed>')
def api_arp_speed(mac, speed):
    """ARP 기반 속도 제어"""
    try:
        speed_value = int(speed)
        
        state.ensure_arp_state(mac)
        
        state.arp_speed_control[mac]["speed"] = speed_value
        
        forward_error = None
        # 외부 API로도 전달 시도 (가능한 경우)
        if USE_EXTERNAL_API:
            try:
                call_external_api("speed", mac, speed, timeout=2)
            except Exception as e:
                forward_error = str(e)
        
        response = {
            "success": True,
            "mac": mac,
            "speed": speed_value,
            "message": "속도 제한 적용됨" if speed_value > 0 else "인터넷 차단됨" if speed_value == 0 else "무제한"
        }
        if forward_error:
            response["forward_warning"] = f"외부 API 전달 실패: {forward_error}"
        return jsonify(response)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/arp/lagswitch/<mac>/<direction>/<ms>')
def api_arp_lagswitch(mac, direction, ms):
    """ARP 기반 지연 스위치"""
    try:
        ms_value = int(ms)
        
        state.ensure_arp_state(mac)
        
        if direction == "out":
            state.arp_speed_control[mac]["lag_out"] = ms_value
            msg = f"출력 지연 {ms_value}ms 적용"
        elif direction == "in":
            state.arp_speed_control[mac]["lag_in"] = ms_value
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

@app.route('/api/arp/block/<mac>/<block_type>/<state_value>')
def api_arp_block(mac, block_type, state_value):
    """ARP 기반 게임 차단"""
    try:
        state.ensure_arp_state(mac)
        
        blocks = state.arp_speed_control[mac]["blocks"]
        
        if state_value.lower() == "on":
            if block_type not in blocks:
                blocks.append(block_type)
            msg = f"{block_type} 차단 활성화"
        elif state_value.lower() == "off":
            if block_type in blocks:
                blocks.remove(block_type)
            msg = f"{block_type} 차단 해제"
        else:
            return jsonify({"success": False, "error": "invalid state"}), 400
        
        return jsonify({
            "success": True,
            "mac": mac,
            "block_type": block_type,
            "state": state_value,
            "blocks": blocks,
            "message": msg
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/arp/service/<mac>/<service>/<state_value>')
def api_arp_service_block(mac, service, state_value):
    """서비스 단위 차단 (youtube/naver/padlet 등)"""
    try:
        state_val = state_value.lower()
        if state_val not in ("on", "off"):
            return jsonify({"success": False, "error": "invalid state"}), 400

        service_key = service.lower().strip()
        device_state = state.ensure_arp_state(mac)
        service_blocks = device_state["service_blocks"]

        # 등록된 서비스가 아니면 커스텀 도메인 1개로 처리
        domains = SERVICE_BLOCK_CATALOG.get(service_key, [service_key])

        service_blocks[service_key] = {
            "enabled": state_val == "on",
            "domains": domains,
            "updated_at": datetime.now().isoformat()
        }

        forward_warning = None
        if USE_EXTERNAL_API:
            # value payload format: service:state:domain1,domain2
            payload = f"{service_key}:{state_val}:{','.join(domains)}"
            try:
                call_external_api("serviceblock", mac, payload, timeout=3)
            except Exception as e:
                forward_warning = str(e)

        response = {
            "success": True,
            "mac": mac,
            "service": service_key,
            "state": state_val,
            "domains": domains,
            "message": f"{service_key} 차단 {'활성화' if state_val == 'on' else '해제'}"
        }
        if forward_warning:
            response["forward_warning"] = f"외부 API 전달 실패: {forward_warning}"
        return jsonify(response)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/arp/services')
def api_service_catalog():
    return jsonify({"success": True, "services": SERVICE_BLOCK_CATALOG})

@app.route('/api/arp/status/<mac>')
def api_arp_status(mac):
    """특정 MAC 주소의 제어 상태 조회"""
    if mac in state.arp_speed_control:
        return jsonify({
            "success": True,
            "mac": mac,
            "status": state.arp_speed_control[mac]
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
    try:
        state.reset_arp_state(mac)
        
        return jsonify({
            "success": True,
            "mac": mac,
            "message": "모든 제어 초기화됨"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/control/<action>/<mac>/<value>')
def api_control(action, mac, value):
    url = make_api_url(action, mac, value)
    # If external API usage is disabled, do not attempt outbound connection.
    if not USE_EXTERNAL_API:
        return jsonify({
            "success": False,
            "url": None,
            "error": "USE_EXTERNAL_API=false 상태입니다. 실제 차단은 수행되지 않았습니다."
        }), 503

    if not is_external_api_available():
        return jsonify({
            "success": False,
            "url": None,
            "error": f"외부 제어 API({API_BASE})에 연결할 수 없습니다."
        }), 503

    try:
        _, result = call_external_api(action, mac, value, timeout=5)
        return jsonify({"success": True, "url": url, "response": result})
    except Exception as e:
        # Log full exception to server console for debugging
        print(f"api_control error calling {url}: {e}")
        return jsonify({"success": False, "url": url, "error": str(e)}), 500

@app.route('/api/control/config')
def api_control_config():
    return jsonify({
        "use_external_api": USE_EXTERNAL_API,
        "api_base": API_BASE,
        "api_available": is_external_api_available() if USE_EXTERNAL_API else False
    })


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
