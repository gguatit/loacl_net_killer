scan_results = []
scan_status = "idle"
last_scan = None
scan_progress = 0

arp_speed_control = {}
arp_devices = []
arp_last_scan = None


def ensure_arp_state(mac):
    if mac not in arp_speed_control:
        arp_speed_control[mac] = {
            "speed": -1,
            "lag_out": 0,
            "lag_in": 0,
            "blocks": [],
            "service_blocks": {}
        }
    elif "service_blocks" not in arp_speed_control[mac]:
        arp_speed_control[mac]["service_blocks"] = {}
    return arp_speed_control[mac]


def reset_arp_state(mac):
    arp_speed_control[mac] = {
        "speed": -1,
        "lag_out": 0,
        "lag_in": 0,
        "blocks": [],
        "service_blocks": {}
    }
    return arp_speed_control[mac]
