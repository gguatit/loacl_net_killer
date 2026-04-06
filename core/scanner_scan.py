import ipaddress
import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from core.scanner_mdns import scan_mdns_services
from core.scanner_platform import (
    IS_LINUX,
    IS_WINDOWS,
    estimate_os,
    get_hostname_from_ip,
    get_local_info,
    get_mac_from_arp,
    get_vendor,
    ping_host_fast,
)


def scan_ip(ip):
    is_alive, ttl = ping_host_fast(ip)
    if is_alive:
        mac = get_mac_from_arp(ip)
        hostname = get_hostname_from_ip(ip)
        return {
            "ip": ip,
            "mac": mac,
            "hostname": hostname or "Unknown",
            "os_estimate": estimate_os(ttl),
            "vendor": get_vendor(mac) if mac else "Unknown",
            "status": "online",
            "ttl": ttl,
            "last_seen": datetime.now().isoformat()
        }
    return None


def scan_network_by_ping():
    local_info = get_local_info()
    local_ip = local_info.get('local_ip', '')

    network = None
    try:
        if local_ip:
            ip_parts = local_ip.split('.')
            if len(ip_parts) == 4:
                network_addr = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                network = ipaddress.ip_network(network_addr, strict=False)
    except Exception:
        pass

    if not network:
        print("[Ping Scan] 네트워크 범위를 감지할 수 없습니다")
        return []

    devices = []
    all_ips = [str(ip) for ip in network.hosts()]

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in all_ips}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    devices.append(result)
            except Exception:
                pass

    return sorted(devices, key=lambda x: [int(p) for p in x['ip'].split('.')])


def arp_scan():
    mdns_thread = threading.Thread(target=scan_mdns_services, daemon=True)
    mdns_thread.start()

    devices = []
    seen_ips = set()

    if IS_LINUX and os.path.exists('/proc/net/arp'):
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3]
                        if ip == 'IP' or mac == "00:00:00:00:00:00" or ip in seen_ips:
                            continue
                        seen_ips.add(ip)
                        is_alive, ttl = ping_host_fast(ip)
                        hostname = get_hostname_from_ip(ip)
                        devices.append({
                            "ip": ip,
                            "mac": mac.upper(),
                            "hostname": hostname or "Unknown",
                            "os_estimate": estimate_os(ttl) if is_alive else "Unknown",
                            "vendor": get_vendor(mac),
                            "status": "online" if is_alive else "offline",
                            "ttl": ttl if is_alive else 0,
                            "last_seen": datetime.now().isoformat()
                        })
            if devices:
                return sorted(devices, key=lambda x: [int(p) for p in x['ip'].split('.')])
        except Exception as e:
            print(f"[ARP Scan] /proc/net/arp 읽기 실패: {e}")

    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, timeout=3, text=True)
        if result.stdout:
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line or 'Interface' in line or '---' in line:
                    continue

                parts = line.split()
                if len(parts) < 2:
                    continue

                ip = parts[0]
                if not all(c.isdigit() or c == '.' for c in ip.split('.')[0] if ip.split('.')[0]):
                    continue

                mac = None
                for part in parts[1:]:
                    if (':' in part or '-' in part) and len(part.replace(':', '').replace('-', '')) >= 10:
                        mac = part.replace('-', ':').upper()
                        break

                if mac and ip not in seen_ips:
                    seen_ips.add(ip)
                    is_alive, ttl = ping_host_fast(ip)
                    hostname = get_hostname_from_ip(ip)
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname or "Unknown",
                        "os_estimate": estimate_os(ttl) if is_alive else "Unknown",
                        "vendor": get_vendor(mac),
                        "status": "online" if is_alive else "offline",
                        "ttl": ttl if is_alive else 0,
                        "last_seen": datetime.now().isoformat()
                    })
            if devices:
                return sorted(devices, key=lambda x: [int(p) for p in x['ip'].split('.')])
    except Exception as e:
        print(f"[ARP Scan] arp -a 실패: {e}")

    if IS_WINDOWS:
        try:
            result = subprocess.run(
                ['netsh', 'interface', 'ip', 'show', 'neighbors'],
                capture_output=True,
                timeout=3,
                text=True
            )
            if result.stdout:
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1] if ':' in parts[1] or '-' in parts[1] else None
                        if mac and ip not in seen_ips and all(c.isdigit() or c == '.' for c in ip):
                            seen_ips.add(ip)
                            mac = mac.replace('-', ':').upper()
                            is_alive, ttl = ping_host_fast(ip)
                            hostname = get_hostname_from_ip(ip)
                            devices.append({
                                "ip": ip,
                                "mac": mac,
                                "hostname": hostname or "Unknown",
                                "os_estimate": estimate_os(ttl) if is_alive else "Unknown",
                                "vendor": get_vendor(mac),
                                "status": "online" if is_alive else "offline",
                                "ttl": ttl if is_alive else 0,
                                "last_seen": datetime.now().isoformat()
                            })
                if devices:
                    return sorted(devices, key=lambda x: [int(p) for p in x['ip'].split('.')])
        except Exception as e:
            print(f"[ARP Scan] netsh 실패: {e}")

    return scan_network_by_ping()


def scan_network(callback=None):
    local_info = get_local_info()
    gateway = local_info.get('gateway', '')
    local_ip = local_info.get('local_ip', '')
    subnet_mask = local_info.get('subnet', '')

    mdns_thread = threading.Thread(target=scan_mdns_services, daemon=True)
    mdns_thread.start()

    devices = []
    network = None
    try:
        if subnet_mask and ('.' in subnet_mask or subnet_mask.startswith('/')):
            mask = subnet_mask if subnet_mask.startswith('/') else subnet_mask
            network = ipaddress.ip_network(f"{local_ip}/{mask}", strict=False)
        elif gateway:
            gateway_parts = gateway.split('.')
            if len(gateway_parts) == 4:
                network = ipaddress.ip_network(
                    f"{gateway_parts[0]}.{gateway_parts[1]}.{gateway_parts[2]}.0/24",
                    strict=False
                )
        elif local_ip:
            if local_ip.startswith('10.') or local_ip.startswith('11.'):
                network = ipaddress.ip_network(f"{local_ip}/16", strict=False)
            else:
                network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    except Exception:
        network = None

    if network is None:
        return {
            "devices": [],
            "local_info": local_info,
            "scanned_at": datetime.now().isoformat(),
            "total_found": 0
        }

    all_ips = [str(ip) for ip in network.hosts()]
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in all_ips}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    devices.append(result)
                    if callback:
                        callback(result)
            except Exception:
                pass

    return {
        "devices": devices,
        "local_info": local_info,
        "scanned_at": datetime.now().isoformat(),
        "total_found": len(devices)
    }
