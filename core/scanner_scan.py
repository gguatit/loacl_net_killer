import ipaddress
import os
import re
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from core.scanner_mdns import scan_mdns_services
from core.scanner_platform import (
    IS_LINUX,
    IS_WINDOWS,
    estimate_os,
    get_windows_route_network_candidates,
    get_hostname_from_ip,
    get_local_info,
    get_mac_from_arp,
    get_vendor,
    ping_host_fast,
)

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# 0 or negative means unlimited scan range.
MAX_SCAN_HOSTS = int(os.getenv("MAX_SCAN_HOSTS", "0"))
PING_WORKERS = int(os.getenv("PING_WORKERS", "128"))
ARP_VERIFY_ALIVE = os.getenv("ARP_VERIFY_ALIVE", "false").lower() in ("1", "true", "yes", "on")
USE_SCAPY_ARP = os.getenv("USE_SCAPY_ARP", "true").lower() in ("1", "true", "yes", "on")
SCAN_NETWORK_CIDR = os.getenv("SCAN_NETWORK_CIDR", "").strip()


def _is_lan_candidate_network(net):
    try:
        addr = net.network_address
    except Exception:
        return False
    if not net.is_private:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return False
    first = int(str(addr).split('.')[0])
    return first in (10, 11, 172, 192)


def _sort_key_ip(value):
    try:
        return [int(p) for p in value.split('.')]
    except Exception:
        return [999, 999, 999, 999]


def _merge_devices(devices):
    merged = {}
    for device in devices:
        ip = device.get("ip")
        if not ip:
            continue
        prev = merged.get(ip)
        if not prev:
            merged[ip] = device
            continue

        # Prefer online status and richer metadata when merging.
        if prev.get("status") != "online" and device.get("status") == "online":
            merged[ip] = device
            prev = merged[ip]

        if not prev.get("mac") and device.get("mac"):
            prev["mac"] = device["mac"]
        if (not prev.get("hostname") or prev.get("hostname") == "Unknown") and device.get("hostname"):
            prev["hostname"] = device["hostname"]
        if (not prev.get("vendor") or prev.get("vendor") == "Unknown") and device.get("vendor"):
            prev["vendor"] = device["vendor"]
        if prev.get("ttl", 0) == 0 and device.get("ttl", 0) > 0:
            prev["ttl"] = device["ttl"]

    return sorted(merged.values(), key=lambda x: _sort_key_ip(x.get("ip", "")))


def _network_from_local_info(local_info):
    gateway = local_info.get('gateway', '')
    local_ip = local_info.get('local_ip', '')
    subnet_mask = local_info.get('subnet', '')

    try:
        if local_ip and gateway and subnet_mask and '.' in subnet_mask:
            # If local IP and gateway are in different subnets, prefer gateway side.
            local_net = ipaddress.ip_network(f"{local_ip}/{subnet_mask}", strict=False)
            if ipaddress.ip_address(gateway) not in local_net:
                return ipaddress.ip_network(f"{gateway}/{subnet_mask}", strict=False)

        if subnet_mask and local_ip and ('.' in subnet_mask or subnet_mask.startswith('/')):
            mask = subnet_mask if subnet_mask.startswith('/') else subnet_mask
            return ipaddress.ip_network(f"{local_ip}/{mask}", strict=False)
        if gateway:
            gateway_parts = gateway.split('.')
            if len(gateway_parts) == 4:
                return ipaddress.ip_network(
                    f"{gateway_parts[0]}.{gateway_parts[1]}.{gateway_parts[2]}.0/24",
                    strict=False
                )
        if local_ip:
            if local_ip.startswith('10.') or local_ip.startswith('11.'):
                return ipaddress.ip_network(f"{local_ip}/16", strict=False)
            return ipaddress.ip_network(f"{local_ip}/24", strict=False)
    except Exception:
        return None
    return None


def _arp_candidate_networks(max_candidates=3):
    """Extract likely /24 networks from ARP table entries."""
    counts = {}
    try:
        result = subprocess.run(
            ['arp', '-a'],
            capture_output=True,
            timeout=3,
            encoding='utf-8',
            errors='replace'
        )
        for line in (result.stdout or '').splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if not m:
                continue
            ip = m.group(1)
            try:
                ip_obj = ipaddress.ip_address(ip)
            except Exception:
                continue
            if not ip_obj.is_private:
                continue
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            key = str(net)
            counts[key] = counts.get(key, 0) + 1
    except Exception:
        pass

    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    out = []
    for cidr, _ in ranked[:max_candidates]:
        try:
            out.append(ipaddress.ip_network(cidr, strict=False))
        except Exception:
            continue
    return out


def _arp_seen_ips(max_items=2048):
    ips = []
    try:
        result = subprocess.run(
            ['arp', '-a'],
            capture_output=True,
            timeout=3,
            encoding='utf-8',
            errors='replace'
        )
        for line in (result.stdout or '').splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if not m:
                continue
            try:
                ip_obj = ipaddress.ip_address(m.group(1))
            except Exception:
                continue
            if not ip_obj.is_private:
                continue
            ips.append(ip_obj)
            if len(ips) >= max_items:
                break
    except Exception:
        pass
    return ips


def _rank_candidate_networks(candidates, local_info):
    unique = []
    seen = set()
    for net in candidates:
        key = str(net)
        if key in seen:
            continue
        if not _is_lan_candidate_network(net):
            continue
        seen.add(key)
        unique.append(net)

    local_ip_raw = (local_info or {}).get('local_ip', '')
    gateway_raw = (local_info or {}).get('gateway', '')

    try:
        local_ip = ipaddress.ip_address(local_ip_raw) if local_ip_raw else None
    except Exception:
        local_ip = None

    try:
        gateway = ipaddress.ip_address(gateway_raw) if gateway_raw else None
    except Exception:
        gateway = None

    arp_ips = _arp_seen_ips()
    ranked = []
    for net in unique:
        score = 0
        if local_ip and local_ip in net:
            score += 100
        if gateway and gateway in net:
            score += 60

        arp_hits = 0
        for ip_obj in arp_ips:
            if ip_obj in net:
                arp_hits += 1
        score += min(arp_hits, 20) * 5

        # In enterprise networks, 10.x/11.x often spans broader than /24.
        if local_ip_raw.startswith('10.') or local_ip_raw.startswith('11.'):
            if net.prefixlen <= 16 and (local_ip and local_ip in net):
                score += 35

        # Slightly prefer narrower ranges when scores tie.
        score += max(0, 32 - net.prefixlen)
        ranked.append((score, net))

    ranked.sort(key=lambda x: x[0], reverse=True)
    return [net for _, net in ranked]


def _auto_candidate_networks(local_info):
    candidates = []
    seen = set()

    if IS_WINDOWS:
        for cidr in get_windows_route_network_candidates(max_candidates=4):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except Exception:
                continue
            key = str(net)
            if key in seen:
                continue
            candidates.append(net)
            seen.add(key)

    base = _network_from_local_info(local_info)
    if base is not None:
        bk = str(base)
        if bk not in seen:
            candidates.append(base)
            seen.add(bk)

    local_ip = (local_info or {}).get('local_ip', '')
    # Backward-compatible fallback for enterprise 10.x/11.x where /24 misses hosts.
    if local_ip.startswith('10.') or local_ip.startswith('11.'):
        try:
            wide = ipaddress.ip_network(f"{local_ip}/16", strict=False)
            wk = str(wide)
            if wk not in seen:
                candidates.append(wide)
                seen.add(wk)
        except Exception:
            pass

    for net in _arp_candidate_networks(max_candidates=4):
        k = str(net)
        if k in seen:
            continue
        candidates.append(net)
        seen.add(k)

    return _rank_candidate_networks(candidates, local_info)


def resolve_auto_network(local_info=None):
    info = local_info or get_local_info()
    candidates = _auto_candidate_networks(info)
    if not candidates:
        return ""
    return str(candidates[0])


def get_auto_network_candidates(local_info=None):
    info = local_info or get_local_info()
    return [str(n) for n in _auto_candidate_networks(info)]


def scapy_arp_scan(network):
    """Active ARP broadcast scan similar to netcut-style discovery."""
    if not (SCAPY_AVAILABLE and USE_SCAPY_ARP):
        return []

    try:
        target = str(network)
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
        answered, _ = srp(packet, timeout=1, verbose=False)

        devices = []
        for _, recv in answered:
            ip = getattr(recv, "psrc", "")
            mac = getattr(recv, "hwsrc", "")
            if not ip or not mac:
                continue
            devices.append({
                "ip": ip,
                "mac": mac.upper(),
                "hostname": "Unknown",
                "os_estimate": "Unknown",
                "vendor": get_vendor(mac),
                "status": "online",
                "ttl": 0,
                "last_seen": datetime.now().isoformat()
            })
        return _merge_devices(devices)
    except Exception as e:
        print(f"[Scapy ARP] 실패: {e}")
        return []


def scan_ip(ip, resolve_hostname=False):
    is_alive, ttl = ping_host_fast(ip)
    if is_alive:
        mac = get_mac_from_arp(ip)
        hostname = get_hostname_from_ip(ip) if resolve_hostname else "Unknown"
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


def scan_network_by_ping(cancel_event=None):
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

    with ThreadPoolExecutor(max_workers=PING_WORKERS) as executor:
        futures = {executor.submit(scan_ip, ip, False): ip for ip in all_ips}
        for future in as_completed(futures):
            if cancel_event and cancel_event.is_set():
                executor.shutdown(wait=False, cancel_futures=True)
                break
            try:
                result = future.result()
                if result:
                    devices.append(result)
            except Exception:
                pass

    return sorted(devices, key=lambda x: [int(p) for p in x['ip'].split('.')])


def arp_scan(verify_alive=ARP_VERIFY_ALIVE, cancel_event=None):
    mdns_thread = threading.Thread(target=scan_mdns_services, daemon=True)
    mdns_thread.start()

    devices = []
    seen_ips = set()

    if IS_LINUX and os.path.exists('/proc/net/arp'):
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f:
                    if cancel_event and cancel_event.is_set():
                        return _merge_devices(devices) if devices else []
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3]
                        if ip == 'IP' or mac == "00:00:00:00:00:00" or ip in seen_ips:
                            continue
                        seen_ips.add(ip)
                        is_alive, ttl = (True, 0)
                        hostname = "Unknown"
                        if verify_alive:
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
        except Exception as e:
            print(f"[ARP Scan] /proc/net/arp 읽기 실패: {e}")

    try:
        result = subprocess.run(
            ['arp', '-a'],
            capture_output=True,
            timeout=3,
            encoding='utf-8',
            errors='replace'
        )
        if result.stdout:
            for line in result.stdout.split('\n'):
                if cancel_event and cancel_event.is_set():
                    return _merge_devices(devices) if devices else []
                line = line.strip()
                if not line or 'Interface' in line or '---' in line:
                    continue

                parts = line.split()
                if len(parts) < 2:
                    continue

                ip = parts[0]
                try:
                    ipaddress.ip_address(ip)
                except Exception:
                    continue

                mac = None
                for part in parts[1:]:
                    if (':' in part or '-' in part) and len(part.replace(':', '').replace('-', '')) >= 10:
                        mac = part.replace('-', ':').upper()
                        break

                if mac and ip not in seen_ips:
                    seen_ips.add(ip)
                    is_alive, ttl = (True, 0)
                    hostname = "Unknown"
                    if verify_alive:
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
    except Exception as e:
        print(f"[ARP Scan] arp -a 실패: {e}")

    if IS_WINDOWS:
        try:
            result = subprocess.run(
                ['netsh', 'interface', 'ip', 'show', 'neighbors'],
                capture_output=True,
                timeout=3,
                encoding='utf-8',
                errors='replace'
            )
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if cancel_event and cancel_event.is_set():
                        return _merge_devices(devices) if devices else []
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1] if ':' in parts[1] or '-' in parts[1] else None
                        if mac and ip not in seen_ips and all(c.isdigit() or c == '.' for c in ip):
                            seen_ips.add(ip)
                            mac = mac.replace('-', ':').upper()
                            is_alive, ttl = (True, 0)
                            hostname = "Unknown"
                            if verify_alive:
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
        except Exception as e:
            print(f"[ARP Scan] netsh 실패: {e}")

    if devices:
        return _merge_devices(devices)

    return scan_network_by_ping(cancel_event=cancel_event)


def scan_network(mode="fast", callback=None, cancel_event=None, network_cidr=None):
    local_info = get_local_info()

    mdns_thread = threading.Thread(target=scan_mdns_services, daemon=True)
    mdns_thread.start()

    devices = []
    selected_network = (network_cidr or SCAN_NETWORK_CIDR or "").strip()
    network = None
    candidate_networks = []
    if selected_network:
        try:
            network = ipaddress.ip_network(selected_network, strict=False)
            candidate_networks = [network]
        except Exception:
            print(f"[Scan] 잘못된 network override: {selected_network}")
            network = None

    if network is None:
        candidate_networks = _auto_candidate_networks(local_info)
        network = candidate_networks[0] if candidate_networks else None

    if network is None:
        return {
            "devices": [],
            "local_info": local_info,
            "scanned_at": datetime.now().isoformat(),
            "total_found": 0,
            "network": selected_network or ""
        }

    mode = (mode or "fast").lower()
    if mode not in ("fast", "deep"):
        mode = "fast"

    devices = []
    scanned_networks = []

    # Auto fallback: try next candidate networks only when first result is too sparse.
    if not selected_network and len(candidate_networks) > 1:
        networks_to_try = candidate_networks[:3]
    else:
        networks_to_try = candidate_networks[:1]

    for idx, net in enumerate(networks_to_try):
        scanned_networks.append(str(net))
        all_ips = [str(ip) for ip in net.hosts()]

        # Keep optional cap support via env var; default is unlimited.
        if MAX_SCAN_HOSTS > 0 and len(all_ips) > MAX_SCAN_HOSTS:
            print(f"[Scan] 스캔 범위가 큽니다({len(all_ips)} hosts). 상한 {MAX_SCAN_HOSTS}로 제한합니다.")
            all_ips = all_ips[:MAX_SCAN_HOSTS]

        total_hosts = len(all_ips)

        # 0) Fast discover: Active ARP broadcast first (if scapy available)
        scapy_devices = scapy_arp_scan(net) if mode == "fast" else []
        if callback:
            for d in scapy_devices:
                callback(d, 0, total_hosts)
                if cancel_event and cancel_event.is_set():
                    return {
                        "devices": _merge_devices(scapy_devices),
                        "local_info": local_info,
                        "scanned_at": datetime.now().isoformat(),
                        "total_found": len(scapy_devices),
                        "network": ", ".join(scanned_networks),
                        "cancelled": True
                    }

        # 1) ARP-first merge
        arp_devices = arp_scan(verify_alive=False, cancel_event=cancel_event)
        if callback:
            for d in arp_devices:
                callback(d, 0, total_hosts)
                if cancel_event and cancel_event.is_set():
                    merged = _merge_devices(scapy_devices + arp_devices + devices)
                    return {
                        "devices": merged,
                        "local_info": local_info,
                        "scanned_at": datetime.now().isoformat(),
                        "total_found": len(merged),
                        "network": ", ".join(scanned_networks),
                        "cancelled": True
                    }

        # 2) Ping sweep
        ping_devices = []
        processed = 0
        with ThreadPoolExecutor(max_workers=PING_WORKERS) as executor:
            futures = {executor.submit(scan_ip, ip, mode == "deep"): ip for ip in all_ips}
            for future in as_completed(futures):
                if cancel_event and cancel_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                processed += 1
                try:
                    result = future.result()
                    if result:
                        ping_devices.append(result)
                        if callback:
                            callback(result, processed, total_hosts)
                    elif callback:
                        callback(None, processed, total_hosts)
                except Exception:
                    if callback:
                        callback(None, processed, total_hosts)

        # 3) merge with previous candidates
        candidate_devices = _merge_devices(scapy_devices + ping_devices + arp_devices)
        devices = _merge_devices(devices + candidate_devices)

        # If first candidate already found meaningful devices, don't keep expanding.
        if selected_network:
            break
        if idx == 0 and len(devices) <= 1:
            continue
        break

    return {
        "devices": devices,
        "local_info": local_info,
        "scanned_at": datetime.now().isoformat(),
        "total_found": len(devices),
        "network": ", ".join(scanned_networks) if scanned_networks else str(network),
        "cancelled": bool(cancel_event and cancel_event.is_set())
    }
