import socket
import ipaddress
import subprocess
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

OUI_VENDORS = {
    "000566": "ZTE",
    "10FFE0": "Tenda",
    "001122": "Cisco",
    "000C29": "VMware",
    "D4AE52": "D-Link",
    "B4B52F": "Huawei",
    "C86000": "Netgear",
    "AC22": "Tenda",
    "D8CBC": "ZTE",
    "F48E": "ZTE",
    "E894": "ZTE",
    "001A11": "Unitymedia",
    "E8DE27": "TP-Link",
    "C8:3A": "Tenda",
    "D47AE5": "ZTE",
    "A4C": "Huawei",
    "14EB": "TP-Link",
    "0023CD": "Wemo",
    "C0C0": "Cisco",
}

def get_local_info():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    # If hostname resolves to loopback, try a UDP socket to detect the real local IP
    try:
        if local_ip.startswith('127.'):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
    except:
        pass
    
    mac_address = ""
    gateway = ""
    subnet = ""
    dns_servers = []
    
    encodings = ['utf-8', 'cp949', 'euc-kr', 'latin-1']
    ipconfig_output = ""
    
    for encoding in encodings:
        try:
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, encoding=encoding, errors='replace')
            ipconfig_output = result.stdout
            if ipconfig_output and len(ipconfig_output) > 100:
                break
        except:
            continue
    
    lines = ipconfig_output.split('\n')
    
    for i, line in enumerate(lines):
        line_upper = line.upper()
        line_lower = line.lower()
        
        if 'ETHERNET' in line_upper or 'WIFI' in line_upper or 'ADAPTER' in line_upper:
            continue
            
        if 'PHY' in line_upper or '물리' in line_lower:
            parts = line.split(':')
            if len(parts) > 1:
                mac = parts[-1].strip()
                if mac and len(mac) >= 12:
                    mac_address = mac
                    
        if 'GATEWAY' in line_upper or '게이트웨이' in line_lower:
            parts = line.split(':')
            if len(parts) > 1:
                gw = parts[-1].strip()
                if gw and '.' in gw and not gw.startswith('fe80'):
                    gateway = gw
                    continue
            if i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                if '.' in next_line and not next_line.startswith('fe80'):
                    gateway = next_line
                    
        if 'SUBNET' in line_upper or '서브넷' in line_lower:
            parts = line.split(':')
            if len(parts) > 1:
                subnet = parts[-1].strip()
                
        if 'DNS' in line_upper and 'SERVER' in line_upper or 'DNS' in line_lower:
            parts = line.split(':')
            if len(parts) > 1:
                dns = parts[-1].strip()
                if dns and '.' in dns and dns not in dns_servers:
                    dns_servers.append(dns)
    
    if not gateway:
        gateway = get_default_gateway()
    
    if not mac_address:
        mac_address = get_mac_address()
    
    return {
        "hostname": hostname,
        "local_ip": local_ip,
        "mac_address": mac_address,
        "gateway": gateway,
        "subnet": subnet or "255.255.255.0",
        "dns_servers": dns_servers,
        "os": platform.system(),
        "platform": platform.platform(),
        "timestamp": datetime.now().isoformat()
    }

def get_default_gateway():
    try:
        result = subprocess.run(['route', 'print', '0.0.0.0'], capture_output=True, encoding='utf-8', errors='replace')
        for line in result.stdout.split('\n'):
            if '0.0.0.0' in line and '0.0.0.0' in line.split():
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
    except:
        pass
    
    try:
        result = subprocess.run(['netstat', '-r'], capture_output=True, encoding='utf-8', errors='replace')
        for line in result.stdout.split('\n'):
            if '0.0.0.0' in line or 'Default' in line:
                parts = line.split()
                for part in parts:
                    if part.count('.') == 3:
                        return part
    except:
        pass
    
    return ""

def get_mac_address():
    for interface in ['wifi', 'ethernet', 'local area connection', '이더넷']:
        try:
            result = subprocess.run(['getmac', '/v', '/fo', 'list'], capture_output=True, encoding='utf-8', errors='replace')
            for line in result.stdout.split('\n'):
                if interface.lower() in line.lower():
                    continue
                parts = line.split()
                for p in parts:
                    if '-' in p and len(p) == 17:
                        return p.upper()
        except:
            pass
    
    try:
        result = subprocess.run(['ipconfig', '/all'], capture_output=True, encoding='utf-8', errors='replace')
        lines = result.stdout.split('\n')
        for line in lines:
            if 'Physical Address' in line or '물리적 주소' in line:
                mac = line.split(':')[-1].strip()
                if mac and len(mac) >= 12:
                    return mac.upper()
    except:
        pass
        
    return ""

def ping_host_fast(ip):
    try:
        system = platform.system().lower()
        ttl = 0
        if system == 'windows':
            # -n 1 : one echo, -w 1000 : timeout in ms
            cmd = ['ping', '-n', '1', '-w', '1000', ip]
            timeout_sec = 4
        else:
            # unix-like: -c 1 one echo, -W 1 timeout in seconds (some systems use -W)
            # Use -c and -W where available; fallback to -c only
            cmd = ['ping', '-c', '1', '-W', '1', ip]
            timeout_sec = 4

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout_sec,
            encoding='utf-8',
            errors='replace'
        )

        out = result.stdout or ''
        out_lower = out.lower()
        # Determine success by returncode or presence of reply text
        success = (result.returncode == 0) or ('reply from' in out_lower) or ('bytes from' in out_lower)
        if success:
            # try to extract TTL value
            ttl = 0
            for line in out.split('\n'):
                l = line.upper()
                if 'TTL=' in l:
                    try:
                        ttl_str = l.split('TTL=')[-1].split()[0]
                        ttl = int(''.join(ch for ch in ttl_str if ch.isdigit()))
                        break
                    except:
                        continue
                # linux output example: "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.123 ms"
                if ' ttl=' in line.lower():
                    try:
                        parts = line.lower().split(' ttl=')[-1]
                        ttl = int(parts.split()[0])
                        break
                    except:
                        continue
            if ttl == 0:
                ttl = 64
            return True, ttl
        return False, 0
    except Exception:
        return False, 0

def get_hostname_from_ip(ip):
    try:
        result = subprocess.run(
            ['nbtstat', '-a', ip],
            capture_output=True,
            timeout=1,
            encoding='utf-8',
            errors='replace'
        )
        for line in result.stdout.split('\n'):
            if '<00>' in line and 'UNIQUE' in line:
                hostname = line.split()[0].strip()
                if hostname and len(hostname) > 1:
                    return hostname
    except:
        pass
    
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return ""

def estimate_os(ttl):
    if ttl <= 0:
        return "Unknown"
    elif ttl <= 64:
        return "Linux/Mac/Android"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Network Device"
    return "Unknown"

def get_vendor(mac):
    if not mac:
        return "Unknown"
    
    mac_clean = mac.replace('-', '').replace(':', '').replace('.', '').upper()
    if len(mac_clean) < 6:
        return "Unknown"
    
    prefix = mac_clean[:6]
    
    for oui_prefix, vendor in OUI_VENDORS.items():
        oui_clean = oui_prefix.replace('-', '').replace(':', '')
        if prefix.upper().startswith(oui_clean):
            return vendor
    
    return "Unknown"

def get_mac_from_arp(ip):
    try:
        result = subprocess.run(
            ['arp', '-a', ip],
            capture_output=True,
            timeout=0.5,
            encoding='utf-8',
            errors='replace'
        )
        for line in result.stdout.split('\n'):
            # Accept MAC in formats with '-' or ':' or '.'
            if ('-' in line) or (':' in line) or ('.' in line):
                parts = line.split()
                if len(parts) >= 2 and parts[0] == ip:
                    mac = parts[1].replace('-', ':').replace('.', '').upper()
                    # normalize dotted mac like aabb.ccdd.eeff -> AABBCCDDEEFF then insert ':'
                    if len(mac) == 12:
                        mac = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
                    if mac != "FF:FF:FF:FF:FF:FF" and mac != "00:00:00:00:00:00":
                        return mac
    except:
        pass
    return ""

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

def arp_scan():
    devices = []
    seen_ips = set()
    arp_output = ""
    
    encodings = ['utf-8', 'cp949', 'euc-kr', 'latin-1']
    
    for encoding in encodings:
        try:
            result = subprocess.run(
                ['arp', '-a'],
                capture_output=True,
                encoding=encoding,
                errors='replace'
            )
            arp_output = result.stdout
            if arp_output and len(arp_output) > 100:
                break
        except:
            continue
    
    if not arp_output:
        return []
    
    ips_to_check = []
    
    for line in arp_output.split('\n'):
        line = line.strip()
        if not line:
            continue
        
        if 'interface' in line.lower() or '---' in line:
            continue
        # Accept lines with MAC in '-', ':' or '.' formats
        if ('-' in line) or (':' in line) or ('.' in line):
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                raw_mac = parts[1]
                mac = raw_mac.replace('-', ':').replace('.', '').upper()
                if len(mac) == 12:
                    mac = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])

                if ip in seen_ips:
                    continue
                seen_ips.add(ip)

                if mac == "FF:FF:FF:FF:FF:FF" or mac == "00:00:00:00:00:00":
                    continue

                ips_to_check.append((ip, mac))
    
    def process_arp_device(args):
        ip, mac = args
        is_alive, ttl = ping_host_fast(ip)
        hostname = get_hostname_from_ip(ip)
        
        return {
            "ip": ip,
            "mac": mac,
            "hostname": hostname or "Unknown",
            "os_estimate": estimate_os(ttl) if is_alive else "Unknown",
            "vendor": get_vendor(mac),
            "status": "online" if is_alive else "offline",
            "ttl": ttl if is_alive else 0,
            "last_seen": datetime.now().isoformat()
        }
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(process_arp_device, args) for args in ips_to_check]
        for future in as_completed(futures):
            try:
                device = future.result()
                if device:
                    devices.append(device)
            except:
                pass
    
    return sorted(devices, key=lambda x: [int(p) for p in x['ip'].split('.')])

def scan_network(callback=None):
    local_info = get_local_info()
    gateway = local_info.get('gateway', '')
    local_ip = local_info.get('local_ip', '')
    subnet_mask = local_info.get('subnet', '')
    
    devices = []

    # Determine network to scan using subnet mask if available, otherwise infer
    network = None
    try:
        if subnet_mask and ('.' in subnet_mask or subnet_mask.startswith('/')):
            # subnet may be like '255.255.255.0' or '/24'
            mask = subnet_mask if subnet_mask.startswith('/') else subnet_mask
            # ip_network accepts 'ip/netmask' where netmask can be a mask like 255.255.255.0
            network = ipaddress.ip_network(f"{local_ip}/{mask}", strict=False)
        elif gateway:
            # fall back to gateway's /24
            gateway_parts = gateway.split('.')
            if len(gateway_parts) == 4:
                network = ipaddress.ip_network(f"{gateway_parts[0]}.{gateway_parts[1]}.{gateway_parts[2]}.0/24", strict=False)
        elif local_ip:
            # no gateway or subnet info; infer default prefix
            if local_ip.startswith('10.') or local_ip.startswith('11.'):
                # larger private network - default to /16 to cover typical site-local ranges
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

    # Build host list (exclude network and broadcast)
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
            except:
                pass
    
    return {
        "devices": devices,
        "local_info": local_info,
        "scanned_at": datetime.now().isoformat(),
        "total_found": len(devices)
    }
