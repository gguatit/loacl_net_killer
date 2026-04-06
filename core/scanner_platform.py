import ipaddress
import os
import platform
import re
import socket
import subprocess
from datetime import datetime

from core.scanner_mdns import ZEROCONF_AVAILABLE, mdns_cache, query_mdns_hostname

SYSTEM = platform.system().lower()
IS_WINDOWS = SYSTEM == "windows"
IS_LINUX = SYSTEM == "linux"
IS_MACOS = SYSTEM == "darwin"

WINDOWS_VIRTUAL_ADAPTER_KEYWORDS = (
    "virtual",
    "vmware",
    "hyper-v",
    "vethernet",
    "loopback",
    "bluetooth",
    "tailscale",
    "wsl",
    "docker",
)

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
    if IS_LINUX:
        return get_local_info_linux()
    if IS_WINDOWS:
        return get_local_info_windows()
    if IS_MACOS:
        return get_local_info_macos()
    return get_local_info_generic()


def get_local_info_linux():
    hostname = socket.gethostname()
    local_ip = ""
    mac_address = ""
    gateway = ""
    subnet = ""
    dns_servers = []

    try:
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            if 'inet ' in line and 'scope host' not in line:
                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    local_ip = match.group(1)
                    break
    except Exception:
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=2)
            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                local_ip = match.group(1)
        except Exception:
            pass

    if not local_ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            match = re.search(r'link/ether\s+([0-9a-fA-F:]+)', line)
            if match:
                mac_address = match.group(1).upper()
                break
    except Exception:
        pass

    try:
        result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            if 'default via' in line:
                match = re.search(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    gateway = match.group(1)
                    break
    except Exception:
        pass

    try:
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            if 'inet ' in line and local_ip in line:
                match = re.search(r'/(\d+)', line)
                if match:
                    prefix = int(match.group(1))
                    subnet = str(ipaddress.IPv4Network(f'0.0.0.0/{prefix}').netmask)
                    break
    except Exception:
        pass

    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    dns = line.split()[1]
                    if dns not in dns_servers:
                        dns_servers.append(dns)
    except Exception:
        pass

    return {
        "hostname": hostname,
        "local_ip": local_ip or "127.0.0.1",
        "mac_address": mac_address,
        "gateway": gateway,
        "subnet": subnet or "255.255.255.0",
        "dns_servers": dns_servers,
        "os": platform.system(),
        "platform": platform.platform(),
        "timestamp": datetime.now().isoformat()
    }


def get_local_info_windows():
    hostname = socket.gethostname()
    local_ip = ""
    mac_address = ""
    gateway = ""
    subnet = ""
    dns_servers = []

    ipconfig_output = ""
    for enc in ['utf-8', 'cp949', 'euc-kr', 'latin-1']:
        try:
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, encoding=enc, errors='replace')
            ipconfig_output = result.stdout
            if ipconfig_output and len(ipconfig_output) > 100:
                break
        except Exception:
            continue

    adapters = _parse_windows_ipconfig_adapters(ipconfig_output)
    route_info = _get_windows_default_route_info()

    if route_info and route_info.get("interface_ip"):
        route_ip = route_info["interface_ip"]
        matched = next((a for a in adapters if a.get("ip") == route_ip), None)
        if matched:
            local_ip = matched.get("ip", "")
            mac_address = matched.get("mac", "")
            gateway = matched.get("gateway", "") or route_info.get("gateway", "")
            subnet = matched.get("subnet", "")
            dns_servers = matched.get("dns", [])
        else:
            # Keep interface IP from default route even when ipconfig block parsing fails.
            local_ip = route_ip
            gateway = route_info.get("gateway", "")

    if not local_ip:
        preferred = _select_best_windows_adapter(adapters)
        if preferred:
            local_ip = preferred.get("ip", "")
            mac_address = preferred.get("mac", "")
            gateway = preferred.get("gateway", "")
            subnet = preferred.get("subnet", "")
            dns_servers = preferred.get("dns", [])

    if not local_ip:
        try:
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            local_ip = ""

    if not local_ip or local_ip.startswith('127.'):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

    if not gateway:
        gateway = route_info.get("gateway", "") if route_info else get_default_gateway_windows()
    if not mac_address:
        mac_address = get_mac_address_windows()

    if not subnet and local_ip:
        matched = next((a for a in adapters if a.get("ip") == local_ip), None)
        if matched:
            subnet = matched.get("subnet", "")
            if not dns_servers:
                dns_servers = matched.get("dns", [])

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


def _parse_windows_ipconfig_adapters(ipconfig_output):
    adapters = []
    if not ipconfig_output:
        return adapters

    lines = ipconfig_output.splitlines()
    current = None
    pending = None

    def flush_current():
        nonlocal current
        if not current:
            return
        if current.get("ip") and not current.get("disconnected"):
            adapters.append({
                "name": current.get("name", ""),
                "ip": current.get("ip", ""),
                "subnet": current.get("subnet", ""),
                "gateway": current.get("gateway", ""),
                "mac": current.get("mac", ""),
                "dns": current.get("dns", []),
            })
        current = None

    for raw in lines:
        line = raw.rstrip("\r\n")
        stripped = line.strip()
        low = stripped.lower()

        is_header = (
            stripped.endswith(":") and (
                "adapter" in low or "어댑터" in low
            )
        )
        if is_header:
            flush_current()
            current = {
                "name": stripped,
                "ip": "",
                "subnet": "",
                "gateway": "",
                "mac": "",
                "dns": [],
                "disconnected": False,
            }
            pending = None
            continue

        if not current:
            continue

        if "media disconnected" in low or "미디어 연결 끊김" in low:
            current["disconnected"] = True

        value = stripped.split(":", 1)[1].strip() if ":" in stripped else ""
        parsed_ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", value or stripped)

        if "physical address" in low or "물리적 주소" in low:
            m = re.search(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", value or stripped)
            if m:
                current["mac"] = m.group(1).upper()

        if ("ipv4" in low or "ipv4 주소" in low) and parsed_ip and not current["ip"]:
            current["ip"] = parsed_ip.group(1)

        if ("subnet mask" in low or "서브넷" in low) and parsed_ip and not current["subnet"]:
            current["subnet"] = parsed_ip.group(1)

        if ("default gateway" in low or "기본 게이트웨이" in low):
            pending = "gateway"
            if parsed_ip and not current["gateway"]:
                current["gateway"] = parsed_ip.group(1)
                pending = None
            continue

        if ("dns servers" in low or "dns 서버" in low):
            pending = "dns"
            if parsed_ip and parsed_ip.group(1) not in current["dns"]:
                current["dns"].append(parsed_ip.group(1))
            continue

        if pending == "gateway" and parsed_ip and not current["gateway"]:
            current["gateway"] = parsed_ip.group(1)
            pending = None

        if pending == "dns" and parsed_ip:
            dns_ip = parsed_ip.group(1)
            if dns_ip not in current["dns"]:
                current["dns"].append(dns_ip)
            else:
                pending = None

    flush_current()

    return adapters


def _select_best_windows_adapter(adapters):
    best = None
    best_score = -10**9

    for a in adapters:
        ip = a.get("ip", "")
        if not ip:
            continue
        if ip.startswith("169.254.") or ip.startswith("127."):
            continue

        score = 0
        if a.get("gateway"):
            score += 40
        if a.get("subnet"):
            score += 10
        if a.get("mac"):
            score += 5

        name_lower = a.get("name", "").lower()
        if any(k in name_lower for k in ("wi-fi", "wifi", "wireless", "이더넷", "ethernet", "무선")):
            score += 30
        if any(k in name_lower for k in WINDOWS_VIRTUAL_ADAPTER_KEYWORDS):
            score -= 50

        if ip.startswith("10.") or ip.startswith("11.") or ip.startswith("172.") or ip.startswith("192.168."):
            score += 10

        if score > best_score:
            best_score = score
            best = a

    return best


def _get_windows_default_route_info():
    # Try to map default route to interface IP/gateway using route print output.
    for enc in ["utf-8", "cp949", "euc-kr", "latin-1"]:
        try:
            result = subprocess.run(['route', 'print', '-4'], capture_output=True, encoding=enc, errors='replace', timeout=2)
            lines = result.stdout.splitlines()
            best = None
            for line in lines:
                parts = line.split()
                # Expected: destination netmask gateway interface metric
                if len(parts) < 5:
                    continue
                if parts[0] != '0.0.0.0' or parts[1] != '0.0.0.0':
                    continue
                gateway = parts[2]
                interface_ip = parts[3]
                try:
                    metric = int(parts[4])
                except Exception:
                    metric = 9999
                if not re.match(r"^\d+\.\d+\.\d+\.\d+$", gateway):
                    continue
                if not re.match(r"^\d+\.\d+\.\d+\.\d+$", interface_ip):
                    continue
                if best is None or metric < best["metric"]:
                    best = {"gateway": gateway, "interface_ip": interface_ip, "metric": metric}
            if best:
                return best
        except Exception:
            continue
    return None


def get_local_info_macos():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    try:
        if local_ip.startswith('127.'):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
    except Exception:
        pass

    mac_address = ""
    gateway = ""
    dns_servers = []

    try:
        result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            if 'inet ' in line and 'inet6' not in line:
                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                if match and local_ip.startswith('127.'):
                    local_ip = match.group(1)
            if 'ether ' in line:
                match = re.search(r'ether\s+([0-9a-fA-F:]+)', line)
                if match:
                    mac_address = match.group(1).upper()
    except Exception:
        pass

    try:
        result = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            if 'gateway:' in line:
                match = re.search(r'gateway:\s+(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    gateway = match.group(1)
                    break
    except Exception:
        pass

    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    dns = line.split()[1]
                    if dns not in dns_servers:
                        dns_servers.append(dns)
    except Exception:
        pass

    return {
        "hostname": hostname,
        "local_ip": local_ip,
        "mac_address": mac_address,
        "gateway": gateway,
        "subnet": "255.255.255.0",
        "dns_servers": dns_servers,
        "os": platform.system(),
        "platform": platform.platform(),
        "timestamp": datetime.now().isoformat()
    }


def get_local_info_generic():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    try:
        if local_ip.startswith('127.'):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
    except Exception:
        pass

    return {
        "hostname": hostname,
        "local_ip": local_ip,
        "mac_address": "",
        "gateway": "",
        "subnet": "255.255.255.0",
        "dns_servers": [],
        "os": platform.system(),
        "platform": platform.platform(),
        "timestamp": datetime.now().isoformat()
    }


def get_default_gateway_windows():
    try:
        result = subprocess.run(['route', 'print', '0.0.0.0'], capture_output=True, encoding='utf-8', errors='replace')
        for line in result.stdout.split('\n'):
            if '0.0.0.0' in line and '0.0.0.0' in line.split():
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
    except Exception:
        pass
    try:
        result = subprocess.run(['netstat', '-r'], capture_output=True, encoding='utf-8', errors='replace')
        for line in result.stdout.split('\n'):
            if '0.0.0.0' in line or 'Default' in line:
                parts = line.split()
                for part in parts:
                    if part.count('.') == 3:
                        return part
    except Exception:
        pass
    return ""


def get_mac_address_windows():
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
        except Exception:
            pass
    try:
        result = subprocess.run(['ipconfig', '/all'], capture_output=True, encoding='utf-8', errors='replace')
        for line in result.stdout.split('\n'):
            if 'Physical Address' in line or '물리적 주소' in line:
                mac = line.split(':')[-1].strip()
                if mac and len(mac) >= 12:
                    return mac.upper()
    except Exception:
        pass
    return ""


def ping_host_fast(ip):
    try:
        ttl = 0
        if IS_WINDOWS:
            # 350ms ping timeout to keep bulk scan responsive.
            cmd = ['ping', '-n', '1', '-w', '350', ip]
            timeout_sec = 1.2
        else:
            # Linux/macOS: -W 1 is 1 second, but subprocess timeout is kept short.
            cmd = ['ping', '-c', '1', '-W', '1', ip]
            timeout_sec = 1.5

        result = subprocess.run(cmd, capture_output=True, timeout=timeout_sec, encoding='utf-8', errors='replace')
        out = result.stdout or ''
        out_lower = out.lower()

        success = (result.returncode == 0) or ('reply from' in out_lower) or ('bytes from' in out_lower)
        if not success:
            return False, 0

        for line in out.split('\n'):
            l = line.upper()
            if 'TTL=' in l:
                try:
                    ttl_str = l.split('TTL=')[-1].split()[0]
                    ttl = int(''.join(ch for ch in ttl_str if ch.isdigit()))
                    break
                except Exception:
                    continue
            if ' ttl=' in line.lower():
                try:
                    ttl = int(line.lower().split(' ttl=')[-1].split()[0])
                    break
                except Exception:
                    continue

        if ttl == 0:
            ttl = 64
        return True, ttl
    except Exception:
        return False, 0


def get_hostname_from_ip(ip):
    if ip in mdns_cache:
        return mdns_cache[ip]

    if IS_WINDOWS:
        try:
            result = subprocess.run(['nbtstat', '-a', ip], capture_output=True, timeout=1, encoding='utf-8', errors='replace')
            for line in result.stdout.split('\n'):
                if '<00>' in line and 'UNIQUE' in line:
                    hostname = line.split()[0].strip()
                    if hostname and len(hostname) > 1:
                        return hostname
        except Exception:
            pass

    if IS_LINUX:
        try:
            result = subprocess.run(['host', ip], capture_output=True, timeout=1, text=True)
            if 'domain name pointer' in result.stdout:
                return result.stdout.split('pointer ')[-1].strip().rstrip('.')
        except Exception:
            pass

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        pass

    if ZEROCONF_AVAILABLE:
        try:
            mdns_hostname = query_mdns_hostname(ip)
            if mdns_hostname:
                mdns_cache[ip] = mdns_hostname
                return mdns_hostname
        except Exception:
            pass

    return ""


def estimate_os(ttl):
    if ttl <= 0:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Mac/Android"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
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
            ['arp', '-a', ip] if IS_WINDOWS else ['arp', '-a'],
            capture_output=True,
            timeout=1,
            encoding='utf-8',
            errors='replace'
        )
        for line in result.stdout.split('\n'):
            if ('-' in line) or (':' in line) or ('.' in line):
                parts = line.split()
                if len(parts) >= 2 and parts[0] == ip:
                    mac = parts[1].replace('-', ':').replace('.', '').upper()
                    if len(mac) == 12:
                        mac = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
                    if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                        return mac
    except Exception:
        pass

    if IS_LINUX and os.path.exists('/proc/net/arp'):
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00" and ':' in mac:
                            return mac.upper()
        except Exception:
            pass

    return ""
