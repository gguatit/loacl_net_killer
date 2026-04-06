import socket
import ipaddress
import subprocess
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import os
import re

try:
    from zeroconf import ServiceBrowser, Zeroconf
    ZEROCONF_AVAILABLE = True
except ImportError:
    ZEROCONF_AVAILABLE = False
    print("[Warning] zeroconf 라이브러리가 없습니다. mDNS 감지가 비활성화됩니다.")

# 플랫폼 감지
SYSTEM = platform.system().lower()
IS_WINDOWS = SYSTEM == "windows"
IS_LINUX = SYSTEM == "linux"
IS_MACOS = SYSTEM == "darwin"

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

# mDNS 캐시 (IP -> hostname)
mdns_cache = {}
mdns_scan_lock = threading.Lock()
mdns_scanning = False

# =============================================================================
# Linux 플랫폼용 헬퍼 함수
# =============================================================================

def get_local_info_linux():
    """Linux/NetHunter에서 로컬 정보 수집"""
    hostname = socket.gethostname()
    local_ip = ""
    mac_address = ""
    gateway = ""
    subnet = ""
    dns_servers = []
    
    # 1. Local IP 감지 (ip addr show 또는 ifconfig)
    try:
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            if 'inet ' in line and 'scope host' not in line:
                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    local_ip = match.group(1)
                    break
    except:
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=2)
            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                local_ip = match.group(1)
        except:
            pass
    
    if not local_ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            pass
    
    # 2. MAC 주소 (ip link show)
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            match = re.search(r'link/ether\s+([0-9a-fA-F:]+)', line)
            if match:
                mac_address = match.group(1).upper()
                break
    except:
        pass
    
    # 3. 게이트웨이 (ip route show)
    try:
        result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            if 'default via' in line:
                match = re.search(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    gateway = match.group(1)
                    break
    except:
        pass
    
    # 4. 서브넷 마스크
    try:
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            if 'inet ' in line and local_ip in line:
                match = re.search(r'/(\d+)', line)
                if match:
                    prefix = int(match.group(1))
                    # CIDR to netmask
                    subnet = str(ipaddress.IPv4Network(f'0.0.0.0/{prefix}').netmask)
                    break
    except:
        pass
    
    # 5. DNS 서버
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    dns = line.split()[1]
                    if dns not in dns_servers:
                        dns_servers.append(dns)
    except:
        pass
    
    return {
        "hostname": hostname,
        "local_ip": local_ip or "127.0.0.1",
        "mac_address": mac_address or "",
        "gateway": gateway or "",
        "subnet": subnet or "255.255.255.0",
        "dns_servers": dns_servers,
        "os": platform.system(),
        "platform": platform.platform(),
        "timestamp": datetime.now().isoformat()
    }

def get_default_gateway_linux():
    """Linux에서 게이트웨이 감지"""
    try:
        result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            if 'default via' in line:
                match = re.search(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    return match.group(1)
    except:
        pass
    return ""

def get_mac_address_linux():
    """Linux에서 MAC 주소 조회"""
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            match = re.search(r'link/ether\s+([0-9a-fA-F:]+)', line)
            if match:
                return match.group(1).upper()
    except:
        pass
    return ""

def get_local_info():
    """플랫폼에 따라 로컬 정보 수집"""
    if IS_LINUX:
        return get_local_info_linux()
    elif IS_WINDOWS:
        return get_local_info_windows()
    elif IS_MACOS:
        return get_local_info_macos()
    else:
        return get_local_info_generic()

def get_local_info_windows():
    """Windows에서 로컬 정보 수집"""
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
        gateway = get_default_gateway_windows()
    
    if not mac_address:
        mac_address = get_mac_address_windows()
    
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

def get_local_info_macos():
    """macOS에서 로컬 정보 수집"""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
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
    
    # macOS: ifconfig 사용
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
    except:
        pass
    
    # 게이트웨이
    try:
        result = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            if 'gateway:' in line:
                match = re.search(r'gateway:\s+(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    gateway = match.group(1)
                    break
    except:
        pass
    
    # DNS
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    dns = line.split()[1]
                    if dns not in dns_servers:
                        dns_servers.append(dns)
    except:
        pass
    
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

def get_local_info_generic():
    """기타 플랫폼용 기본 구현"""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    try:
        if local_ip.startswith('127.'):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
    except:
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
    """Windows에서 게이트웨이 감지"""
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

def get_mac_address_windows():
    """Windows에서 MAC 주소 조회"""
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
        ttl = 0
        if IS_WINDOWS:
            # -n 1 : one echo, -w 1000 : timeout in ms
            cmd = ['ping', '-n', '1', '-w', '1000', ip]
            timeout_sec = 4
        else:
            # Linux/macOS: -c 1 one echo, -W 1 timeout in seconds
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
    # 1. 캐시 확인
    if ip in mdns_cache:
        return mdns_cache[ip]
    
    # 2. Windows NBTStat 시도
    if IS_WINDOWS:
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
    
    # 3. Linux reverse DNS lookup
    if IS_LINUX:
        try:
            result = subprocess.run(
                ['host', ip],
                capture_output=True,
                timeout=1,
                text=True
            )
            if 'domain name pointer' in result.stdout:
                hostname = result.stdout.split('pointer ')[-1].strip().rstrip('.')
                return hostname
        except:
            pass
    
    # 4. socket 역조회 시도
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        pass
    
    # 5. mDNS 역조회 시도 (.local 도메인)
    if ZEROCONF_AVAILABLE:
        try:
            mdns_hostname = query_mdns_hostname(ip)
            if mdns_hostname:
                mdns_cache[ip] = mdns_hostname
                return mdns_hostname
        except:
            pass
    
    return ""

def query_mdns_hostname(ip):
    """mDNS를 통해 IP의 호스트명 조회"""
    if not ZEROCONF_AVAILABLE:
        return ""
    
    try:
        from zeroconf import IPVersion, Zeroconf
        
        # 로컬 네트워크에서 서비스 검색
        zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        
        # 주요 서비스 타입 검색
        service_types = [
            "_http._tcp.local.",
            "_https._tcp.local.",
            "_ssh._tcp.local.",
            "_smb._tcp.local.",
            "_device-info._tcp.local.",
        ]
        
        found_hostname = None
        
        for service_type in service_types:
            try:
                from zeroconf import ServiceBrowser
                
                class HostnameListener:
                    def __init__(self):
                        self.hostname = None
                    
                    def update_record(self, zeroconf, service_type, name):
                        pass
                    
                    def add_service(self, zeroconf, service_type, name):
                        try:
                            info = zeroconf.get_service_info(service_type, name)
                            if info and info.addresses:
                                for addr in info.addresses:
                                    if addr == ip:
                                        # 호스트명 추출 (예: "device.local" -> "device")
                                        hostname = name.split('.')[0]
                                        self.hostname = hostname
                        except:
                            pass
                    
                    def remove_service(self, zeroconf, service_type, name):
                        pass
                
                listener = HostnameListener()
                browser = ServiceBrowser(zeroconf, service_type, listener, timeout=500)
                
                # 0.5초 대기
                time.sleep(0.5)
                browser.cancel()
                
                if listener.hostname:
                    found_hostname = listener.hostname
                    break
                    
            except:
                pass
        
        zeroconf.close()
        return found_hostname if found_hostname else ""
        
    except Exception as e:
        return ""

def scan_mdns_services():
    """백그라운드에서 전체 mDNS 서비스 검색 (캐시 생성)"""
    global mdns_scanning, mdns_cache
    
    if not ZEROCONF_AVAILABLE or mdns_scanning:
        return
    
    mdns_scanning = True
    
    try:
        from zeroconf import IPVersion, ServiceBrowser, Zeroconf
        
        zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        
        class CacheListener:
            def update_record(self, zeroconf, service_type, name):
                pass
            
            def add_service(self, zeroconf, service_type, name):
                try:
                    info = zeroconf.get_service_info(service_type, name)
                    if info and info.addresses:
                        # 호스트명 추출
                        hostname = name.split('.')[0] if '.' in name else name
                        # IP 주소 저장
                        for addr in info.addresses:
                            with mdns_scan_lock:
                                mdns_cache[addr] = hostname
                except:
                    pass
            
            def remove_service(self, zeroconf, service_type, name):
                pass
        
        # 여러 서비스 타입 검색
        listener = CacheListener()
        browsers = []
        
        for service_type in ["_http._tcp.local.", "_ssh._tcp.local.", "_device-info._tcp.local."]:
            try:
                browser = ServiceBrowser(zeroconf, service_type, listener, timeout=1000)
                browsers.append(browser)
            except:
                pass
        
        # 2초 대기
        time.sleep(2)
        
        # 정리
        for browser in browsers:
            try:
                browser.cancel()
            except:
                pass
        
        zeroconf.close()
        
    except Exception as e:
        print(f"[mDNS Scan Error] {e}")
    finally:
        mdns_scanning = False

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
    """ARP 테이블에서 IP의 MAC 주소 조회"""
    try:
        # 모든 플랫폼에서 arp -a 시도
        result = subprocess.run(
            ['arp', '-a', ip] if IS_WINDOWS else ['arp', '-a'],
            capture_output=True,
            timeout=1,
            encoding='utf-8',
            errors='replace'
        )
        for line in result.stdout.split('\n'):
            # Accept MAC in formats with '-' or ':' or '.'
            if ('-' in line) or (':' in line) or ('.' in line):
                parts = line.split()
                # Windows: IP MAC Type 형식
                if IS_WINDOWS and len(parts) >= 2:
                    if parts[0] == ip:
                        mac = parts[1].replace('-', ':').replace('.', '').upper()
                        if len(mac) == 12:
                            mac = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
                        if mac != "FF:FF:FF:FF:FF:FF" and mac != "00:00:00:00:00:00":
                            return mac
                # Linux/macOS: IP MAC 형식
                elif len(parts) >= 2 and parts[0] == ip:
                    mac = parts[1].replace('-', ':').replace('.', '').upper()
                    if len(mac) == 12:
                        mac = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
                    if mac != "FF:FF:FF:FF:FF:FF" and mac != "00:00:00:00:00:00":
                        return mac
    except:
        pass
    
    # Linux: /proc/net/arp 직접 읽기 (빠름)
    if IS_LINUX and os.path.exists('/proc/net/arp'):
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00" and ':' in mac:
                            return mac.upper()
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
    """ARP 테이블 스캔 (크로스플랫폼) - 안정화 버전"""
    # 백그라운드에서 mDNS 스캔 시작 (비동기)
    mdns_thread = threading.Thread(target=scan_mdns_services, daemon=True)
    mdns_thread.start()
    
    devices = []
    seen_ips = set()
    
    # 1. 먼저 ARP 테이블에서 직접 읽기 시도
    if IS_LINUX and os.path.exists('/proc/net/arp'):
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3]
                        
                        # 헤더 스킵, 유효한 MAC만
                        if ip == 'IP' or mac == "00:00:00:00:00:00" or ip in seen_ips:
                            continue
                        
                        seen_ips.add(ip)
                        
                        is_alive, ttl = ping_host_fast(ip)
                        hostname = get_hostname_from_ip(ip)
                        
                        device = {
                            "ip": ip,
                            "mac": mac.upper(),
                            "hostname": hostname or "Unknown",
                            "os_estimate": estimate_os(ttl) if is_alive else "Unknown",
                            "vendor": get_vendor(mac),
                            "status": "online" if is_alive else "offline",
                            "ttl": ttl if is_alive else 0,
                            "last_seen": datetime.now().isoformat()
                        }
                        devices.append(device)
            
            if devices:
                return sorted(devices, key=lambda x: [int(p) for p in x['ip'].split('.')])
        except Exception as e:
            print(f"[ARP Scan] /proc/net/arp 읽기 실패: {e}")
    
    # 2. arp -a 커맨드 사용
    try:
        result = subprocess.run(
            ['arp', '-a'],
            capture_output=True,
            timeout=3,
            text=True
        )
        
        if result.stdout:
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line or 'Interface' in line or '---' in line:
                    continue
                
                # Windows: IP MAC Type 형식
                # Linux: IP HW Type HW Address Flags Mask
                # macOS: IP (HW) at MAC on interface
                
                parts = line.split()
                if len(parts) < 2:
                    continue
                
                ip = parts[0]
                mac = None
                
                # IP 형식 확인
                if not all(c.isdigit() or c == '.' for c in ip.split('.')[0] if ip.split('.')[0]):
                    continue
                
                # MAC 주소 추출
                for part in parts[1:]:
                    if (':' in part or '-' in part) and len(part.replace(':', '').replace('-', '')) >= 10:
                        mac = part.replace('-', ':').upper()
                        break
                
                if mac and ip not in seen_ips:
                    seen_ips.add(ip)
                    
                    is_alive, ttl = ping_host_fast(ip)
                    hostname = get_hostname_from_ip(ip)
                    
                    device = {
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname or "Unknown",
                        "os_estimate": estimate_os(ttl) if is_alive else "Unknown",
                        "vendor": get_vendor(mac),
                        "status": "online" if is_alive else "offline",
                        "ttl": ttl if is_alive else 0,
                        "last_seen": datetime.now().isoformat()
                    }
                    devices.append(device)
            
            if devices:
                return sorted(devices, key=lambda x: [int(p) for p in x['ip'].split('.')])
    except Exception as e:
        print(f"[ARP Scan] arp -a 실패: {e}")
    
    # 3. Windows netsh 백업 방법
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
                        # netsh 형식: IP MAC State
                        ip = parts[0]
                        mac = parts[1] if ':' in parts[1] or '-' in parts[1] else None
                        
                        if mac and ip not in seen_ips and all(c.isdigit() or c == '.' for c in ip):
                            seen_ips.add(ip)
                            
                            mac = mac.replace('-', ':').upper()
                            is_alive, ttl = ping_host_fast(ip)
                            hostname = get_hostname_from_ip(ip)
                            
                            device = {
                                "ip": ip,
                                "mac": mac,
                                "hostname": hostname or "Unknown",
                                "os_estimate": estimate_os(ttl) if is_alive else "Unknown",
                                "vendor": get_vendor(mac),
                                "status": "online" if is_alive else "offline",
                                "ttl": ttl if is_alive else 0,
                                "last_seen": datetime.now().isoformat()
                            }
                            devices.append(device)
                
                if devices:
                    return sorted(devices, key=lambda x: [int(p) for p in x['ip'].split('.')])
        except Exception as e:
            print(f"[ARP Scan] netsh 실패: {e}")
    
    # 4. ARP 테이블이 비어있으면 네트워크 범위 스캔으로 전환
    if not devices:
        print("[ARP Scan] ARP 테이블이 비어있어 Ping 기반 스캔으로 전환...")
        return scan_network_by_ping()
    
    return sorted(devices, key=lambda x: [int(p) for p in x['ip'].split('.')])

def scan_network_by_ping():
    """Ping 기반 네트워크 스캔 (ARP 실패 시 백업)"""
    local_info = get_local_info()
    local_ip = local_info.get('local_ip', '')
    gateway = local_info.get('gateway', '')
    
    # 네트워크 범위 감지
    network = None
    try:
        if local_ip:
            # /24 범위 기본값
            ip_parts = local_ip.split('.')
            if len(ip_parts) == 4:
                network_addr = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                network = ipaddress.ip_network(network_addr, strict=False)
    except:
        pass
    
    if not network:
        print("[Ping Scan] 네트워크 범위를 감지할 수 없습니다")
        return []
    
    devices = []
    all_ips = [str(ip) for ip in network.hosts()]
    
    print(f"[Ping Scan] {len(all_ips)}개 IP 범위 스캔 시작...")
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in all_ips}
        completed = 0
        
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    devices.append(result)
                completed += 1
                if completed % 50 == 0:
                    print(f"[Ping Scan] 진행 중... {completed}/{len(all_ips)}")
            except Exception as e:
                completed += 1
    
    print(f"[Ping Scan] 스캔 완료: {len(devices)}개 기기 발견")
    return sorted(devices, key=lambda x: [int(p) for p in x['ip'].split('.')])


def scan_network(callback=None):
    global mdns_cache
    
    local_info = get_local_info()
    gateway = local_info.get('gateway', '')
    local_ip = local_info.get('local_ip', '')
    subnet_mask = local_info.get('subnet', '')
    
    # 백그라운드에서 mDNS 스캔 시작 (비동기)
    mdns_thread = threading.Thread(target=scan_mdns_services, daemon=True)
    mdns_thread.start()
    
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
