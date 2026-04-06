import threading
import time

try:
    from zeroconf import ServiceBrowser, Zeroconf
    ZEROCONF_AVAILABLE = True
except ImportError:
    ZEROCONF_AVAILABLE = False

mdns_cache = {}
mdns_scan_lock = threading.Lock()
mdns_scanning = False


def query_mdns_hostname(ip):
    """mDNS를 통해 IP의 호스트명 조회"""
    if not ZEROCONF_AVAILABLE:
        return ""

    try:
        from zeroconf import IPVersion, Zeroconf

        zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
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
                                        self.hostname = name.split('.')[0]
                        except Exception:
                            pass

                    def remove_service(self, zeroconf, service_type, name):
                        pass

                listener = HostnameListener()
                browser = ServiceBrowser(zeroconf, service_type, listener, timeout=500)
                time.sleep(0.5)
                browser.cancel()

                if listener.hostname:
                    found_hostname = listener.hostname
                    break
            except Exception:
                pass

        zeroconf.close()
        return found_hostname if found_hostname else ""
    except Exception:
        return ""


def scan_mdns_services():
    """백그라운드에서 전체 mDNS 서비스 검색 (캐시 생성)"""
    global mdns_scanning

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
                        hostname = name.split('.')[0] if '.' in name else name
                        for addr in info.addresses:
                            with mdns_scan_lock:
                                mdns_cache[addr] = hostname
                except Exception:
                    pass

            def remove_service(self, zeroconf, service_type, name):
                pass

        listener = CacheListener()
        browsers = []

        for service_type in ["_http._tcp.local.", "_ssh._tcp.local.", "_device-info._tcp.local."]:
            try:
                browser = ServiceBrowser(zeroconf, service_type, listener, timeout=1000)
                browsers.append(browser)
            except Exception:
                pass

        time.sleep(2)

        for browser in browsers:
            try:
                browser.cancel()
            except Exception:
                pass

        zeroconf.close()
    except Exception as e:
        print(f"[mDNS Scan Error] {e}")
    finally:
        mdns_scanning = False
