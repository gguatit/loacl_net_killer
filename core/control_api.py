import urllib.parse
import urllib.request

from core.config import API_BASE


def normalize_mac(mac):
    return ''.join(ch for ch in (mac or '') if ch.isalnum()).upper()


def make_api_url(action, mac, value):
    mac_enc = urllib.parse.quote(normalize_mac(mac), safe='')
    val_enc = urllib.parse.quote(str(value), safe='')
    return f"{API_BASE}/{urllib.parse.quote(action, safe='')}/{mac_enc}/{val_enc}"


def is_external_api_available():
    try:
        with urllib.request.urlopen(API_BASE, timeout=1.5):
            return True
    except Exception:
        return False


def call_external_api(action, mac, value, timeout=5):
    url = make_api_url(action, mac, value)
    with urllib.request.urlopen(url, timeout=timeout) as response:
        result = response.read().decode('utf-8')
        return url, result
