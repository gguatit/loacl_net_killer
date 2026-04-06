import json
from core.config import DATA_FILE


def load_network_data():
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        return {"ResponseStat": "ERROR", "error": str(e), "network_device": []}
