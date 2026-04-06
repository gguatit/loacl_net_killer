import os

API_BASE = os.getenv("API_BASE", "http://127.0.0.1:4622")
DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "새 텍스트 문서.txt")
USE_EXTERNAL_API = os.getenv("USE_EXTERNAL_API", "true").lower() in ("1", "true", "yes", "on")
