import os
from dotenv import load_dotenv

load_dotenv()

ACCUKNOX_PF_TOKEN = os.getenv("ACCUKNOX_PF_TOKEN", "")
PF_USER_INFO = os.getenv("PF_USER_INFO", "pf-lab-user")
PF_LIVE_ENABLED = os.getenv("PF_LIVE_ENABLED", "false").lower() == "true"
PF_MAX_LIVE_REQUESTS = int(os.getenv("PF_MAX_LIVE_REQUESTS", "20"))

FAIL_CLOSED = os.getenv("FAIL_CLOSED", "true").lower() == "true"
BLOCK_UNCHECKED = os.getenv("BLOCK_UNCHECKED", "false").lower() == "true"
BLOCK_MONITOR = os.getenv("BLOCK_MONITOR", "false").lower() == "true"
EXPOSE_RAW_PF_RESULT = os.getenv("EXPOSE_RAW_PF_RESULT", "false").lower() == "true"
