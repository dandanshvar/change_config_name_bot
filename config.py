import os
import random
import logging

from dotenv import load_dotenv

load_dotenv()

# TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
# up
LIST_NAMES = [
    "@Zlinkid 🫦",
    "@Zlinkid 🇺🇸",
    "@Zlinkid 🇨🇦",
    "@Zlinkid 🇩🇪",
    "@Zlinkid 🇫🇷",
]

def get_random_name():
    return random.choice(LIST_NAMES)

NEW_NAME = "@zlinkid 🇩🇪 "

ADMIN_CHANNEL_ID = os.getenv("ADMIN_CHANNEL_ID")

MAX_CONFIGS_PER_MSG = int(os.getenv("MAX_CONFIGS_PER_MSG", 100))
MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_FILE_SIZE_BYTES", 512 * 1024))

RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", 10))
RATE_LIMIT_WINDOW = float(os.getenv("RATE_LIMIT_WINDOW", 60))

# PROXY_URL = os.getenv("PROXY_URL")

LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"

# SOURCE_CHANNEL_ID = int(os.getenv("SOURCE_CHANNEL_ID"))
# DEST_CHANNEL_ID = int(os.getenv("DEST_CHANNEL_ID"))

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
PROXY_URL = os.getenv("PROXY_URL", "").strip() if os.getenv("PROXY_URL") else None

SOURCE_CHANNEL_ID = int(os.getenv("SOURCE_CHANNEL_ID", "0"))
DEST_CHANNEL_ID = int(os.getenv("DEST_CHANNEL_ID", "0"))