import os
import random
import logging

from dotenv import load_dotenv

load_dotenv()
# TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
LIST_NAMES = [
    "@Zlinkid_US",
    "@Zlinkid_US_MCI",
    "@Zlinkid_US_IRANC",

    "@Zlinkid_CA",
    "@Zlinkid_CA_MCI",
    "@Zlinkid_CA_IRANC",

    "@Zlinkid_DE",
    "@Zlinkid_DE_MCI",
    "@Zlinkid_DE_IRANC",

    "@Zlinkid_FR",
    "@Zlinkid_FR_MCI",
    "@Zlinkid_FR_IRANC",

    "@Zlinkid_FI",
    "@Zlinkid_FI_MCI",
    "@Zlinkid_FI_IRANC",

    "@Zlinkid_NL",
    "@Zlinkid_NL_MCI",
    "@Zlinkid_NL_IRANC",

    "@Zlinkid_GB",
    "@Zlinkid_GB_MCI",
    "@Zlinkid_GB_IRANC",

    "@Zlinkid_SE",
    "@Zlinkid_SE_MCI",
    "@Zlinkid_SE_IRANC",

    "@Zlinkid_NO",
    "@Zlinkid_NO_MCI",
    "@Zlinkid_NO_IRANC",

    "@Zlinkid_CH",
    "@Zlinkid_CH_MCI",
    "@Zlinkid_CH_IRANC",

    "@Zlinkid_IT",
    "@Zlinkid_IT_MCI",
    "@Zlinkid_IT_IRANC",

    "@Zlinkid_ES",
    "@Zlinkid_ES_MCI",
    "@Zlinkid_ES_IRANC",

    "@Zlinkid_JP",
    "@Zlinkid_JP_MCI",
    "@Zlinkid_JP_IRANC",

    "@Zlinkid_SG",
    "@Zlinkid_SG_MCI",
    "@Zlinkid_SG_IRANC",

    "@Zlinkid_AU",
    "@Zlinkid_AU_MCI",
    "@Zlinkid_AU_IRANC",

    "@Zlinkid_KR",
    "@Zlinkid_KR_MCI",
    "@Zlinkid_KR_IRANC",

    "@Zlinkid_TR",
    "@Zlinkid_TR_MCI",
    "@Zlinkid_TR_IRANC",

    "@Zlinkid_AE",
    "@Zlinkid_AE_MCI",
    "@Zlinkid_AE_IRANC",

    "@Zlinkid_PL",
    "@Zlinkid_PL_MCI",
    "@Zlinkid_PL_IRANC",

    "@Zlinkid_AT",
    "@Zlinkid_AT_MCI",
    "@Zlinkid_AT_IRANC",

    "@Zlinkid_BE",
    "@Zlinkid_BE_MCI",
    "@Zlinkid_BE_IRANC",

    "@Zlinkid_DK",
    "@Zlinkid_DK_MCI",
    "@Zlinkid_DK_IRANC",

    "@Zlinkid_IE",
    "@Zlinkid_IE_MCI",
    "@Zlinkid_IE_IRANC",

    "@Zlinkid_CZ",
    "@Zlinkid_CZ_MCI",
    "@Zlinkid_CZ_IRANC",

    "@Zlinkid_PT",
    "@Zlinkid_PT_MCI",
    "@Zlinkid_PT_IRANC",
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

SOURCE_CHANNEL_ID = int(os.getenv("SOURCE_CHANNEL_ID", "0").strip())
DEST_CHANNEL_ID = int(os.getenv("DEST_CHANNEL_ID", "0").strip())
# SOURCE_CHANNEL_ID = int(os.getenv("SOURCE_CHANNEL_ID"))
# DEST_CHANNEL_ID = int(os.getenv("DEST_CHANNEL_ID"))

# TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
PROXY_URL = os.getenv("PROXY_URL", "").strip() if os.getenv("PROXY_URL") else None

# SOURCE_CHANNEL_ID = int(os.getenv("SOURCE_CHANNEL_ID", "0"))
# DEST_CHANNEL_ID = int(os.getenv("DEST_CHANNEL_ID", "0"))