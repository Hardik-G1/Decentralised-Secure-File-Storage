# secure_file_client/constants.py

from enum import IntEnum

class AccessMode(IntEnum):
    PUBLIC = 0
    PRIVATE = 1
    SHARED = 2
    PAID = 3

MASTER_KEY_SSS_SHARES = 5
MASTER_KEY_SSS_THRESHOLD = 3

INDEX_NAME_PRIVATE = "private"
INDEX_NAME_PUBLIC = "public"
INDEX_NAME_SHARED = "shared"
INDEX_NAME_PAID = "paid"