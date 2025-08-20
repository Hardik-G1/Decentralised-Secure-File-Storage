# secure_file_client/__init__.py

from .client import Web3Client

# Import the constants that are most likely to be used by the UI or other scripts.
from .constants import (
    AccessMode,
    MASTER_KEY_SSS_SHARES,
    MASTER_KEY_SSS_THRESHOLD,
    INDEX_NAME_PRIVATE,
    INDEX_NAME_PUBLIC,
    INDEX_NAME_SHARED,
    INDEX_NAME_PAID
)

from .exceptions import ClientError

__all__ = [
    'Web3Client',
    'AccessMode',
    'ClientError',
    'MASTER_KEY_SSS_SHARES',
    'MASTER_KEY_SSS_THRESHOLD',
    'INDEX_NAME_PRIVATE',
    'INDEX_NAME_PUBLIC',
    'INDEX_NAME_SHARED',
    'INDEX_NAME_PAID'
]

# Print a message to confirm the package has been loaded.
print("Secure File Client package loaded.")