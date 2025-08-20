# secure_file_client/exceptions.py

class ClientError(Exception):
    pass


class InitializationError(ClientError):
    pass


class ConnectionError(InitializationError):
    pass


class IPFSInteractionError(ClientError):
    pass


class TransactionError(ClientError):
    pass


class ContractRevertError(TransactionError):
    def __init__(self, message="Transaction reverted by contract", reason=None):
        self.reason = reason
        super().__init__(f"{message}: {reason}" if reason else message)


class CryptographyError(ClientError):
    pass


class IndexManagementError(ClientError):
    pass