import os
import json
import requests
import hashlib
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from umbral import pre, keys, signing
from importlib import resources
from . import constants, crypto, exceptions
from .offchain.index_manager import IndexManager

class Web3Client:
    def __init__(self, private_key: str, rpc_url: str, contract_address: str, pinata_jwt: str):
        if not all([rpc_url, contract_address, private_key, pinata_jwt]):
            raise exceptions.InitializationError("RPC URL, contract address, private key, or Pinata JWT is missing.")
        self.pinata_jwt = pinata_jwt
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        if not self.w3.is_connected():
            raise exceptions.ConnectionError("Failed to connect to the blockchain RPC.")
        self.account = self.w3.eth.account.from_key(private_key)
        self.w3.eth.default_account = self.account.address
        try:
            abi_file_path = resources.files('client').joinpath('abi.json')
            with abi_file_path.open('r') as f: contract_abi = json.load(f)
        except (FileNotFoundError, AttributeError):
            raise exceptions.InitializationError("Could not load the bundled abi.json file.")
        self.contract = self.w3.eth.contract(address=self.w3.to_checksum_address(contract_address), abi=contract_abi)
        print(f"✅ Client initialized successfully.\n   - Account: {self.account.address}\n   - Contract: {self.contract.address}")
        self.session_master_key = None
        self.session_umbral_private_key = None

    def _send_transaction(self, function_call, value=0):
        try:
            gas_estimate = function_call.estimate_gas({'from': self.account.address, 'value': value})
            transaction = function_call.build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': int(gas_estimate * 1.3),
                'gasPrice': self.w3.eth.gas_price,
                'value': value
            })
            signed_tx = self.w3.eth.account.sign_transaction(transaction, self.account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            print(f"   - Transaction sent. Hash: {tx_hash.hex()}. Waiting for confirmation...")
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            if tx_receipt.status == 0:
                raise exceptions.ContractRevertError("Transaction failed and was reverted by the contract.")
            print(f"   - Transaction confirmed in block: {tx_receipt.blockNumber}")
            return tx_receipt
        except ValueError as e:
            raise exceptions.ContractRevertError(f"Transaction reverted: {e}") from e
        except Exception as e:
            raise exceptions.TransactionError(f"An unexpected error occurred: {e}") from e
    


    def login_user(self, shares: list[str]):
        print("Logging in user...")
        try:
            self.session_master_key = crypto.reconstruct_key_from_shares(shares)
            print("✅ Master key successfully reconstructed.")
            umbral_key_hash = self.contract.functions.encryptedUmbralKeyHashes(self.account.address).call()
            if umbral_key_hash == b'\x00' * 32:
                raise exceptions.ClientError("Could not find an Umbral key for this account.")
            umbral_key_cid = crypto.bytes32_to_cid(umbral_key_hash)
            encrypted_umbral_key = self.download_from_ipfs(umbral_key_cid)
            umbral_key_bytes = crypto.decrypt_data(encrypted_umbral_key, self.session_master_key)
            self.session_umbral_private_key = keys.SecretKey.from_bytes(umbral_key_bytes)
            print("✅ Umbral key successfully decrypted. User is logged in.")
        except Exception as e:
            self.session_master_key = None
            self.session_umbral_private_key = None
            raise exceptions.CryptographyError(f"Login failed. Error: {e}") from e
            
    def get_logged_in_address(self) -> str: return self.account.address
    
    def get_my_umbral_public_key(self) -> str:
        """Returns the user's Umbral public key, needed for others to grant them access."""
        if not self.session_umbral_private_key:
            raise exceptions.ClientError("User is not logged in or Umbral key is not set.")
     
        return bytes(self.session_umbral_private_key.public_key()).hex()

    def register_file(self, ipfs_cid: str, price: int, is_encrypted: bool, mode: int, is_index: bool, ext: str) -> int:
        function_call = self.contract.functions.registerFile(ipfs_cid, price, is_encrypted, mode, is_index, ext)
        tx_receipt = self._send_transaction(function_call)
        try:
            logs = self.contract.events.FileRegistered().process_receipt(tx_receipt)
            return logs[0]['args']['fileId']
        except (IndexError, KeyError):
            raise exceptions.TransactionError("Could not find FileRegistered event.")
            
    def set_encrypted_file_key(self, file_id: int, encrypted_key: bytes):
        function_call = self.contract.functions.setEncryptedFileKey(file_id, encrypted_key)
        self._send_transaction(function_call)

    def set_master_index(self, index_name: str, file_id: int, integrity_hash: bytes):
        function_call = self.contract.functions.setMasterIndex(index_name, file_id, integrity_hash)
        self._send_transaction(function_call)
        
    def request_access(self, file_id: int):
        function_call = self.contract.functions.requestAccess(file_id)
        self._send_transaction(function_call)

    def approve_access_request(self, file_id: int, user_address: str):
        checksum_address = self.w3.to_checksum_address(user_address)
        function_call = self.contract.functions.approveAccessRequest(file_id, checksum_address)
        self._send_transaction(function_call)
        
    def deny_access_request(self, file_id: int, user_address: str):
        checksum_address = self.w3.to_checksum_address(user_address)
        function_call = self.contract.functions.denyAccessRequest(file_id, checksum_address)
        self._send_transaction(function_call)

    def purchase_file(self, file_id: int, price_in_wei: int):
        function_call = self.contract.functions.purchaseFile(file_id)
        self._send_transaction(function_call, value=price_in_wei)

    def put_key_for_other_user(self, file_id: int, user_address: str, key_location_cid: str):
        checksum_address = self.w3.to_checksum_address(user_address)
        function_call = self.contract.functions.putKeyForOtherUser(file_id, checksum_address, key_location_cid)
        self._send_transaction(function_call)
        
    def remove_file(self, file_id: int):
        function_call = self.contract.functions.removeFile(file_id)
        self._send_transaction(function_call)

    def get_master_index_pointer(self, user_address: str, index_name: str) -> dict:
        try:
            pointer_tuple = self.contract.functions.getMasterIndex(self.w3.to_checksum_address(user_address), index_name).call()
            return {"fileId": pointer_tuple[0], "integrityHash": pointer_tuple[1]}
        except Exception as e:
            raise exceptions.ClientError(f"Could not read master index: {e}")
            
    def get_file_metadata(self, file_id: int) -> dict:
        try:
            meta_tuple = self.contract.functions.getFileMetadata(file_id).call()
            return {
                "owner": meta_tuple[0], "ipfsCID": meta_tuple[1], "price": meta_tuple[2],
                "isEncrypted": meta_tuple[3], "mode": meta_tuple[4], "isIndex": meta_tuple[5],
                "isDeleted": meta_tuple[6], "fileExtension": meta_tuple[7]
            }
        except Exception as e:
            raise exceptions.ClientError(f"Could not read file metadata for ID {file_id}: {e}")

    def get_my_encrypted_key(self, file_id: int) -> bytes:
        try:
            return self.contract.functions.getMyEncryptedKey(file_id).call({'from': self.account.address})
        except Exception as e:
            raise exceptions.ClientError(f"Could not retrieve encrypted key: {e}")

    def check_access_rights(self, file_id: int, user_address: str) -> bool:
        return self.contract.functions.accessRights(file_id, self.w3.to_checksum_address(user_address)).call()

    def get_key_location(self, file_id: int, user_address: str) -> str:
        return self.contract.functions.grantedKeyLocations(file_id, self.w3.to_checksum_address(user_address)).call()

    def get_total_files(self) -> int: return self.contract.functions.getTotalFiles().call()
    
    def upload_to_ipfs(self, data: bytes) -> str:
        print("Uploading data to IPFS via Pinata...")
        headers = {"Authorization": f"Bearer {self.pinata_jwt}"}
        try:
            response = requests.post("https://api.pinata.cloud/pinning/pinFileToIPFS", files={"file": data}, headers=headers)
            response.raise_for_status()
            cid = response.json()["IpfsHash"]
            print(f"✅ Successfully pinned to IPFS. CID: {cid}")
            return cid
        except requests.exceptions.RequestException as e:
            raise exceptions.IPFSInteractionError(f"Failed to upload to IPFS: {e}")

    def download_from_ipfs(self, cid: str) -> bytes:
        print(f"Downloading data from IPFS for CID: {cid}...")
        gateway_url = f"https://gateway.pinata.cloud/ipfs/{cid}"
        try:
            response = requests.get(gateway_url, timeout=60)
            response.raise_for_status()
            print("✅ Data downloaded successfully.")
            return response.content
        except requests.exceptions.RequestException as e:
            raise exceptions.IPFSInteractionError(f"Failed to download from IPFS: {e}")

    def is_first_time_user(self) -> bool:
        pointer = self.get_master_index_pointer(self.account.address, constants.INDEX_NAME_PRIVATE)
        return pointer['fileId'] == 0

    def initialize_all_indexes(self):
        if not self.session_master_key:
            raise exceptions.ClientError("User must be logged in to initialize indexes.")
        print("Initializing all user indexes on-chain...")
        for index_name in [constants.INDEX_NAME_PRIVATE, constants.INDEX_NAME_PUBLIC, constants.INDEX_NAME_SHARED, constants.INDEX_NAME_PAID]:
            print(f"  - Initializing '{index_name}' index...")
            index_bytes = IndexManager.to_json_bytes(IndexManager.create_new_index())
            should_be_encrypted = (index_name in [constants.INDEX_NAME_PRIVATE, constants.INDEX_NAME_SHARED,constants.INDEX_NAME_PAID])
            if should_be_encrypted:
                blob_to_upload = crypto.encrypt_data(index_bytes, self.session_master_key)
            else: # Public and Paid indexes are plaintext
                blob_to_upload = index_bytes
            integrity_hash = hashlib.sha256(blob_to_upload).digest()
            index_cid = self.upload_to_ipfs(blob_to_upload)
            if index_name==constants.INDEX_NAME_PRIVATE:
                file_id = self.register_file(index_cid, 0, should_be_encrypted, constants.AccessMode.PRIVATE, True, "json")
            elif index_name==constants.INDEX_NAME_PUBLIC:
                file_id = self.register_file(index_cid, 0, should_be_encrypted, constants.AccessMode.PUBLIC, True, "json")
            elif index_name==constants.INDEX_NAME_PAID or index_name==constants.INDEX_NAME_SHARED:
                file_id = self.register_file(index_cid, 0, should_be_encrypted, constants.AccessMode.SHARED, True, "json")
            self.set_master_index(index_name, file_id, integrity_hash)
        print("✅ All indexes initialized.")

    def _update_index_file(self, index_name: str, file_id_to_add: int, filename: str, content_hash: str):
        index_pointer = self.get_master_index_pointer(self.account.address, index_name)
        index_file_id = index_pointer['fileId']
        if index_file_id == 0:
            raise exceptions.IndexManagementError(f"Index '{index_name}' is not initialized.")
        index_metadata = self.get_file_metadata(index_file_id)
        encrypted_index_blob = self.download_from_ipfs(index_metadata['ipfsCID'])
        if hashlib.sha256(encrypted_index_blob).digest() != index_pointer['integrityHash']:
            raise exceptions.IndexManagementError("Integrity check failed!")
        print("✅ Index integrity check passed.")
        should_be_encrypted = (index_name in [constants.INDEX_NAME_PRIVATE, constants.INDEX_NAME_SHARED,constants.INDEX_NAME_PAID])
        decrypted_index_bytes = None
        if should_be_encrypted:
            if not index_metadata['isEncrypted']: # Sanity check
                raise exceptions.IndexManagementError(f"Index '{index_name}' should be encrypted but is not marked as such!")
            decrypted_index_bytes = crypto.decrypt_data(encrypted_index_blob, self.session_master_key)
        else:
            if index_metadata['isEncrypted']: # Sanity check
                raise exceptions.IndexManagementError(f"Index '{index_name}' should be plaintext but is marked as encrypted!")
            decrypted_index_bytes = encrypted_index_blob

        index_data = IndexManager.from_json_bytes(decrypted_index_bytes)
        updated_index_data = IndexManager.add_file_entry(index_data, file_id_to_add, filename, content_hash)
        updated_index_bytes = IndexManager.to_json_bytes(updated_index_data)
        
        new_blob_to_upload = None
        if should_be_encrypted:
            new_blob_to_upload = crypto.encrypt_data(updated_index_bytes, self.session_master_key)
        else:
            new_blob_to_upload = updated_index_bytes

        new_integrity_hash = hashlib.sha256(new_blob_to_upload).digest()
        new_index_cid = self.upload_to_ipfs(new_blob_to_upload)

        
        if index_name==constants.INDEX_NAME_PRIVATE:
            new_index_file_id = self.register_file(new_index_cid, 0, should_be_encrypted, constants.AccessMode.PRIVATE, True, "json")
        elif index_name==constants.INDEX_NAME_PUBLIC:
            new_index_file_id = self.register_file(new_index_cid, 0, should_be_encrypted, constants.AccessMode.PUBLIC, True, "json")
        elif index_name==constants.INDEX_NAME_PAID or index_name==constants.INDEX_NAME_SHARED:
            new_index_file_id = self.register_file(new_index_cid, 0, should_be_encrypted, constants.AccessMode.SHARED, True, "json")
        self.set_master_index(index_name, new_index_file_id, new_integrity_hash)

    def add_new_file(self, local_filepath: str, filename: str, index_name: str, price: int = 0):
        if not self.session_master_key:
            raise exceptions.ClientError("User must be logged in.")
        print(f"Starting workflow to add file '{filename}' to '{index_name}' index...")
        is_encrypted = (index_name != constants.INDEX_NAME_PUBLIC)
        mode = getattr(constants.AccessMode, index_name.upper())
        with open(local_filepath, 'rb') as f:
            file_content = f.read()
        content_hash = hashlib.sha256(file_content).hexdigest()
        original_file_key = None
        if is_encrypted:
            original_file_key = crypto.generate_key()
            encrypted_content = crypto.encrypt_data(file_content, original_file_key)
        else:
            encrypted_content = file_content
        content_cid = self.upload_to_ipfs(encrypted_content)
        file_ext = filename.split('.')[-1] if '.' in filename else ''
        new_file_id = self.register_file(content_cid, price, is_encrypted, mode, False, file_ext)
        if is_encrypted and original_file_key:
            encrypted_original_key = crypto.encrypt_data(original_file_key, self.session_master_key)
            self.set_encrypted_file_key(new_file_id, encrypted_original_key)
        self._update_index_file(index_name, new_file_id, filename, content_hash)
        print(f"✅ Successfully added '{filename}' to '{index_name}' index.")
        return new_file_id
    

    def retrieve_shared_index(self, owner_address: str, index_name: str) -> list:
        if not self.session_umbral_private_key:
            raise exceptions.ClientError("User must be logged in with their Umbral key.")
        print(f"Retrieving shared index '{index_name}' from {owner_address}...")
        
        checksum_owner = self.w3.to_checksum_address(owner_address)
        key_location_cid = self.contract.functions.indexAccessKeyLocations(checksum_owner, index_name, self.account.address).call()
        if not key_location_cid:
            raise exceptions.ClientError(f"You do not have permission to browse index '{index_name}'.")

        grant_package = json.loads(self.download_from_ipfs(key_location_cid))
        verified_kfrags_hex = grant_package['verified_kfrags']
        delegating_pubkey = keys.PublicKey.from_bytes(bytes.fromhex(grant_package['delegating_pubkey']))
        master_key_package_bytes = grant_package['master_key_package'].encode('utf-8')
        owner_master_key = crypto.umbral_decrypt_reencrypted(
            recipient_private_key=self.session_umbral_private_key,
            delegating_public_key=delegating_pubkey,
            encrypted_package_bytes=master_key_package_bytes,
            verified_kfrags_hex=verified_kfrags_hex # Pass the verified kfrags
        )
        
        index_pointer = self.get_master_index_pointer(owner_address, index_name)
        index_metadata = self.get_file_metadata(index_pointer['fileId'])
        encrypted_index_blob = self.download_from_ipfs(index_metadata['ipfsCID'])
        
        decrypted_index_bytes = crypto.decrypt_data(encrypted_index_blob, owner_master_key)
        
        index_data = IndexManager.from_json_bytes(decrypted_index_bytes)
        print("✅ Shared index successfully retrieved and decrypted.")
        return index_data.get("files", [])

    def retrieve_and_decrypt_shared_file(self, file_id: int):
        if not self.session_umbral_private_key:
            raise exceptions.ClientError("User must be logged in with their Umbral key.")
        
        print(f"Retrieving shared file {file_id}...")
        file_metadata = self.get_file_metadata(file_id)
        is_deleted=file_metadata['isDeleted']
        if is_deleted:
            raise exceptions.FileExistsError("File is deleted!")
        if not file_metadata["isEncrypted"]:
            decrypted_content = self.download_from_ipfs(file_metadata['ipfsCID'])
            print(f"✅ File {file_id} fully retrieved and decrypted successfully.")
            return decrypted_content

        if not self.check_access_rights(file_id, self.account.address):
            raise exceptions.ClientError("You do not have access rights to this file.")

        key_location_cid = self.get_key_location(file_id, self.account.address)
        if not key_location_cid:
            raise exceptions.ClientError("Access rights granted, but key has not been published.")

        grant_package = json.loads(self.download_from_ipfs(key_location_cid))
        verified_kfrags_hex = grant_package['verified_kfrags']
        delegating_pubkey = keys.PublicKey.from_bytes(bytes.fromhex(grant_package['delegating_pubkey']))
        file_key_package_bytes = grant_package['file_key_package'].encode('utf-8')
        
        original_file_key = crypto.umbral_decrypt_reencrypted(
            recipient_private_key=self.session_umbral_private_key,
            delegating_public_key=delegating_pubkey,
            encrypted_package_bytes=file_key_package_bytes,
            verified_kfrags_hex=verified_kfrags_hex
        )
        print("✅ Successfully decrypted the original file key.")
        
        encrypted_content = self.download_from_ipfs(file_metadata['ipfsCID'])
        decrypted_content = crypto.decrypt_data(encrypted_content, original_file_key)
        
        print(f"✅ File {file_id} fully retrieved and decrypted successfully.")
        return decrypted_content

    def remove_file_from_my_index(self, file_id_to_remove: int, index_name: str):
        if not self.session_master_key:
            raise exceptions.ClientError("User must be logged in to modify an index.")
        print(f"Removing file {file_id_to_remove} from index '{index_name}'...")
        
        self._update_index_file_remove_entry(index_name, file_id_to_remove)
        self.remove_file(file_id_to_remove)
        print(f"✅ Workflow complete. File {file_id_to_remove} has been removed.")

    def _update_index_file_remove_entry(self, index_name: str, file_id_to_remove: int):
        index_pointer = self.get_master_index_pointer(self.account.address, index_name)
        if index_pointer['fileId'] == 0: return None
        index_metadata = self.get_file_metadata(index_pointer['fileId'])
        old_index_cid = index_metadata['ipfsCID'] # Get the CID before we replace it

        encrypted_index_blob = self.download_from_ipfs(index_metadata['ipfsCID'])
        
        if hashlib.sha256(encrypted_index_blob).digest() != index_pointer['integrityHash']:
            raise exceptions.IndexManagementError("Integrity check failed!")

        decrypted_index_bytes = crypto.decrypt_data(encrypted_index_blob, self.session_master_key)
        index_data = IndexManager.from_json_bytes(decrypted_index_bytes)
        
        updated_index_data = IndexManager.remove_file_entry(index_data, file_id_to_remove)
        
        updated_index_bytes = IndexManager.to_json_bytes(updated_index_data)
        new_encrypted_index_blob = crypto.encrypt_data(updated_index_bytes, self.session_master_key)
        new_integrity_hash = hashlib.sha256(new_encrypted_index_blob).digest()
        
        new_index_cid = self.upload_to_ipfs(new_encrypted_index_blob)
        new_index_file_id=None
        if index_name == constants.INDEX_NAME_PUBLIC:
            new_index_file_id = self.register_file(new_index_cid, 0, False, constants.AccessMode.PUBLIC, True, "json")
        elif index_name==constants.INDEX_NAME_PAID:
            new_index_file_id = self.register_file(new_index_cid, 0, True, constants.AccessMode.SHARED, True, "json")
        elif index_name==constants.INDEX_NAME_PRIVATE:
            new_index_file_id = self.register_file(new_index_cid, 0, True, constants.AccessMode.PRIVATE, True, "json")
        elif index_name==constants.INDEX_NAME_SHARED:
            new_index_file_id = self.register_file(new_index_cid, 0, True, constants.AccessMode.SHARED, True, "json")

        self.set_master_index(index_name, new_index_file_id, new_integrity_hash)
        return old_index_cid
    def setup_new_user(self):
        master_key = crypto.generate_key()
        shares = crypto.split_key_into_shares(master_key, constants.MASTER_KEY_SSS_THRESHOLD, constants.MASTER_KEY_SSS_SHARES)
        self.session_master_key = master_key
        
        umbral_priv_key = keys.SecretKey.from_bytes(crypto.generate_key(32))
        self.session_umbral_private_key = umbral_priv_key
        umbral_pub = umbral_priv_key.public_key()
        umbral_pub_key_bytes = bytes(umbral_pub)
        restored = keys.PublicKey.from_bytes(umbral_pub_key_bytes)
        
        print("Publishing Umbral public key to on-chain directory...")
        function_call = self.contract.functions.setMyUmbralPublicKey(umbral_pub_key_bytes)
        self._send_transaction(function_call)
        
        encrypted_umbral_key = crypto.encrypt_data(umbral_priv_key.to_secret_bytes(), self.session_master_key)
        umbral_key_cid = self.upload_to_ipfs(encrypted_umbral_key)
        umbral_key_hash_bytes32 = crypto.cid_to_bytes32(umbral_key_cid)
        print(f"Storing encrypted Umbral private key pointer on-chain...")
        function_call = self.contract.functions.setEncryptedUmbralKey(umbral_key_hash_bytes32)
        self._send_transaction(function_call)
        
        print(f"✅ Onboarding complete. User only needs to save their master key shares.")
        return shares

    def reset_all_indexes(self):
        if not self.session_master_key:
            raise exceptions.ClientError("User must be logged in to reset indexes.")
        
        print("WARNING: Resetting all user indexes on-chain...")
        
        for index_name in [constants.INDEX_NAME_PRIVATE, constants.INDEX_NAME_PUBLIC, constants.INDEX_NAME_SHARED, constants.INDEX_NAME_PAID]:
            print(f"  - Resetting '{index_name}' index...")
            index_bytes = IndexManager.to_json_bytes(IndexManager.create_new_index())
            
            should_be_encrypted = (index_name in [constants.INDEX_NAME_PRIVATE, constants.INDEX_NAME_SHARED,constants.INDEX_NAME_PAID])
            
            if should_be_encrypted:
                blob_to_upload = crypto.encrypt_data(index_bytes, self.session_master_key)
            else:
                blob_to_upload = index_bytes

            integrity_hash = hashlib.sha256(blob_to_upload).digest()
            index_cid = self.upload_to_ipfs(blob_to_upload)
            
            if index_name==constants.INDEX_NAME_PRIVATE:
                file_id = self.register_file(index_cid, 0, should_be_encrypted, constants.AccessMode.PRIVATE, True, "json")
            elif index_name==constants.INDEX_NAME_PUBLIC:
                file_id = self.register_file(index_cid, 0, should_be_encrypted, constants.AccessMode.PUBLIC, True, "json")
            elif index_name==constants.INDEX_NAME_PAID or index_name==constants.INDEX_NAME_SHARED:
                file_id = self.register_file(index_cid, 0, should_be_encrypted, constants.AccessMode.SHARED, True, "json")
            self.set_master_index(index_name, file_id, integrity_hash)
        
        print("✅ All indexes have been reset to an empty state.")
    def unpin_from_ipfs(self, cid: str):
        print(f"Requesting to unpin CID: {cid} from IPFS via Pinata...")
        url = f"https://api.pinata.cloud/pinning/unpin/{cid}"
        headers = { "Authorization": f"Bearer {self.pinata_jwt}" }
        
        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
            print(f"✅ Successfully sent unpin request for CID: {cid}")
        except requests.exceptions.RequestException as e:
            print(f"⚠️  Warning: Failed to unpin from IPFS: {e}")
            raise exceptions.IPFSInteractionError(f"Failed to unpin from IPFS: {e}")
    def remove_file_from_my_index(self, file_id_to_remove: int, index_name: str):
        if not self.session_master_key:
            raise exceptions.ClientError("User must be logged in to modify an index.")
            
        print(f"Starting full deletion workflow for file {file_id_to_remove}...")
        
        try:
            file_meta_to_delete = self.get_file_metadata(file_id_to_remove)
            cid_to_unpin = file_meta_to_delete['ipfsCID']
        except Exception as e:
            print(f"Warning: Could not get metadata for file {file_id_to_remove} to unpin it. Skipping unpin. Error: {e}")
            cid_to_unpin = None

        old_index_cid = self._update_index_file_remove_entry(index_name, file_id_to_remove)
        
        print(f"✅ Off-chain index '{index_name}' updated successfully.")

        self.remove_file(file_id_to_remove)
        
        if cid_to_unpin:
            self.unpin_from_ipfs(cid_to_unpin)
        if old_index_cid:
            self.unpin_from_ipfs(old_index_cid)
        
        print(f"✅ Workflow complete. File {file_id_to_remove} has been removed.")
    def generate_new_shares_from_session_key(self) -> list[str]:
        if self.session_master_key is None:
            raise exceptions.ClientError("User must be logged in with an active master key to generate new shares.")
        
        print("Generating a new set of master key shares from the active session key...")
        
        new_shares = crypto.split_key_into_shares(
            self.session_master_key,
            constants.MASTER_KEY_SSS_THRESHOLD,
            constants.MASTER_KEY_SSS_SHARES
        )
        
        print(f"✅ New set of {len(new_shares)} shares generated.")
        return new_shares
    def grant_index_access(self, index_name: str, recipient_eth_address: str):
        if not self.session_master_key or not self.session_umbral_private_key:
            raise exceptions.ClientError("User must be logged in with both master and Umbral keys.")
        
        checksum_address = self.w3.to_checksum_address(recipient_eth_address)
        print(f"Granting access for index '{index_name}' to {checksum_address}...")
        
        print("   - Fetching recipient's public key from on-chain directory...")
        recipient_public_key_bytes = self.contract.functions.userUmbralPublicKeys(checksum_address).call()
        if not recipient_public_key_bytes:
            raise exceptions.ClientError(f"Recipient {recipient_eth_address} has not published their public key.")
        recipient_public_key = keys.PublicKey.from_bytes(recipient_public_key_bytes)
        
        owner_secret_key = self.session_umbral_private_key
        owner_public_key = owner_secret_key.public_key()
        
        owner_signer = signing.Signer(owner_secret_key)

        verified_kfrags = pre.generate_kfrags(
            delegating_sk=owner_secret_key,
            signer=owner_signer,
            receiving_pk=recipient_public_key,
            threshold=1, shares=1
        )
        master_key_package = crypto.umbral_encrypt(owner_public_key, self.session_master_key)
        
        grant_package = {
            "verified_kfrags": [bytes(vkfrag).hex() for vkfrag in verified_kfrags],
            "delegating_pubkey": bytes(owner_public_key).hex(),
            "master_key_package": master_key_package.decode('utf-8')
        }
        grant_bytes = json.dumps(grant_package).encode('utf-8')
        key_location_cid = self.upload_to_ipfs(grant_bytes)
        
        function_call = self.contract.functions.grantIndexAccess(index_name, checksum_address, key_location_cid)
        self._send_transaction(function_call)
        print(f"✅ Index access grant complete. Grant package at IPFS: {key_location_cid}")

    def grant_access_to_file(self, file_id: int, recipient_eth_address: str):
        if not self.session_master_key or not self.session_umbral_private_key:
            raise exceptions.ClientError("User must be logged in with both keys.")
        
        checksum_address = self.w3.to_checksum_address(recipient_eth_address)
        print(f"Granting access for file {file_id} to {checksum_address}...")
        
        print("   - Fetching recipient's public key from on-chain directory...")
        recipient_public_key_bytes = self.contract.functions.userUmbralPublicKeys(checksum_address).call()
        if not recipient_public_key_bytes:
            raise exceptions.ClientError(f"Recipient {recipient_eth_address} has not published their public key.")
        recipient_public_key = keys.PublicKey.from_bytes(recipient_public_key_bytes)
        
        owner_secret_key = self.session_umbral_private_key
        owner_public_key = owner_secret_key.public_key() 
        owner_signer = signing.Signer(owner_secret_key)

        verified_kfrags = pre.generate_kfrags(
            delegating_sk=owner_secret_key,
            signer=owner_signer,
            receiving_pk=recipient_public_key,
            threshold=1, shares=1
        )
        encrypted_original_key = self.get_my_encrypted_key(file_id)
        original_file_key = crypto.decrypt_data(encrypted_original_key, self.session_master_key)
        
        file_key_package = crypto.umbral_encrypt(owner_public_key, original_file_key)
        grant_package = {
            "verified_kfrags": [bytes(vkfrag).hex() for vkfrag in verified_kfrags],
            "delegating_pubkey": bytes(owner_public_key).hex(),
            "file_key_package": file_key_package.decode('utf-8')
        }   
        
        key_location_cid = self.upload_to_ipfs(json.dumps(grant_package).encode('utf-8'))
        self.put_key_for_other_user(file_id, recipient_eth_address, key_location_cid)
        print(f"✅ File access grant complete.")

    
    def request_index_access(self, owner_address: str, index_name: str):
        print(f"Sending on-chain request to browse index '{index_name}' from {owner_address}...")
        checksum_owner = self.w3.to_checksum_address(owner_address)
        function_call = self.contract.functions.requestIndexAccess(checksum_owner, index_name)
        self._send_transaction(function_call)
        print("✅ Index access request sent successfully.")

    def approve_index_access_request(self, index_name: str, requester_address: str):
        print(f"Approving on-chain request from {requester_address} for index '{index_name}'...")
        checksum_requester = self.w3.to_checksum_address(requester_address)
        function_call = self.contract.functions.approveIndexAccessRequest(index_name, checksum_requester)
        self._send_transaction(function_call)
        print("✅ Index access request approved.")

    def deny_index_access_request(self, index_name: str, requester_address: str):
        print(f"Denying on-chain request from {requester_address} for index '{index_name}'...")
        checksum_requester = self.w3.to_checksum_address(requester_address)
        function_call = self.contract.functions.denyIndexAccessRequest(index_name, checksum_requester)
        self._send_transaction(function_call)
        print("✅ Index access request denied.")

    
    def get_my_outgoing_requests(self) -> list[dict]:
        if not self.session_master_key:
            raise exceptions.ClientError("User must be logged in.")
            
        print("Scanning blockchain for your outgoing access requests...")
        early_block=self.contract.functions.getUserFileLastBlock().call()
        event_filter = self.contract.events.AccessRequested.create_filter(
            from_block=early_block,
            argument_filters={'requester': self.account.address}
        )
        all_request_logs = event_filter.get_all_entries()
        print(f"Found {len(all_request_logs)} historical outgoing request events.")
        
        outgoing_requests = []
        for log in all_request_logs:
            args = log['args']
            file_id = args['fileId']
            owner = args['owner']
            status = "Unknown"
            try:
                is_still_pending = self.contract.functions.accessRequests(file_id, self.account.address).call()
                has_access = self.check_access_rights(file_id, self.account.address)

                if is_still_pending:
                    status = "Pending"
                elif has_access:
                    status = "Approved"
                else:
                    status = "Denied or Cleared"
                    
                outgoing_requests.append({
                    "fileId": file_id,
                    "owner": owner,
                    "status": status
                })
            except Exception:
                continue # Skip if file metadata lookup fails for some reason
        
        print(f"✅ Processed {len(outgoing_requests)} outgoing requests.")
        return outgoing_requests
    
    
    def get_my_purchases(self) -> list[dict]:
        print("Scanning blockchain for your purchase history...")
        early_block=self.contract.functions.getUserFileLastBlock().call()
        event_filter = self.contract.events.FilePurchased.create_filter(
            from_block=early_block,
            argument_filters={'buyer': self.account.address}
        )
        purchase_logs = event_filter.get_all_entries()
        
        purchases = [log['args'] for log in purchase_logs]
        print(f"✅ Found {len(purchases)} purchase records.")
        return purchases

    def get_my_sales(self) -> list[dict]:
        print("Scanning blockchain for your sales history...")
        early_block=self.contract.functions.getUserFileLastBlock().call()
        event_filter = self.contract.events.FilePurchased.create_filter(from_block=early_block)
        all_sales_logs = event_filter.get_all_entries()
        print(f"Found {len(all_sales_logs)} total sales events on the contract. Filtering for yours...")
        
        my_sales = []
        for log in all_sales_logs:
            try:
                file_id = log['args']['fileId']
                meta = self.get_file_metadata(file_id)
                if meta['owner'].lower() == self.account.address.lower():
                    # This sale belongs to us
                    my_sales.append(log['args'])
            except Exception:
                continue # Skip if metadata is unreadable
        
        print(f"✅ Found {len(my_sales)} sales records belonging to you.")
        return my_sales
    def _find_index_name_for_file_id(self, owner_address: str, file_id_to_find: int) -> str | None:
        for index_name in [constants.INDEX_NAME_PUBLIC, constants.INDEX_NAME_SHARED, constants.INDEX_NAME_PAID]:
            try:
                # We can only scan indexes we can decrypt/read
                index_files = self.retrieve_index_content(owner_address, index_name)
                for file_entry in index_files:
                    if file_entry.get("fileId") == file_id_to_find:
                        return index_name
            except Exception:
                continue # Ignore errors (e.g., no access to the index)
        return None
    
    def retrieve_index_content(self, owner_address: str, index_name: str) -> list:
        is_my_own = (owner_address.lower() == self.account.address.lower())
        
        if is_my_own:
            if not self.session_master_key: raise exceptions.ClientError("Must be logged in.")
            index_pointer = self.get_master_index_pointer(owner_address, index_name)
            if index_pointer['fileId'] == 0: return []
            meta = self.get_file_metadata(index_pointer['fileId'])
            blob = self.download_from_ipfs(meta['ipfsCID'])
            decrypted_bytes=blob
            if index_name in [constants.INDEX_NAME_PAID,constants.INDEX_NAME_PRIVATE,constants.INDEX_NAME_SHARED]:
                decrypted_bytes = crypto.decrypt_data(blob, self.session_master_key)
            index_data = IndexManager.from_json_bytes(decrypted_bytes)
            return index_data.get("files", [])
        
        else:
            if index_name in [constants.INDEX_NAME_PUBLIC]:
                index_pointer = self.get_master_index_pointer(owner_address, index_name)
                if index_pointer['fileId'] == 0: return []
                meta = self.get_file_metadata(index_pointer['fileId'])
                if meta['isEncrypted']: raise exceptions.ClientError("Public index cannot be encrypted.")
                blob = self.download_from_ipfs(meta['ipfsCID'])
                index_data = IndexManager.from_json_bytes(blob)
                return index_data.get("files", [])
            elif index_name == constants.INDEX_NAME_SHARED or index_name==constants.INDEX_NAME_PAID:
                return self.retrieve_shared_index(owner_address, index_name)
            else:
                raise exceptions.ClientError("Cannot access a private index of another user.")
            
    def get_my_pending_file_requests(self, file_id: int,index_name:str) -> list[dict]:
        if not self.session_master_key:
            raise exceptions.ClientError("User must be logged in.")
        print(f"Scanning for pending requests specifically for File ID: {file_id}...")
        early_block=self.contract.functions.getUserFileLastBlock().call()
        latest_block = self.w3.eth.block_number
        all_request_logs=None
        batch_size=500
        try:
            all_request_logs = self.contract.events.AccessRequested.create_filter(
                from_block=early_block,
                argument_filters={'fileId': file_id}
            )
            all_request_logs=all_request_logs.get_all_entries()
        except:
            result=[]
            for from_chunk in range(early_block,latest_block+1, batch_size):
                start=from_chunk
                end=min(from_chunk+batch_size-1, latest_block)
                temp = self.contract.events.AccessRequested.create_filter(
                    from_block=start,
                    to_block=end,
                    argument_filters={'fileId': file_id}
                )
                temp=temp.get_all_entries()
                if not temp:
                    continue
                
                result.append(temp)
            all_request_logs=result
        if not all_request_logs:
            self.contract.functions.updateUserFileLastBlock(latest_block).call()
            print(f"Found new requests. The earliest is at block {latest_block}. Updating checkpoint...")
        else:
            earliest_new_request_block = min([log['blockNumber'] for log in all_request_logs] + [latest_block])
            
            print(f"Found new requests. The earliest is at block {earliest_new_request_block}. Updating checkpoint...")
            new_checkpoint = earliest_new_request_block - 1 if earliest_new_request_block > 0 else 0
            self.contract.functions.updateUserFileLastBlock(new_checkpoint).call()

        pending_requesters = []
        if not all_request_logs:
            print(" -> No historical requests found for this file.")
            return []

        for log in all_request_logs:
            requester = log['args']['requester']

            is_still_pending = self.contract.functions.accessRequests(file_id, requester).call()

            if is_still_pending:
                pending_requesters.append({"requester": requester})
                print(f"[DEBUG] Request from {requester} for file {file_id} is PENDING.")
            else:
                print(f"[DEBUG] Request from {requester} for file {file_id} is NOT pending (approved/denied/cleared).")

        print(f"✅ Found {len(pending_requesters)} pending requests for File ID: {file_id}.")
        return pending_requesters

    def get_my_pending_index_requests(self) -> list[dict]:
        early_block = self.contract.functions.getUserIndexLastBlock().call()
        latest_block = self.w3.eth.block_number
        all_request_logs = []

        if latest_block - early_block >= 10000:
            batch_size = 500
            for from_chunk in range(early_block, latest_block + 1, batch_size):
                start = from_chunk
                end = min(from_chunk + batch_size - 1, latest_block)
                try:
                    temp = self.contract.events.IndexAccessRequested.create_filter(
                        from_block=start,
                        to_block=end,
                        argument_filters={'owner': self.account.address}
                    )
                    batch_logs = temp.get_all_entries()
                    all_request_logs.extend(batch_logs)  # Extend the flat list
                except Exception as e:
                    print(f"Warning: Error fetching batch {start}-{end}: {e}")
                    continue
        else:
            try:
                event_filter = self.contract.events.IndexAccessRequested.create_filter(
                    from_block=early_block,
                    argument_filters={'owner': self.account.address}
                )
                all_request_logs = event_filter.get_all_entries()
            except Exception as e:
                print(f"Warning: Error fetching events: {e}")

        if not all_request_logs:
            print("No historical index request events found for this owner.")
            self.contract.functions.updateUserIndexLastBlock(latest_block).call()
            return []

        block_numbers = [log['blockNumber'] for log in all_request_logs]
        if block_numbers:
            earliest_new_request_block = min(block_numbers)
            print(f"Found new requests. The earliest is at block {earliest_new_request_block}. Updating checkpoint...")
            new_checkpoint = earliest_new_request_block - 1 if earliest_new_request_block > 0 else 0
            self.contract.functions.updateUserIndexLastBlock(new_checkpoint).call()

        pending_requests = []
        for log in all_request_logs:
            args = log['args']
            index_name = args['indexName']
            requester = args['requester']
            
            try:
                is_still_pending = self.contract.functions.indexAccessRequests(
                    self.account.address, index_name, requester
                ).call()

                if is_still_pending:
                    pending_requests.append({
                        "indexName": index_name,
                        "requester": requester
                    })
            except Exception as e:
                print(f"Warning: Error checking pending status: {e}")
                continue
        
        print(f"✅ Found {len(pending_requests)} pending index requests.")
        return pending_requests

    def get_my_outgoing_file_requests(self) -> list[dict]:
        early_block=self.contract.functions.getUserFileLastBlock().call()
        print("Scanning for MY OUTGOING file requests...")
        event_filter = self.contract.events.AccessRequested.create_filter(
            from_block=early_block,
            argument_filters={'requester': self.account.address}
        )
        all_request_logs = event_filter.get_all_entries()

        outgoing_requests = []
        if not all_request_logs:
            print("No outgoing file request events found for this requester.")
            return []

        for log in all_request_logs:
            args = log['args']
            file_id = args['fileId']
            owner = args['owner']
            
            status = "Unknown"
            try:
                is_still_pending = self.contract.functions.accessRequests(file_id, self.account.address).call()
                has_access = self.check_access_rights(file_id, self.account.address)

                if is_still_pending:
                    status = "Pending"
                elif has_access:
                    status = "Approved"
                else:
                    status = "Denied / Cleared"
                    
                outgoing_requests.append({"fileId": file_id, "owner": owner, "status": status})
            except Exception:
                continue
        
        print(f"✅ Processed {len(outgoing_requests)} outgoing file requests.")
        return outgoing_requests
        
    def get_my_outgoing_index_requests(self) -> list[dict]:
        early_block=self.contract.functions.getUserIndexLastBlock().call()
        print("Scanning for MY OUTGOING index requests...")
        event_filter = self.contract.events.IndexAccessRequested.create_filter(
            from_block=early_block,
            argument_filters={'requester': self.account.address}
        )
        all_request_logs = event_filter.get_all_entries()

        outgoing_requests = []
        if not all_request_logs:
            print("No outgoing index request events found for this requester.")
            return []

        for log in all_request_logs:
            args = log['args']
            owner = args['owner']
            index_name = args['indexName']
            
            status = "Unknown"
            try:
                is_still_pending = self.contract.functions.indexAccessRequests(owner, index_name, self.account.address).call()
                key_location = self.contract.functions.indexAccessKeyLocations(owner, index_name, self.account.address).call()

                if is_still_pending:
                    status = "Pending"
                elif key_location:
                    status = "Approved"
                else:
                    status = "Denied / Cleared"
                    
                outgoing_requests.append({"owner": owner, "indexName": index_name, "status": status})
            except Exception:
                continue
        
        print(f"✅ Processed {len(outgoing_requests)} outgoing index requests.")
        return outgoing_requests