# secure_file_client/crypto.py

import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pyshamir import split, combine
import base58
import json

# Umbral imports
from umbral import pre, keys
from umbral.capsule import Capsule
from umbral.key_frag import VerifiedKeyFrag

AES_KEY_SIZE_BYTES = 32
AES_NONCE_SIZE_BYTES = 16
AES_TAG_SIZE_BYTES = 16

def generate_key(key_size_bytes: int = AES_KEY_SIZE_BYTES) -> bytes:
    return get_random_bytes(key_size_bytes)


def encrypt_data(data: bytes, key: bytes) -> bytes:
    if len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {AES_KEY_SIZE_BYTES} bytes.")
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(AES_NONCE_SIZE_BYTES))
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext


def decrypt_data(encrypted_blob: bytes, key: bytes) -> bytes:
    if len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {AES_KEY_SIZE_BYTES} bytes.")

    nonce = encrypted_blob[:AES_NONCE_SIZE_BYTES]
    tag = encrypted_blob[AES_NONCE_SIZE_BYTES : AES_NONCE_SIZE_BYTES + AES_TAG_SIZE_BYTES]
    ciphertext = encrypted_blob[AES_NONCE_SIZE_BYTES + AES_TAG_SIZE_BYTES:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e:
        raise ValueError("Decryption failed. Data may be corrupt or key is incorrect.") from e


def split_key_into_shares(key: bytes, threshold: int, num_shares: int) -> list[str]:
    if len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {AES_KEY_SIZE_BYTES} bytes for Shamir splitting.")
        
    shares = split(key, num_shares, threshold)
    
    return [share.hex() for share in shares]


def reconstruct_key_from_shares(shares: list[str]) -> bytes:
    if not shares:
        raise ValueError("Cannot reconstruct key from an empty list of shares.")

    try:
        shares_as_bytes = [bytes.fromhex(share) for share in shares]
        reconstructed_key = combine(shares_as_bytes)
        return reconstructed_key
    except Exception as e:
        raise ValueError("Key reconstruction failed. Please check your shares.") from e
    
def cid_to_bytes32(cid_string: str) -> bytes:
    if not cid_string.startswith("Qm"):
        raise ValueError("Invalid IPFS CID v0 format. Must start with 'Qm'.")
    
    try:
        multihash_bytes = base58.b58decode(cid_string)
        
        if len(multihash_bytes) != 34 or multihash_bytes[0] != 0x12 or multihash_bytes[1] != 0x20:
            raise ValueError("CID does not appear to be a standard SHA2-256 multihash.")
        
        return multihash_bytes[2:]
    except Exception as e:
        raise ValueError(f"Failed to decode CID '{cid_string}': {e}") from e


def bytes32_to_cid(ipfs_hash: bytes) -> str:
    if len(ipfs_hash) != 32:
        raise ValueError("Input must be 32 bytes.")
    multihash_prefix = b'\x12\x20'
    full_multihash = multihash_prefix + ipfs_hash
    
    cid_string = base58.b58encode(full_multihash).decode('ascii')
    
    return cid_string


def generate_umbral_keypair() -> tuple[keys.SecretKey, keys.PublicKey]:
    secret_key = keys.SecretKey.gen_key()
    public_key = secret_key.get_pubkey()
    return secret_key, public_key

def umbral_private_key_to_bytes(private_key: keys.SecretKey) -> bytes:
    return private_key.to_bytes()

def umbral_private_key_from_bytes(private_key_bytes: bytes) -> keys.SecretKey:
    return keys.SecretKey.from_bytes(private_key_bytes)

def umbral_public_key_to_bytes(public_key: keys.PublicKey) -> bytes:
    if not isinstance(public_key, keys.PublicKey):
        raise ValueError("Invalid public key type.")
    return public_key.to_bytes()

def umbral_public_key_from_bytes(public_key_bytes: bytes) -> keys.PublicKey:
    return keys.PublicKey.from_bytes(public_key_bytes)

def encrypt_file_key_with_master_key(file_key: bytes, master_key: bytes) -> bytes:
    return encrypt_data(file_key, master_key)

def decrypt_file_key_with_master_key(encrypted_file_key_blob: bytes, master_key: bytes) -> bytes:
    return decrypt_data(encrypted_file_key_blob, master_key)

def encrypt_index_content(index_data_json: dict, master_key: bytes) -> bytes:
    index_data_bytes = json.dumps(index_data_json).encode('utf-8')
    return encrypt_data(index_data_bytes, master_key)

def decrypt_index_content(encrypted_index_blob: bytes, master_key: bytes) -> dict:
    plaintext_bytes = decrypt_data(encrypted_index_blob, master_key)
    return json.loads(plaintext_bytes.decode('utf-8'))

def generate_kfrags_for_sharing(
    owner_private_key: keys.SecretKey,
    recipient_public_key: keys.PublicKey,
    signer_public_key: keys.PublicKey, 
    threshold: int = 2, 
    num_kfrags: int = 3 
) -> list[str]:
    if signer_public_key is None:
        signer_public_key = owner_private_key.get_pubkey()

    kfrags = pre.generate_kfrags(
        delegating_privkey=owner_private_key,
        receiving_pubkey=recipient_public_key,
        signer_pubkey=signer_public_key,
        threshold=threshold,
        shares=num_kfrags
    )
    return [kfrag.to_secret_bytes().hex() for kfrag in kfrags]

def get_umbral_capsule_from_package(encrypted_package_bytes: bytes) -> Capsule:
    encrypted_package = json.loads(encrypted_package_bytes)
    return Capsule.from_bytes(bytes.fromhex(encrypted_package['capsule']))

def get_umbral_ciphertext_from_package(encrypted_package_bytes: bytes) -> bytes:
    encrypted_package = json.loads(encrypted_package_bytes)
    return bytes.fromhex(encrypted_package['ciphertext'])
def umbral_encrypt(public_key: keys.PublicKey, plaintext: bytes) -> bytes:
    capsule, ciphertext = pre.encrypt(public_key, plaintext)
    
    encrypted_package = {
        "capsule": bytes(capsule).hex(),
        "ciphertext": ciphertext.hex()
    }
    return json.dumps(encrypted_package).encode('utf-8')


def umbral_decrypt_own(private_key: keys.SecretKey, encrypted_package_bytes: bytes) -> bytes:
    encrypted_package = json.loads(encrypted_package_bytes)
    capsule = Capsule.from_bytes(bytes.fromhex(encrypted_package['capsule']))
    ciphertext = bytes.fromhex(encrypted_package['ciphertext'])
    
    return pre.decrypt_original(delegating_sk=private_key, capsule=capsule, ciphertext=ciphertext)


def umbral_decrypt_reencrypted(
    recipient_private_key: keys.SecretKey, 
    delegating_public_key: keys.PublicKey,
    encrypted_package_bytes: bytes, 
    verified_kfrags_hex: list[str]
) -> bytes:
    encrypted_package = json.loads(encrypted_package_bytes)
    capsule = Capsule.from_bytes(bytes.fromhex(encrypted_package['capsule']))
    ciphertext = bytes.fromhex(encrypted_package['ciphertext'])
    
    verified_kfrags = [VerifiedKeyFrag.from_verified_bytes(bytes.fromhex(kfrag_hex)) for kfrag_hex in verified_kfrags_hex]
    
    verified_cfrags = [pre.reencrypt(capsule=capsule, kfrag=kfrag) for kfrag in verified_kfrags]
    
    return pre.decrypt_reencrypted(
        receiving_sk=recipient_private_key,
        delegating_pk=delegating_public_key,
        capsule=capsule,
        verified_cfrags=verified_cfrags,
        ciphertext=ciphertext
    )