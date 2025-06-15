# encryption_utils.py
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Function to derive a key from a password and salt (used for Master Password -> MPDK)
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # 256 bits for AES-256
        salt=salt,
        iterations=100000, # Increased iterations for better security
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

# New: Function to encrypt the Vault Key using the Master Password Derived Key (MPDK)
def encrypt_vault_key(vault_key_bytes, mpdk_bytes):
    iv = os.urandom(16) # AES block size
    cipher = Cipher(algorithms.AES(mpdk_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 padding for the 32-byte vault key
    pad_len = 16 - (len(vault_key_bytes) % 16)
    padded_vault_key = vault_key_bytes + bytes([pad_len]) * pad_len

    encrypted_vk = encryptor.update(padded_vault_key) + encryptor.finalize()

    return {
        'ciphertext': base64.b64encode(encrypted_vk).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8')
    }

# New: Function to decrypt the Vault Key using the Master Password Derived Key (MPDK)
def decrypt_vault_key(encrypted_vk_b64, iv_b64, mpdk_bytes):
    encrypted_vk = base64.b64decode(encrypted_vk_b64)
    iv = base64.b64decode(iv_b64)

    cipher = Cipher(algorithms.AES(mpdk_bytes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_vault_key = decryptor.update(encrypted_vk) + decryptor.finalize()

    # Remove PKCS7 padding
    pad_len = padded_vault_key[-1]
    vault_key_bytes = padded_vault_key[:-pad_len]
    return vault_key_bytes # Returns bytes

# Modified: Now takes vault_key_bytes (VK) directly, not a string from MPDK
def encrypt_entry(plaintext, vault_key_bytes):
    iv = os.urandom(16) # AES block size
    cipher = Cipher(algorithms.AES(vault_key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 padding
    pad_len = 16 - (len(plaintext.encode('utf-8')) % 16)
    padded_plaintext = plaintext.encode('utf-8') + bytes([pad_len]) * pad_len

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'salt': base64.b64encode(b'').decode('utf-8'), # Still kept for consistency, but not used for key derivation here
        'iv': base64.b64encode(iv).decode('utf-8')
    }

# Modified: Now takes vault_key_bytes (VK) directly, not a string from MPDK
def decrypt_entry(ciphertext_b64, vault_key_bytes, salt_b64, iv_b64):
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)

    cipher = Cipher(algorithms.AES(vault_key_bytes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    pad_len = padded_plaintext[-1]
    plaintext = padded_plaintext[:-pad_len].decode('utf-8')
    return plaintext