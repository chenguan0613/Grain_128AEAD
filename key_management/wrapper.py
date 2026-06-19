import os
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


class KeyManager:
    def __init__(self):
        self.iterations = 600000

    @staticmethod
    def generate_random_key_hex():
        return secrets.token_hex(16)

    def wrap_key(
        self,
        password_str,
        grain_key_hex,
        ad_data,
        ad_is_hex=False,
        custom_salt_hex="",
        custom_iterations="",
        custom_nonce_hex="",
    ):
        # Derive a key from the password
        if ad_is_hex:
            ad_bytes = bytes.fromhex(ad_data.replace("0x", ""))
        else:
            ad_bytes = ad_data.encode("utf-8")
        # Salt
        if custom_salt_hex:
            salt = bytes.fromhex(custom_salt_hex.replace("0x", ""))
        else:
            salt = os.urandom(16)
        # Nonce
        if custom_nonce_hex:
            nonce = bytes.fromhex(custom_nonce_hex.replace("0x", ""))
        else:
            nonce = os.urandom(12)
        # iteration
        if custom_iterations:
            iterations_to_use = int(custom_iterations)
        else:
            iterations_to_use = self.iterations

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=salt,
            iterations=iterations_to_use,
        )
        # KDF Key Derivation: Using the input cipher, salt, and number of iterations, derive a wrapper key for AES encryption
        key_wrap = kdf.derive(password_str.encode("utf-8"))
        print(f"\nDerived Wrapping Key (K_wrap): {key_wrap.hex()}\n")
        grain_key_bytes = bytes.fromhex(grain_key_hex.replace("0x", ""))
        aesccm = AESCCM(key_wrap)
        # Encrypt and generate MAC
        encrypted_data = aesccm.encrypt(nonce, grain_key_bytes, ad_bytes)
        encrypted_key = encrypted_data[:-16]
        mac = encrypted_data[-16:]
        # Return wrapped key as JSON string
        return {
            "salt": salt.hex(),
            "iterations": iterations_to_use,
            "nonce": nonce.hex(),
            "mac": mac.hex(),
            "encrypted_key": encrypted_key.hex(),
        }

    def unwrap_key(self, password_str, key_file_data, ad_data, ad_is_hex=False):
        # Extract parameters from the key file data
        if ad_is_hex:
            ad_bytes = bytes.fromhex(ad_data.replace("0x", ""))
        else:
            ad_bytes = ad_data.encode("utf-8")

        salt = bytes.fromhex(key_file_data["salt"])
        iterations = key_file_data["iterations"]
        nonce = bytes.fromhex(key_file_data["nonce"])
        mac = bytes.fromhex(key_file_data["mac"])
        encrypted_key = bytes.fromhex(key_file_data["encrypted_key"])
        # Using the same Salt and number of iterations, derive K_wrap again from the user-entered password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=salt,
            iterations=iterations,
        )
        key_wrap = kdf.derive(password_str.encode("utf-8"))
        encrypted_data = encrypted_key + mac
        aesccm = AESCCM(key_wrap)
        # Perform decryption and authentication
        try:
            grain_key_bytes = aesccm.decrypt(nonce, encrypted_data, ad_bytes)
            return grain_key_bytes.hex()
        except Exception as e:
            raise ValueError("Authentication Failed: Incorrect password or AD")
