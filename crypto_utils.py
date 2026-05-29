"""
Cryptographic utilities for AES encryption/decryption
Using AES-GCM mode for authenticated encryption
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class AESChatCrypto:
    """Handles AES encryption/decryption for chat messages"""
    
    def __init__(self, key: bytes):
        """
        Initialize with pre-shared key
        Key should be 32 bytes for AES-256
        """
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes (AES-128/192/256)")
        self.key = key
        self.backend = default_backend()
    
    @classmethod
    def generate_key(cls, size=32):
        """Generate a random AES key (32 bytes = AES-256)"""
        return os.urandom(size)
    
    @classmethod
    def key_to_string(cls, key: bytes) -> str:
        """Convert key to base64 string for storage/sharing"""
        return base64.b64encode(key).decode('utf-8')
    
    @classmethod
    def string_to_key(cls, key_str: str) -> bytes:
        """Convert base64 string back to key bytes"""
        return base64.b64decode(key_str.encode('utf-8'))
    
    def encrypt_message(self, plaintext: str) -> str:
        """
        Encrypt a message using AES-GCM
        Returns: base64 encoded (IV + ciphertext + tag)
        """
        # Generate random 12-byte IV (recommended for GCM)
        iv = os.urandom(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Encrypt the message
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        
        # Get the authentication tag
        tag = encryptor.tag
        
        # Combine IV + ciphertext + tag and encode as base64
        combined = iv + ciphertext + tag
        return base64.b64encode(combined).decode('utf-8')
    
    def decrypt_message(self, encrypted_data: str) -> str:
        """
        Decrypt a message using AES-GCM
        Expects: base64 encoded (IV + ciphertext + tag)
        """
        # Decode from base64
        combined = base64.b64decode(encrypted_data.encode('utf-8'))
        
        # Extract IV (first 12 bytes), tag (last 16 bytes), and ciphertext (middle)
        iv = combined[:12]
        tag = combined[-16:]
        ciphertext = combined[12:-16]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    
    @staticmethod
    def generate_and_save_key(filename="chat_key.key"):
        """Generate a new key and save to file"""
        key = AESChatCrypto.generate_key()
        with open(filename, 'wb') as f:
            f.write(key)
        print(f"Key saved to {filename}")
        print(f"Key (base64): {AESChatCrypto.key_to_string(key)}")
        return key
    
    @staticmethod
    def load_key_from_file(filename="chat_key.key"):
        """Load key from file"""
        with open(filename, 'rb') as f:
            return f.read()