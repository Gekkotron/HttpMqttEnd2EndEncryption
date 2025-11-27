"""Encryption and decryption utilities using AES-GCM."""
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoManager:
    """Manages encryption and decryption operations."""
    
    def __init__(self, secret_key: bytes):
        """
        Initialize crypto manager with a secret key.
        
        Args:
            secret_key: 32-byte secret key for AES-GCM encryption
        """
        self.secret_key = secret_key
        self.aesgcm = AESGCM(secret_key)
    
    def encrypt(self, data: dict) -> bytes:
        """
        Encrypt dictionary data using AES-GCM.
        
        Args:
            data: Dictionary to encrypt
            
        Returns:
            Encrypted data as bytes (nonce + ciphertext)
        """
        nonce = os.urandom(12)
        plaintext = json.dumps(data).encode()
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    
    def decrypt(self, data: bytes) -> dict:
        """
        Decrypt AES-GCM encrypted data.
        
        Args:
            data: Encrypted data (nonce + ciphertext)
            
        Returns:
            Decrypted data as dictionary
        """
        nonce, ciphertext = data[:12], data[12:]
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext)
