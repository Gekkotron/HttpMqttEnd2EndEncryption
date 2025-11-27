"""Gateway route handler for encrypted HTTP requests."""
import base64
import json
import time
from flask import request, Response
from typing import Tuple

from .crypto import CryptoManager
from .services.http_service import HttpService
from . import config


class GatewayHandler:
    """Handles gateway requests with encryption/decryption for HTTP."""

    def __init__(self, crypto_manager: CryptoManager):
        """
        Initialize gateway handler.

        Args:
            crypto_manager: CryptoManager instance for encryption operations
        """
        self.crypto = crypto_manager
        self.http_service = HttpService(crypto_manager)

    def handle_request(self) -> Tuple[bytes, int]:
        """
        Handle encrypted gateway request for HTTP.

        Returns:
            Tuple of (encrypted response, status code)
        """
        try:
            # Decrypt request
            encrypted_request = base64.b64decode(request.data)
            payload = self.crypto.decrypt(encrypted_request)

            # Validate timestamp
            if not self._validate_timestamp(payload.get("timestamp")):
                return self._encrypt_error("Request expired"), 200

            # Forward to HTTP service
            response = self.http_service.handle_request(payload)

            # Encrypt and return response
            encrypted_response = base64.b64encode(response)
            return Response(
                encrypted_response,
                mimetype="application/octet-stream"
            )

        except Exception as e:
            return self._encrypt_error(str(e)), 200

    def _validate_timestamp(self, timestamp: int) -> bool:
        """
        Validate request timestamp to prevent replay attacks.

        Args:
            timestamp: Request timestamp in seconds

        Returns:
            True if timestamp is valid, False otherwise
        """
        if timestamp is None:
            return False
        return abs(time.time() - timestamp) <= config.MAX_AGE_SECONDS
    
    def _encrypt_error(self, message: str) -> bytes:
        """
        Create encrypted error response.
        
        Args:
            message: Error message
            
        Returns:
            Encrypted error response
        """
        error_payload = {
            "status": 403,
            "body": json.dumps({"error": message}),
            "timestamp": int(time.time())
        }
        return base64.b64encode(self.crypto.encrypt(error_payload))
