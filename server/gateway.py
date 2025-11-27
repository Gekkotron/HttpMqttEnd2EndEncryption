"""Gateway route handler for encrypted requests."""
import base64
import json
import time
from flask import request, Response
from typing import Tuple

from .crypto import CryptoManager
from .services.jeedom_service import JeedomService
from .services.mqtt_service import MQTTService
from . import config


class GatewayHandler:
    """Handles gateway requests with encryption/decryption."""
    
    def __init__(self, crypto_manager: CryptoManager):
        """
        Initialize gateway handler.
        
        Args:
            crypto_manager: CryptoManager instance for encryption operations
        """
        self.crypto = crypto_manager
        self.jeedom_service = JeedomService(crypto_manager)
        self.mqtt_service = MQTTService(crypto_manager)
    
    def handle_request(self) -> Tuple[bytes, int]:
        """
        Handle encrypted gateway request.
        
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
            
            # Get service type (default to jeedom for backward compatibility)
            service_type = payload.get("service", "jeedom")
            
            # Route to appropriate service handler
            if service_type == "jeedom":
                response = self.jeedom_service.handle_request(payload)
            elif service_type == "mqtt":
                response = self.mqtt_service.handle_request(payload)
            else:
                return self._encrypt_error(
                    f"Unknown service: {service_type}"
                ), 200
    
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
