"""Jeedom JSON-RPC service handler."""
import json
import time
import requests

from ..crypto import CryptoManager
from .. import config


class JeedomService:
    """Handles requests to Jeedom JSON-RPC API."""
    
    def __init__(self, crypto_manager: CryptoManager):
        """
        Initialize Jeedom service handler.
        
        Args:
            crypto_manager: CryptoManager instance for encryption operations
        """
        self.crypto = crypto_manager
    
    def handle_request(self, payload: dict) -> bytes:
        """
        Forward request to Jeedom JSON-RPC API.

        Args:
            payload: Decrypted request payload

        Returns:
            Encrypted response from Jeedom
        """
        # Build JSON-RPC 2.0 payload
        jsonrpc_payload = {
            "jsonrpc": "2.0",
            "method": payload["jsonrpc"],
            "params": {
                "apikey": payload["apikey"]
            }
        }

        # Add optional params if provided
        if "params" in payload:
            jsonrpc_payload["params"].update(payload["params"])

        # Get endpoint from payload or use default
        endpoint = payload.get("endpoint", "/core/api/jeeApi.php")

        # Forward to Jeedom with JSON-RPC 2.0 POST request
        resp = requests.post(
            url=config.JEEDOM_URL + endpoint,
            json=jsonrpc_payload,
            headers={"Content-Type": "application/json"},
            timeout=30
        )

        # Build response payload
        try:
            body = resp.json()
        except Exception:
            # If response is not JSON, return as text
            body = resp.text

        response_payload = {
            "status": resp.status_code,
            "body": body,
            "timestamp": int(time.time())
        }

        return self.crypto.encrypt(response_payload)
