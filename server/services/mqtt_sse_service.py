"""MQTT SSE subscription service handler."""
import json
import time
import queue
import threading
from typing import Generator
import paho.mqtt.client as mqtt

from ..crypto import CryptoManager
from .. import config


class MQTTSSEService:
    """Handles MQTT subscription via Server-Sent Events."""

    def __init__(self, crypto_manager: CryptoManager):
        """
        Initialize MQTT SSE service handler.

        Args:
            crypto_manager: CryptoManager instance for encryption operations
        """
        self.crypto = crypto_manager

    def subscribe_stream(self, payload: dict) -> Generator[str, None, None]:
        """
        Subscribe to MQTT topic and stream messages via SSE.

        Args:
            payload: Decrypted request payload with topic and broker details

        Yields:
            SSE formatted messages with encrypted MQTT data
        """
        # Message queue for thread-safe communication
        message_queue = queue.Queue()

        # Extract MQTT parameters
        broker_host = payload.get("broker_host", config.MQTT_BROKER_HOST)
        broker_port = payload.get("broker_port", config.MQTT_BROKER_PORT)
        topic = payload.get("topic")
        username = payload.get("username")
        password = payload.get("password")
        qos = payload.get("qos", 0)

        if not topic:
            yield self._format_sse_error("Missing required field: topic")
            return

        # Create MQTT client
        client = mqtt.Client()

        # Set up callbacks
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                client.subscribe(topic, qos=qos)
                message_queue.put({
                    "type": "connected",
                    "topic": topic,
                    "message": f"Successfully connected and subscribed to {topic}"
                })
            else:
                message_queue.put({
                    "type": "error",
                    "message": f"Connection failed with code {rc}"
                })

        def on_message(client, userdata, msg):
            try:
                # Decode payload as UTF-8
                payload_str = msg.payload.decode("utf-8")

                # Try to parse as JSON, fallback to string if invalid
                try:
                    payload_data = json.loads(payload_str)
                except json.JSONDecodeError:
                    payload_data = payload_str

                message_queue.put({
                    "type": "message",
                    "topic": msg.topic,
                    "payload": payload_data,
                    "qos": msg.qos,
                    "retain": msg.retain,
                    "timestamp": int(time.time())
                })
            except Exception as e:
                message_queue.put({
                    "type": "error",
                    "message": f"Error processing message: {str(e)}"
                })

        def on_disconnect(client, userdata, rc):
            message_queue.put({
                "type": "disconnected",
                "message": f"Disconnected from broker (code {rc})"
            })

        client.on_connect = on_connect
        client.on_message = on_message
        client.on_disconnect = on_disconnect

        # Set credentials if provided
        if username and password:
            client.username_pw_set(username, password)

        # Connect to broker in a separate thread
        try:
            client.connect(broker_host, broker_port, 60)
            client.loop_start()

            # Send keepalive and stream messages
            last_keepalive = time.time()
            keepalive_interval = 15  # seconds

            while True:
                try:
                    # Get message from queue with timeout
                    msg = message_queue.get(timeout=1)

                    # Encrypt the message
                    encrypted_msg = self._encrypt_message(msg)

                    # Format as SSE
                    yield f"data: {encrypted_msg}\n\n"

                    # If error or disconnect, stop streaming
                    if msg.get("type") in ["error", "disconnected"]:
                        break

                except queue.Empty:
                    # Send keepalive comment to prevent timeout
                    current_time = time.time()
                    if current_time - last_keepalive >= keepalive_interval:
                        yield ": keepalive\n\n"
                        last_keepalive = current_time
                    continue

        except Exception as e:
            yield self._format_sse_error(f"MQTT connection error: {str(e)}")
        finally:
            # Clean up
            client.loop_stop()
            client.disconnect()

    def _encrypt_message(self, message: dict) -> str:
        """
        Encrypt message data.

        Args:
            message: Message dictionary to encrypt

        Returns:
            Base64 encoded encrypted message
        """
        import base64
        encrypted_data = self.crypto.encrypt(message)
        return base64.b64encode(encrypted_data).decode("utf-8")

    def _format_sse_error(self, error_message: str) -> str:
        """
        Format error message as SSE event.

        Args:
            error_message: Error message text

        Returns:
            SSE formatted error message
        """
        error_data = {
            "type": "error",
            "message": error_message,
            "timestamp": int(time.time())
        }
        encrypted_error = self._encrypt_message(error_data)
        return f"data: {encrypted_error}\n\n"
