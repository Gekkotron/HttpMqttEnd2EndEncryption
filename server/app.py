"""Flask application factory and routes."""
import base64
import time
from flask import Flask, request, Response, stream_with_context

from .crypto import CryptoManager
from .gateway import GatewayHandler
from .key_manager import load_or_generate_secret_key
from .services.mqtt_service import MQTTService
from .services.mqtt_sse_service import MQTTSSEService
from . import config


def create_app() -> Flask:
    """
    Create and configure the Flask application.
    
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    
    # Load or generate secret key
    secret_key = load_or_generate_secret_key(config.SECRET_KEY_FILE)

    # Initialize crypto manager and service handlers
    crypto_manager = CryptoManager(secret_key)
    gateway_handler = GatewayHandler(crypto_manager)
    mqtt_service = MQTTService(crypto_manager)
    mqtt_sse_service = MQTTSSEService(crypto_manager)

    # Register routes
    @app.route("/gateway", methods=["POST"])
    def gateway():
        """Gateway endpoint for encrypted HTTP requests."""
        return gateway_handler.handle_request()

    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint."""
        return {"status": "ok", "version": "1.0.0"}, 200

    @app.route("/mqtt/publish", methods=["POST"])
    def mqtt_publish():
        """
        MQTT publish endpoint for encrypted requests.

        Expects encrypted payload with:
        - topic: MQTT topic to publish to
        - message: Message to publish
        - broker_host: (optional) MQTT broker hostname
        - broker_port: (optional) MQTT broker port
        - username: (optional) MQTT username
        - password: (optional) MQTT password
        - qos: (optional) Quality of Service level
        - retain: (optional) Retain flag
        """
        try:
            # Decrypt request
            encrypted_request = base64.b64decode(request.data)
            payload = crypto_manager.decrypt(encrypted_request)

            # Validate timestamp
            timestamp = payload.get("timestamp")
            if timestamp is None or abs(time.time() - timestamp) > config.MAX_AGE_SECONDS:
                error_payload = {
                    "status": 403,
                    "body": {"error": "Request expired"},
                    "timestamp": int(time.time())
                }
                encrypted_error = base64.b64encode(crypto_manager.encrypt(error_payload))
                return Response(encrypted_error, mimetype="application/octet-stream")

            # Forward to MQTT service
            response = mqtt_service.handle_request(payload)

            # Return encrypted response
            encrypted_response = base64.b64encode(response)
            return Response(
                encrypted_response,
                mimetype="application/octet-stream"
            )

        except Exception as e:
            error_payload = {
                "status": 500,
                "body": {"error": str(e)},
                "timestamp": int(time.time())
            }
            encrypted_error = base64.b64encode(crypto_manager.encrypt(error_payload))
            return Response(encrypted_error, mimetype="application/octet-stream")

    @app.route("/mqtt/subscribe", methods=["POST"])
    def mqtt_subscribe():
        """
        SSE endpoint for subscribing to MQTT topics.

        Expects encrypted payload with:
        - topic: MQTT topic to subscribe to
        - broker_host: (optional) MQTT broker hostname
        - broker_port: (optional) MQTT broker port
        - username: (optional) MQTT username
        - password: (optional) MQTT password
        - qos: (optional) Quality of Service level
        """
        try:
            # Decrypt request
            encrypted_request = base64.b64decode(request.data)
            payload = crypto_manager.decrypt(encrypted_request)

            # Create SSE stream
            def generate():
                return mqtt_sse_service.subscribe_stream(payload)

            return Response(
                stream_with_context(generate()),
                mimetype="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "X-Accel-Buffering": "no",
                    "Connection": "keep-alive"
                }
            )

        except Exception as e:
            return {"error": str(e)}, 400

    return app


def run_server():
    """Run the Flask development server."""
    app = create_app()
    print(f"Starting server on {config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT)


if __name__ == "__main__":
    run_server()
