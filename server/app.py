"""Flask application factory and routes."""
import base64
from flask import Flask, request, Response, stream_with_context

from .crypto import CryptoManager
from .gateway import GatewayHandler
from .key_manager import load_or_generate_secret_key
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

    # Initialize crypto manager and gateway handler
    crypto_manager = CryptoManager(secret_key)
    gateway_handler = GatewayHandler(crypto_manager)
    mqtt_sse_service = MQTTSSEService(crypto_manager)
    
    # Register routes
    @app.route("/gateway", methods=["POST"])
    def gateway():
        """Gateway endpoint for encrypted requests."""
        return gateway_handler.handle_request()
    
    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint."""
        return {"status": "ok", "version": "1.0.0"}, 200

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
    app.run(host=config.HOST, port=config.PORT)


if __name__ == "__main__":
    run_server()
