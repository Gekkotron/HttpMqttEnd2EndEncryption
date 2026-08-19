"""Publish health-check failure alerts to an MQTT topic.

Called by the health_check orchestrator after each check completes.
Only failures are published; a passing (or recovered) check is silent.

Topic layout:
    <HEALTH_ALERT_MQTT_TOPIC_PREFIX>/<component>
    e.g., "encryption-gateway/health/gateway",
          "encryption-gateway/health/tailscale"

Payload (JSON):
    {
      "component": "gateway",
      "status": "fail" | "config_error",
      "exit_code": 1 | 2,
      "restart_attempted": true | false,
      "timestamp": 1723456789,
      "host": "<gethostname>"
    }

Environment variables:
    MQTT_BROKER_HOST                Broker hostname (required for alerts to fire)
    MQTT_BROKER_PORT                Broker port (default: 1883)
    MQTT_USERNAME                   Optional broker username
    MQTT_PASSWORD                   Optional broker password
    HEALTH_ALERT_ENABLED            "true" | "false" | "auto" (default: auto).
                                    "auto" enables when MQTT_BROKER_HOST is set.
    HEALTH_ALERT_MQTT_TOPIC_PREFIX  Topic prefix (default: "encryption-gateway/health")
    HEALTH_ALERT_MQTT_QOS           QoS 0/1/2 (default: 1)
    HEALTH_ALERT_MQTT_RETAIN        "true"/"false" (default: false)
    HEALTH_ALERT_MQTT_TIMEOUT       Connect timeout in seconds (default: 5)
"""
import json
import os
import socket
import sys
import time

import paho.mqtt.client as mqtt

from ._env import env_int, env_str


_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}


def _bool_env(name: str, default: bool) -> bool:
    v = env_str(name, "").lower()
    if not v:
        return default
    if v in _TRUTHY:
        return True
    if v in _FALSY:
        return False
    return default


def is_enabled() -> bool:
    """Return True if alerts should fire for this invocation."""
    mode = env_str("HEALTH_ALERT_ENABLED", "auto").lower()
    if mode == "auto":
        return bool(env_str("MQTT_BROKER_HOST"))
    return mode in _TRUTHY


def publish_alert(
    component: str,
    exit_code: int,
    *,
    restart_attempted: bool = False,
    verbose: bool = True,
) -> bool:
    """Publish a failure alert for *component*. Returns True on success.

    A publish failure is non-fatal: it prints a warning and returns False,
    but never raises. Alerts are a side channel.
    """
    if exit_code == 0:
        return True
    if not is_enabled():
        return True

    host = env_str("MQTT_BROKER_HOST")
    if not host:
        if verbose:
            print("[alert] MQTT_BROKER_HOST not set, skipping publish", file=sys.stderr)
        return False

    port = env_int("MQTT_BROKER_PORT", 1883)
    username = env_str("MQTT_USERNAME") or None
    password = env_str("MQTT_PASSWORD") or None

    prefix = env_str("HEALTH_ALERT_MQTT_TOPIC_PREFIX", "encryption-gateway/health").rstrip("/")
    qos = env_int("HEALTH_ALERT_MQTT_QOS", 1)
    retain = _bool_env("HEALTH_ALERT_MQTT_RETAIN", False)
    timeout = env_int("HEALTH_ALERT_MQTT_TIMEOUT", 5)

    topic = f"{prefix}/{component}"
    status = "config_error" if exit_code == 2 else "fail"
    payload = json.dumps({
        "component": component,
        "status": status,
        "exit_code": exit_code,
        "restart_attempted": restart_attempted,
        "timestamp": int(time.time()),
        "host": socket.gethostname(),
    })

    client = mqtt.Client()
    if username and password:
        client.username_pw_set(username, password)

    try:
        client.connect(host, port, timeout)
        info = client.publish(topic, payload, qos=qos, retain=retain)
        # For qos>0, wait_for_publish confirms the broker acked before disconnect.
        info.wait_for_publish(timeout=timeout)
        client.disconnect()
    except (OSError, socket.gaierror, socket.timeout, ValueError) as exc:
        if verbose:
            print(f"[alert] MQTT publish to {host}:{port} failed: {exc}", file=sys.stderr)
        return False

    if info.rc != mqtt.MQTT_ERR_SUCCESS:
        if verbose:
            print(f"[alert] MQTT publish returned rc={info.rc}", file=sys.stderr)
        return False

    if verbose:
        print(f"[alert] published to {topic} (qos={qos}, retain={retain})")
    return True
