"""Health check for the Tailscale tunnel exposing the gateway.

Runs three checks:
  1. `tailscale status --json`   - daemon is running and node is online.
  2. `tailscale funnel status`   - funnel is active for the expected port.
  3. HTTPS GET on the funnel URL - the tunnel is reachable from outside.

Exit codes:
  0 - all checks passed
  1 - one or more checks failed
  2 - configuration error (tailscale CLI missing, invalid config, ...)

Environment variables:
  TAILSCALE_FUNNEL_URL    Public funnel URL to probe
                          (required for the remote check)
  TAILSCALE_FUNNEL_PORT   Expected port bound to the funnel (default: 10000)
  TAILSCALE_BIN           tailscale binary path (default: tailscale)
  HEALTH_TIMEOUT          Per-request timeout in seconds (default: 10)
  TAILSCALE_RESTART_CMD   Shell command used by restart() to re-arm the funnel.
                          Default: './run_tailscale.sh' (which uses sudo internally).
                          Passwordless sudo required for headless use.
"""
import json
import os
import shutil
import subprocess
import sys

import requests
from dotenv import load_dotenv


def _run_tailscale(bin_path: str, args: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            [bin_path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return 127, "", f"{bin_path} not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", f"{bin_path} {' '.join(args)} timed out"
    return result.returncode, result.stdout, result.stderr


def check_daemon(bin_path: str) -> tuple[bool, str]:
    code, out, err = _run_tailscale(bin_path, ["status", "--json"])
    if code != 0:
        return False, f"tailscale status failed (exit {code}): {err.strip() or out.strip()}"

    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        return False, f"malformed status JSON: {exc}"

    backend_state = data.get("BackendState")
    self_node = data.get("Self") or {}
    online = self_node.get("Online")
    hostname = self_node.get("HostName", "?")

    if backend_state != "Running":
        return False, f"BackendState={backend_state}"
    if not online:
        return False, f"self node offline (host={hostname})"

    return True, f"daemon Running, self={hostname} online"


def check_funnel(bin_path: str, expected_port: int) -> tuple[bool, str]:
    code, out, err = _run_tailscale(bin_path, ["funnel", "status"])
    if code != 0:
        # `funnel status` exits non-zero when nothing is served.
        combined = (err + out).strip() or "no funnel configured"
        return False, f"funnel not active: {combined[:160]}"

    text = out.strip()
    if not text:
        return False, "funnel status is empty"

    port_token = f":{expected_port}"
    if port_token not in text:
        preview = text.replace("\n", " | ")[:160]
        return False, f"port {expected_port} not exposed by funnel ({preview})"

    return True, f"funnel exposes port {expected_port}"


def check_remote(url: str, timeout: float) -> tuple[bool, str]:
    if not url:
        return False, "TAILSCALE_FUNNEL_URL is not set"

    probe_url = url.rstrip("/") + "/health"
    try:
        resp = requests.get(probe_url, timeout=timeout)
    except requests.RequestException as exc:
        return False, f"unreachable: {exc}"

    if resp.status_code != 200:
        return False, f"HTTP {resp.status_code} on {probe_url}"

    return True, f"reachable via {probe_url}"


DEFAULT_RESTART_CMD = "./run_tailscale.sh"


def restart(verbose: bool = True) -> tuple[bool, str]:
    """Run the configured restart command for the Tailscale funnel.

    By default this re-executes ``run_tailscale.sh`` from the repository root,
    which itself does ``sudo tailscale funnel off`` followed by
    ``sudo tailscale funnel -bg <port>``.
    """
    cmd = os.getenv("TAILSCALE_RESTART_CMD", DEFAULT_RESTART_CMD)

    if verbose:
        print(f"[tailscale] restarting via: {cmd}")

    # `&&` chaining requires a shell; the command is operator-supplied via env,
    # not user input, so shell=True is acceptable here.
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return False, "restart command timed out after 30s"

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:200]
        return False, f"restart exited {result.returncode}: {detail}"

    return True, "restart command succeeded"


def run(verbose: bool = True) -> int:
    """Run the tailscale health check. Returns a process exit code."""
    load_dotenv()

    bin_path = os.getenv("TAILSCALE_BIN", "tailscale")
    expected_port = int(os.getenv("TAILSCALE_FUNNEL_PORT", "10000"))
    funnel_url = os.getenv("TAILSCALE_FUNNEL_URL", "").strip()
    timeout = float(os.getenv("HEALTH_TIMEOUT", "10"))

    if verbose:
        print(f"[tailscale] using bin={bin_path}, expected port={expected_port}")

    if shutil.which(bin_path) is None:
        print(f"[tailscale] CONFIG ERROR: '{bin_path}' not found on PATH")
        return 2

    checks = [
        ("daemon status", lambda: check_daemon(bin_path)),
        ("funnel status", lambda: check_funnel(bin_path, expected_port)),
        ("remote probe", lambda: check_remote(funnel_url, timeout)),
    ]

    failed = 0
    for name, run_check in checks:
        ok, detail = run_check()
        marker = "PASS" if ok else "FAIL"
        if verbose:
            print(f"[tailscale] {marker} {name}: {detail}")
        if not ok:
            failed += 1

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
