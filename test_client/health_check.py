"""Unified entry point for the gateway and Tailscale health checks.

Usage:
    python -m test_client.health_check              # runs both (same as --all)
    python -m test_client.health_check --gateway    # HTTP gateway only
    python -m test_client.health_check --tailscale  # Tailscale only
    python -m test_client.health_check --all        # both, explicit
    python -m test_client.health_check --restart    # bounce whatever fails, then re-check
    python -m test_client.health_check --no-alert   # do not publish MQTT failure alert
    python -m test_client.health_check -q --all     # quiet, only exit code

Exit codes:
  0 - every selected check passed (after restart, if used)
  1 - one or more checks failed (or restart didn't recover them)
  2 - configuration error in one of the selected checks
      (never triggers a restart; fix the config first)

Restart behaviour (--restart):
  * Only real failures (exit 1) trigger a restart, not config errors (exit 2).
  * After restart, the check is re-run with exponential backoff:
    sleep D, check, else sleep D*F, check, ... up to N attempts.
  * The loop stops on the first PASS.
  * Only one restart command is issued per check per invocation.

Environment variables (in addition to those of the per-check modules):
  RESTART_BACKOFF_INITIAL       Seconds before the first re-check (default: 2)
  RESTART_BACKOFF_FACTOR        Multiplier applied between attempts (default: 2)
  RESTART_BACKOFF_MAX_ATTEMPTS  Maximum re-check attempts (default: 5).
                                Set to 0 to retry forever until PASS.
  RESTART_BACKOFF_MAX_DELAY     Per-attempt delay cap in seconds (default: 300).
                                Prevents runaway growth in infinite mode.

  Defaults give delays of 2s, 4s, 8s, 16s, 32s (max ~62s of waiting).
  With MAX_ATTEMPTS=0, delays follow the same sequence but plateau at
  MAX_DELAY and repeat forever until the check passes.

MQTT failure alerts:
  When a check ends in a non-zero state (including after --restart failed to
  recover), a JSON message is published to <TOPIC_PREFIX>/<component> on
  MQTT_BROKER_HOST. Recovered checks stay silent. See test_client.health_alert
  for env vars (HEALTH_ALERT_MQTT_*). Pass --no-alert to skip publishing.
"""
import argparse
import os
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_client import health_alert, health_check_gateway, health_check_tailscale  # noqa: E402


class BackoffConfig:
    """Exponential backoff settings for the post-restart re-check loop.

    max_attempts:
        Positive int  -> that many attempts, then give up.
        0 (or negative) -> retry forever until the check passes.
    max_delay:
        Per-attempt delay cap in seconds. The exponential sequence grows
        up to this ceiling and then stays there.
    """

    def __init__(self) -> None:
        self.initial = float(os.getenv("RESTART_BACKOFF_INITIAL", "2"))
        self.factor = float(os.getenv("RESTART_BACKOFF_FACTOR", "2"))
        self.max_attempts = int(os.getenv("RESTART_BACKOFF_MAX_ATTEMPTS", "5"))
        self.max_delay = float(os.getenv("RESTART_BACKOFF_MAX_DELAY", "300"))

    @property
    def infinite(self) -> bool:
        return self.max_attempts <= 0

    @property
    def budget_label(self) -> str:
        return "∞" if self.infinite else str(self.max_attempts)

    def delays(self):
        delay = self.initial
        attempt = 0
        while self.infinite or attempt < self.max_attempts:
            yield min(delay, self.max_delay)
            delay *= self.factor
            attempt += 1


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="health_check",
        description="Health checks for the HTTP encryption gateway and its Tailscale tunnel.",
    )
    parser.add_argument("--gateway", action="store_true", help="run the HTTP gateway check")
    parser.add_argument("--tailscale", action="store_true", help="run the Tailscale check")
    parser.add_argument("--all", action="store_true", help="run both checks (default)")
    parser.add_argument(
        "--restart",
        action="store_true",
        help="restart a failing component and re-check with exponential backoff",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress per-check output")
    parser.add_argument(
        "--no-alert",
        action="store_true",
        help="skip MQTT failure alert even if MQTT_BROKER_HOST is set",
    )
    return parser.parse_args(argv)


def _run_with_optional_restart(
    label: str, module, *, restart: bool, backoff: BackoffConfig, verbose: bool
) -> tuple[int, bool]:
    """Run a check module; on hard failure and --restart, bounce and re-check with backoff.

    Returns (final_exit_code, restart_attempted).
    """
    code = module.run(verbose=verbose)
    if code != 1 or not restart:
        return code, False

    if verbose:
        print(f"[{label}] failure detected — attempting restart")

    ok, detail = module.restart(verbose=verbose)
    if verbose:
        marker = "PASS" if ok else "FAIL"
        print(f"[{label}] restart {marker}: {detail}")
    if not ok:
        return 1, True

    last_code = 1
    for attempt, delay in enumerate(backoff.delays(), start=1):
        if verbose:
            print(
                f"[{label}] re-check attempt {attempt}/{backoff.budget_label} "
                f"in {delay:g}s"
            )
        time.sleep(delay)
        last_code = module.run(verbose=verbose)
        if last_code == 0:
            if verbose:
                print(f"[{label}] recovered after {attempt} attempt(s)")
            return 0, True

    # Only reachable when max_attempts is finite (infinite mode exits via PASS above).
    if verbose:
        print(f"[{label}] still failing after {backoff.max_attempts} re-check attempts")
    return last_code, True


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    run_gateway = args.gateway or args.all or (not args.gateway and not args.tailscale)
    run_tailscale = args.tailscale or args.all or (not args.gateway and not args.tailscale)

    verbose = not args.quiet
    backoff = BackoffConfig()
    alerts_enabled = not args.no_alert
    codes: list[int] = []

    if run_gateway:
        code, restart_attempted = _run_with_optional_restart(
            "gateway", health_check_gateway,
            restart=args.restart, backoff=backoff, verbose=verbose,
        )
        codes.append(code)
        if code != 0 and alerts_enabled:
            sys.stdout.flush()
            health_alert.publish_alert(
                "gateway", code,
                restart_attempted=restart_attempted, verbose=verbose,
            )
        if verbose:
            print()

    if run_tailscale:
        code, restart_attempted = _run_with_optional_restart(
            "tailscale", health_check_tailscale,
            restart=args.restart, backoff=backoff, verbose=verbose,
        )
        codes.append(code)
        if code != 0 and alerts_enabled:
            sys.stdout.flush()
            health_alert.publish_alert(
                "tailscale", code,
                restart_attempted=restart_attempted, verbose=verbose,
            )
        if verbose:
            print()

    exit_code = max(codes) if codes else 0
    if verbose:
        summary = "OK" if exit_code == 0 else ("FAIL" if exit_code == 1 else "CONFIG ERROR")
        print(f"[health_check] overall: {summary} (exit {exit_code})")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
