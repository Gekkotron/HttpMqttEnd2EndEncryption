import subprocess
import sys

def run_test(script_name):
    print(f"\n===== Running {script_name} =====")
    result = subprocess.run([sys.executable, script_name], capture_output=True, text=True)
    # Show only the last 8 lines of output
    output_lines = result.stdout.splitlines()
    if len(output_lines) > 8:
        print(f"... (output truncated, showing last 8 of {len(output_lines)} lines) ...")
    for line in output_lines[-8:]:
        print(line)
    if result.returncode == 0:
        print(f"{script_name} completed.\n")
    else:
        print(f"{script_name} failed with exit code {result.returncode}.\n")
        print(result.stderr)

def main():
    # This script runs Jeedom, MQTT publish, and MQTT SSE subscription tests.
    # Each test script prints a summary of passed/failed tests at the end.
    # Only the last 8 lines of each test's output are shown for brevity.
    # Ensure the server is running and accessible before running these tests.
    run_test("test_client/client_jeedom_test.py")
    run_test("test_client/client_mqtt_test.py")
    run_test("test_client/client_mqtt_sse_automated_test.py")

if __name__ == "__main__":
    main()
