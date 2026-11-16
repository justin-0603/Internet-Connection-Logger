import os
import subprocess
import sys
import time
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(SCRIPT_DIR, ".env")
DEFAULT_SETTINGS = {
    "CHECK_INTERVAL_SECONDS": 5,
    "HEARTBEAT_INTERVAL_SECONDS": 60,
    "IGNORE_LOOPBACK_CONNECTIONS": True,
    "LOG_FILE_NAME": "system_tracking.log",
}


def load_settings(env_file=ENV_FILE):
    settings = DEFAULT_SETTINGS.copy()
    if not os.path.isfile(env_file):
        return settings

    with open(env_file, encoding="utf-8-sig") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(
                    f"{env_file}:{line_number}: expected KEY=VALUE"
                )

            key, value = (part.strip() for part in line.split("=", 1))
            if key not in settings:
                raise ValueError(
                    f"{env_file}:{line_number}: unknown setting {key!r}"
                )

            if key in (
                "CHECK_INTERVAL_SECONDS",
                "HEARTBEAT_INTERVAL_SECONDS",
            ):
                try:
                    value = int(value)
                except ValueError as error:
                    raise ValueError(
                        f"{env_file}:{line_number}: {key} must be an integer"
                    ) from error
                if value <= 0:
                    raise ValueError(
                        f"{env_file}:{line_number}: {key} must be greater than 0"
                    )
            elif key == "IGNORE_LOOPBACK_CONNECTIONS":
                normalized_value = value.lower()
                if normalized_value not in ("true", "false"):
                    raise ValueError(
                        f"{env_file}:{line_number}: {key} must be true or false"
                    )
                value = normalized_value == "true"
            elif not value:
                raise ValueError(
                    f"{env_file}:{line_number}: {key} must not be empty"
                )

            settings[key] = value

    return settings


SETTINGS = load_settings()
CHECK_INTERVAL_SECONDS = SETTINGS["CHECK_INTERVAL_SECONDS"]
HEARTBEAT_INTERVAL_SECONDS = SETTINGS["HEARTBEAT_INTERVAL_SECONDS"]
IGNORE_LOOPBACK_CONNECTIONS = SETTINGS["IGNORE_LOOPBACK_CONNECTIONS"]
LOG_FILE_NAME = SETTINGS["LOG_FILE_NAME"]
LOG_FILE = os.path.join(SCRIPT_DIR, LOG_FILE_NAME)
REQUIREMENTS_FILE = os.path.join(SCRIPT_DIR, "requirements.txt")


def install_requirements():
    if not os.path.isfile(REQUIREMENTS_FILE):
        return

    with open(REQUIREMENTS_FILE, encoding="utf-8") as requirements:
        has_requirements = any(
            line.strip() and not line.lstrip().startswith("#")
            for line in requirements
        )

    if has_requirements:
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "-r",
                REQUIREMENTS_FILE,
            ]
        )


# Write timestamped messages to log file and console
def log_message(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] {msg}"
    print(formatted_msg)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(formatted_msg + "\n")


# Retrieve current active ESTABLISHED TCP connections cleanly without findstr pipe
def get_active_connections():
    try:
        cmd = "netstat -ano -p tcp"
        output = subprocess.check_output(cmd, shell=True, text=True, timeout=3)

        established_lines = []
        for line in output.splitlines():
            if "ESTABLISHED" in line:
                established_lines.append(line)
        return established_lines
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []


# Retrieve the process executable name matching the given PID
def get_process_name(pid):
    try:
        cmd = f'tasklist /FI "PID eq {pid}" /FO CSV /NH'
        output = subprocess.check_output(
            cmd, shell=True, text=True, timeout=3
        ).strip()
        if output and not output.startswith("INFO:"):
            process_name = output.split(",")[0].replace('"', "")
            return process_name
    except Exception:
        pass
    return "Unknown"


# Main tracking loop for recording established TCP connections
def main():
    log_message("Tracker started. Monitoring established TCP connections...")

    seen_connections = set()
    last_heartbeat_time = time.time()

    try:
        while True:
            # Print a status pulse every 60 seconds so you know it's not dead
            if (
                time.time() - last_heartbeat_time
                >= HEARTBEAT_INTERVAL_SECONDS
            ):
                log_message("[STATUS] Tracker is actively running...")
                last_heartbeat_time = time.time()

            connections = get_active_connections()
            current_connections = set()

            for line in connections:
                parts = line.split()
                if len(parts) >= 5:
                    proto, local_addr, foreign_addr, state, pid = parts[:5]

                    if (
                        IGNORE_LOOPBACK_CONNECTIONS
                        and foreign_addr.startswith("127.0.0.1")
                    ):
                        continue

                    conn_id = f"{foreign_addr} (PID: {pid})"
                    current_connections.add(conn_id)

                    # Log newly discovered connections
                    if conn_id not in seen_connections:
                        proc_name = get_process_name(pid)
                        log_message(
                            f"[NEW CONNECTION] Local: {local_addr} -> Foreign:"
                            f" {foreign_addr} | Process: {proc_name} (PID:"
                            f" {pid})"
                        )

            seen_connections = current_connections
            time.sleep(CHECK_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        log_message("Tracker stopped by user.")


# Entry point of the script
if __name__ == "__main__":
    install_requirements()
    main()