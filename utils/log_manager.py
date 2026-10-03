import json
import os
from datetime import datetime


LOG_FILE = "security_logs.json"


def add_log(action, target, result):
    # Prevent sensitive data from being written to logs
    if action == "Password Check":
        target = "Password"
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "target": target,
        "result": result
    }

    logs = []

    if os.path.exists(LOG_FILE):

        try:
            with open(LOG_FILE, "r", encoding="utf-8") as file:
                logs = json.load(file)

        except (json.JSONDecodeError, OSError):
            logs = []

    logs.append(log_entry)

    with open(LOG_FILE, "w", encoding="utf-8") as file:
        json.dump(logs, file, indent=4)


def get_logs():

    if not os.path.exists(LOG_FILE):
        return []

    try:

        with open(LOG_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):
        return []