import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
    r"(?P<hostname>\S+) "
    r"sshd\[(?P<pid>\d+)\]: "
    r"(?P<message>.*)$"
)

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for "
    r"(?:(?P<invalid_user>invalid user) )?"
    r"(?P<username>\S+) "
    r"from (?P<source_ip>\S+) "
    r"port (?P<source_port>\d+)"
)

SUCCESSFUL_LOGIN_PATTERN = re.compile(
    r"Accepted password for "
    r"(?P<username>\S+) "
    r"from (?P<source_ip>\S+) "
    r"port (?P<source_port>\d+)"
)


def parse_log_line(line):
    log_match = LOG_PATTERN.match(line)

    if not log_match:
        return None

    log_data = log_match.groupdict()
    message = log_data["message"]
    current_year = datetime.now().year

    timestamp = datetime.strptime(
        f"{current_year} {log_data['timestamp']}",
        "%Y %b %d %H:%M:%S"
    )

    event = {
        "timestamp": log_data["timestamp"],
        "timestamp_dt": timestamp,
        "hostname": log_data["hostname"],
        "pid": int(log_data["pid"]),
        "source_ip": None,
        "username": None,
        "source_port": None,
        "event_type": None,
        "invalid_user": False
    }

    failed_match = FAILED_LOGIN_PATTERN.search(message)

    if failed_match:
        data = failed_match.groupdict()

        event["source_ip"] = data["source_ip"]
        event["source_port"] = int(data["source_port"])
        event["username"] = data["username"]
        event["event_type"] = "failed_login"
        event["invalid_user"] = data["invalid_user"] is not None

        return event

    success_match = SUCCESSFUL_LOGIN_PATTERN.search(message)

    if success_match:
        data = success_match.groupdict()

        event["source_ip"] = data["source_ip"]
        event["source_port"] = int(data["source_port"])
        event["username"] = data["username"]
        event["event_type"] = "successful_login"

        return event

    return None