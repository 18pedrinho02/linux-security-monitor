from collections import Counter
from datetime import datetime, timedelta

FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_SECONDS = 300
ALERT_COOLDOWN_SECONDS = 300


def analyze_events(events):
    failed_logins = [
        event for event in events
        if event["event_type"] == "failed_login"
    ]

    attempts_by_ip = Counter(
        event["source_ip"] for event in failed_logins
    )

    print("\n[ANALYSIS] Failed login attempts by IP:")

    for ip, count in attempts_by_ip.items():
        print(f"{ip}: {count} failed attempts")

    alerts = detect_brute_force(failed_logins)
    success_alerts = detect_success_after_brute_force(events)
    all_alerts = alerts + success_alerts

    for alert in all_alerts:
        print(format_alert(alert))
        
        
    return all_alerts


def detect_brute_force(failed_logins):
    events_by_ip = {}

    for event in failed_logins:
        ip = event["source_ip"]
        events_by_ip.setdefault(ip, []).append(event)

    alerts = []

    last_alert_time = {}

    for ip, events in events_by_ip.items():
        events.sort(key=lambda event: event["timestamp_dt"])

        for i in range(len(events)):
            start_time = events[i]["timestamp_dt"]
            attempts = 1
            usernames=set()
            
            if events[i].get("username"):
                usernames.add(events[i]["username"])

            for j in range(i + 1, len(events)):
                current_time = events[j]["timestamp_dt"]

                difference = (
                    current_time - start_time
                ).total_seconds()

                if difference > TIME_WINDOW_SECONDS:
                    break

                attempts += 1
                if events[j].get("username"):
                    usernames.add(events[j]["username"])

                if attempts >= FAILED_LOGIN_THRESHOLD:

                    if ip in last_alert_time:
                        cooldown = (
                            current_time - last_alert_time[ip]
                        ).total_seconds()

                        if cooldown <= ALERT_COOLDOWN_SECONDS:
                            break
                    username_text=(
                        ", ".join(sorted(usernames))
                        if usernames
                        else "unknown"
                    )
                    
                    description=(
                        f"Detected {attempts} attempts of "
                        f"failed authentication from IP {ip}, "
                        f"in a window of {TIME_WINDOW_SECONDS} "
                        f"seconds. Users names envolved: "
                        f"{username_text}"
                    )

                    alerts.append({
                        "source_ip": ip,
                        "event_type": "brute_force",
                        "attempts": attempts,
                        "window_seconds": TIME_WINDOW_SECONDS,
                        "severity":get_alert_severity("brute_force"),
                        "first_seen":start_time.isoformat(),
                        "last_seen":current_time.isoformat(),
                        "detected_at":datetime.now().isoformat(),
                        "usernames":sorted(usernames),
                        "description":description
                    })

                    last_alert_time[ip] = current_time

                    break

    return alerts


def detect_success_after_brute_force(events):
    events_by_ip = {}

    for event in events:
        ip = event["source_ip"]

        events_by_ip.setdefault(ip, []).append(event)

    alerts = []

    for ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda event: event["timestamp_dt"])

        for event in ip_events:
            if event["event_type"] != "successful_login":
                continue

            success_time = event["timestamp_dt"]
            failed_attempts = 0
            relevant_failed_events=[]

            for previous_event in ip_events:

                if previous_event["timestamp_dt"] >= success_time:
                    break

                if previous_event["event_type"] != "failed_login":
                    continue

                difference = (
                    success_time - previous_event["timestamp_dt"]
                ).total_seconds()

                if difference <= TIME_WINDOW_SECONDS:
                    failed_attempts += 1
                    relevant_failed_events.append(previous_event)

            if failed_attempts >= FAILED_LOGIN_THRESHOLD:
                
                first_seen=relevant_failed_events[0]["timestamp_dt"]
                
                usernames={
                    failed_event["username"]
                    for failed_event in relevant_failed_events
                    if failed_event.get("username")
                }
                
                if event.get("username"):
                    usernames.add(event["username"])
                    
                username_text=(
                    ", ".join(sorted(usernames))
                    if usernames
                    else "unknown"
                )
                
                description=(
                    f"Detected a successful login after "
                    f"{failed_attempts} attempts of failed authentication "
                    f"from IP {ip}, in a window of {TIME_WINDOW_SECONDS} "
                    f"seconds. Users names envolved: "
                    f"{username_text}"
                )
                
                alerts.append({
                    "source_ip": ip,
                    "attempts": failed_attempts,
                    "event_type": "successful_login_after_brute_force",
                    "window_seconds": TIME_WINDOW_SECONDS,
                    "severity":get_alert_severity("successful_login_after_brute_force"),
                    "first_seen":first_seen.isoformat(),
                    "last_seen":success_time.isoformat(),
                    "detected_at":datetime.now().isoformat(),
                    "usernames":sorted(usernames),
                    "description":description
                })

                break

    return alerts


def get_alert_severity(event_type):
    if event_type == "brute_force":
        return "HIGH"
    if event_type == "successful_login_after_brute_force":
        return "CRITICAL"
    
    return "LOW"

def format_alert(alert):
    severity=alert["severity"]
    attempts=alert["attempts"]
    source_ip=alert["source_ip"]
    window_minutes=alert["window_seconds"]//60
    
    if alert["event_type"]=="brute_force":
        return (
            f"[ALERT] [{severity}] Possible brute-force activity from "
            f"{source_ip}: {attempts} failed attempts within "
            f"{window_minutes} minutes"
        )

    if alert["event_type"] == "successful_login_after_brute_force":
        return (
            f"[ALERT] [{severity}] Successful login from "
            f"{source_ip} after {attempts} failed attempts within "
            f"{window_minutes} minutes"
        )

    return f"[ALERT] [{severity}] Unknown alert type"