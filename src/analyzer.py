from collections import Counter

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

    for alert in alerts:
        print(
            f"[ALERT] Possible brute-force activity from "
            f"{alert['source_ip']}: "
            f"{alert['attempts']} failed attempts within "
            f"{TIME_WINDOW_SECONDS // 60} minutes"
        )

    return alerts


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

            for j in range(i + 1, len(events)):
                current_time = events[j]["timestamp_dt"]

                difference = (
                    current_time - start_time
                ).total_seconds()

                if difference > TIME_WINDOW_SECONDS:
                    break

                attempts += 1

                if attempts >= FAILED_LOGIN_THRESHOLD:

                    if ip in last_alert_time:
                        cooldown = (
                            current_time - last_alert_time[ip]
                        ).total_seconds()

                        if cooldown <= ALERT_COOLDOWN_SECONDS:
                            break

                    alerts.append({
                        "source_ip": ip,
                        "attempts": attempts,
                        "window_seconds": TIME_WINDOW_SECONDS
                    })

                    last_alert_time[ip] = current_time

                    break

    return alerts

def detect_success_after_brute_force(events):
    events_by_ip={}
    
    for event in events:
        ip = event["source_ip"]
        
        events_by_ip.setdefault(ip,[]).append(event)
        
    alerts=[]
    
    for ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda event:event["timestamp_dt"])
        
        for event in ip_events:
            if event["event_type"] != "successful_login":
                continue
            
            success_time=event["timastamp_dt"]
            failed_attemps=0
            
            for previous_event in ip_events:
                if previous_event["timestamp_dt"]>=success_time:
                    break
                if previous_event["timestamp_dt"]<=success_time:
                    continue
                
                difference=(success_time - previous_event["timestamp_dt"]).total_seconds()
                
                if difference<=TIME_WINDOW_SECONDS:
                    failed_attemps += 1
            
    return alerts