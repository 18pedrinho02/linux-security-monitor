from datetime import datetime, timedelta

from src.analyzer import detect_brute_force, detect_success_after_brute_force

def create_failed_event(ip, timestamp):
    return {
        "timestamp_dt": timestamp,
        "source_ip": ip,
        "event_type": "failed_login"
    }
    
def test_detects_multiple_ips():
    start = datetime(2026, 9, 27, 10, 0, 0)
    
    events = [
        create_failed_event(
            "192.168.1.50",
            start + timedelta(minutes=minutes)
        )
        for minutes in [0,1,2,3,4]
    ]
    
    events += [
        create_failed_event(
            "192.168.1.60",
            start + timedelta(minutes=minutes)
        )
        for minutes in [0,1,2,3,4]
    ]
    
    alerts = detect_brute_force(events)
    assert len(alerts) == 2
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[1]["source_ip"] == "192.168.1.60"
 
 
def test_detects_success_after_brute_force():
    start = datetime(2026, 9, 27, 10, 0, 0)

    events = [
        create_failed_event(
            "192.168.1.50",
            start + timedelta(minutes=minutes)
        )
        for minutes in [0, 1, 2, 3, 4]
    ]

    events.append({
        "timestamp_dt": start + timedelta(minutes=5),
        "source_ip": "192.168.1.50",
        "event_type": "successful_login"
    })

    alerts = detect_success_after_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.168.1.50"   
    

def test_respects_alert_cooldown():
    start = datetime(2026, 9, 27, 10, 0, 0)
    
    events = [
        create_failed_event(
            "192.168.1.50",
            start + timedelta(minutes=minutes)
        )
        for minutes in [0,1,2,3,4,5,6,7,8,9]
    ]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[0]["attempts"] == 5


def test_allows_new_alert_after_cooldown():
    start = datetime(2026, 9, 27, 10, 0, 0)
    
    events = [
        create_failed_event(
            "192.168.1.50",
            start + timedelta(minutes=minutes)
        )
        for minutes in [0,1,2,3,4,10, 11, 12, 13, 14]
    ]
    alerts = detect_brute_force(events)
    assert len(alerts) == 2
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[1]["source_ip"] == "192.168.1.50"


def test_detects_brute_force_within_time_window():
    start = datetime(2026, 9, 27, 10, 0, 0)

    events = [
        create_failed_event(
            "192.168.1.50",
            start + timedelta(seconds=seconds)
        )
        for seconds in [0, 30, 60, 90, 120]
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[0]["attempts"] == 5


def test_does_not_detect_attempts_outside_time_window():
    start = datetime(2026, 9, 27, 10, 0, 0)

    events = [
        create_failed_event(
            "192.168.1.50",
            start + timedelta(minutes=minutes)
        )
        for minutes in [0, 2, 4, 6, 8]
    ]

    alerts = detect_brute_force(events)

    assert alerts == []