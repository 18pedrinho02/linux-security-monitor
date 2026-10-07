from src.log_parser import parse_log_line


def test_failed_login():
    line = (
        "Sep 27 10:15:21 server sshd[1234]: "
        "Failed password for root from 192.168.1.50 port 51234 ssh2"
    )

    event = parse_log_line(line)

    assert event is not None
    assert event["event_type"] == "failed_login"
    assert event["username"] == "root"
    assert event["source_ip"] == "192.168.1.50"
    assert event["source_port"] == 51234
    assert event["invalid_user"] is False


def test_invalid_user():
    line = (
        "Sep 27 10:15:25 server sshd[1234]: "
        "Failed password for invalid user test "
        "from 192.168.1.60 port 51236 ssh2"
    )

    event = parse_log_line(line)

    assert event is not None
    assert event["event_type"] == "failed_login"
    assert event["username"] == "test"
    assert event["invalid_user"] is True


def test_successful_login():
    line = (
        "Sep 27 10:15:28 server sshd[1234]: "
        "Accepted password for pedro from 192.168.1.70 port 51237 ssh2"
    )

    event = parse_log_line(line)

    assert event is not None
    assert event["event_type"] == "successful_login"
    assert event["username"] == "pedro"
    assert event["source_ip"] == "192.168.1.70"