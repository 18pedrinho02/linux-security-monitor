import json

from src.reporter import export_alerts_to_json


def test_exports_alerts_to_json(tmp_path):
    alerts = [
        {
            "source_ip": "192.168.1.50",
            "event_type": "brute_force",
            "attempts": 5,
            "window_seconds": 300,
            "severity": "HIGH"
        }
    ]

    output_file = tmp_path / "alerts.json"

    export_alerts_to_json(alerts, output_file)

    with output_file.open("r", encoding="utf-8") as file:
        exported_alerts = json.load(file)

    assert exported_alerts == alerts