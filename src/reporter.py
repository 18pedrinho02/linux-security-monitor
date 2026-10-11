import json
from pathlib import Path

def export_alerts_to_json(alerts, output_file):
    output_file=Path(output_file)
    
    with output_file.open("w",encoding="utf-8") as file:
        json.dump(
            alerts,
            file,
            indent=4,
            ensure_ascii=False
        )