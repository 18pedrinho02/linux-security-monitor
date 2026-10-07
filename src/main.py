from pathlib import Path

from src.log_parser import parse_log_line
from src.analyzer import analyze_events


def main():
    log_file = Path(__file__).resolve().parent.parent / "data" / "auth.log"

    events = []

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            event = parse_log_line(line.strip())

            if event is not None:
                events.append(event)

    print(f"[INFO] Processed {len(events)} events")

    analyze_events(events)


if __name__ == "__main__":
    main()