"""
Loads a Mordor/Security-Datasets JSON-lines file into a list of dicts.
Each line in the file is one Windows Event Log record (Sysmon, Security,
PowerShell, etc.) that has been converted to JSON.
"""
import json


def load_events(path):
    events = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def summarize_channels(events):
    """Quick sanity-check helper: count events per (Channel, EventID)."""
    counts = {}
    for e in events:
        key = (e.get("Channel", "?"), e.get("EventID", "?"))
        counts[key] = counts.get(key, 0) + 1
    return sorted(counts.items(), key=lambda x: -x[1])
