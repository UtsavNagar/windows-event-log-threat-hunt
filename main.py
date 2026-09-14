#!/usr/bin/env python3
"""
Threat Hunt: Windows Event Log Investigation
Usage: python main.py --data data/empire_mimikatz_logonpasswords_2020-08-07103224.json
"""
import argparse
import sys

from jinja2 import Environment, FileSystemLoader

from data_loader import load_events, summarize_channels
from detectors.encoded_powershell import find_encoded_powershell
from detectors.lsass_access import find_lsass_access
from detectors.suspicious_children import find_suspicious_children


def main():
    parser = argparse.ArgumentParser(description="Run threat-hunt detectors against a Mordor JSON dataset.")
    parser.add_argument("--data", required=True, help="Path to the JSON-lines dataset file")
    parser.add_argument("--out", default="reports/timeline.html", help="Output HTML report path")
    parser.add_argument("--summarize", action="store_true", help="Print Channel/EventID breakdown and exit")
    args = parser.parse_args()

    print(f"[*] Loading events from {args.data} ...")
    events = load_events(args.data)
    print(f"[*] Loaded {len(events)} events")

    if args.summarize:
        print("\nChannel / EventID breakdown:")
        for (channel, eid), count in summarize_channels(events):
            print(f"  {count:>6}  {channel}  (EventID {eid})")
        sys.exit(0)

    print("[*] Running detector: encoded PowerShell execution ...")
    encoded_ps = find_encoded_powershell(events)
    print(f"    -> {len(encoded_ps)} finding(s)")

    print("[*] Running detector: suspicious recon commands ...")
    recon = find_suspicious_children(events)
    print(f"    -> {len(recon)} finding(s)")

    print("[*] Running detector: LSASS process access ...")
    lsass_all = find_lsass_access(events)
    lsass_flagged = [f for f in lsass_all if f["flagged"]]
    print(f"    -> {len(lsass_all)} total LSASS access event(s), {len(lsass_flagged)} flagged")

    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template("report_template.html.j2")
    html = template.render(
        dataset_name=args.data,
        total_events=len(events),
        flagged_count=len(encoded_ps) + len(recon) + len(lsass_flagged),
        encoded_ps=encoded_ps,
        recon=recon,
        lsass_all=lsass_all,
        lsass_flagged=lsass_flagged,
    )

    import os
    os.makedirs("reports", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n[+] Report written to {args.out}")
    print("[+] Open it in your browser, then fill out report_template.md with your findings.")


if __name__ == "__main__":
    main()
