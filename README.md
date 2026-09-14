# Windows Event Log Threat Hunt — Credential Dumping Investigation

An end-to-end SOC investigation exercise: **real Windows event log data →
detection scripts you run yourself → a timeline → an incident report you
write**. This is built to close the exact gap most entry-level SOC resumes
have — tools listed but never demonstrated *investigating* anything.

## The dataset

This uses a real dataset from **[OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets)**
(the successor to the well-known "Mordor" project) — `empire_mimikatz_logonpasswords`,
which captures an actual attack simulation: a PowerShell Empire agent
launched on a Windows host, followed by a Mimikatz credential-dumping
module. It's already included in `data/` — no download needed.

This is a **real, well-documented public dataset** used throughout the
threat-hunting community (see OTRF's own
[ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) for
the original researcher's notes on this exact dataset) — so if you want to
go deeper later, there's a lot to cross-reference against.

## What's actually in the data (no spoilers beyond this)

The dataset contains ~6,000 events across Sysmon, Windows Security, and
PowerShell logs, captured on two hosts (`WORKSTATION5` and `MORDORDC`) in
the `theshire.local` domain. Somewhere in there is a multi-stage attack.
The three detectors in this project each surface one piece of it — it's
on you to connect them into a full story.

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# OR
venv\Scripts\Activate.ps1
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
pip install -r requirements.txt
python main.py --data data/empire_mimikatz_logonpasswords_2020-08-07103224.json
```

## Running it

```bash
# Optional: see what's actually in the dataset first
python main.py --data data/empire_mimikatz_logonpasswords_2020-08-07103224.json --summarize

# Run all detectors and generate the report
python main.py --data data/empire_mimikatz_logonpasswords_2020-08-07103224.json
```

Then open `reports/timeline.html` in your browser.

## What each detector looks for

| Detector | File | MITRE Technique | What it catches |
|---|---|---|---|
| Encoded PowerShell | `detectors/encoded_powershell.py` | T1059.001, T1027 | `-enc`/`-EncodedCommand` usage; auto-decodes the Base64/UTF-16LE payload and flags suspicious markers inside it (logging bypass, AMSI tampering, download cradles) |
| Recon commands | `detectors/suspicious_children.py` | T1033, T1087 | Built-in Windows recon binaries (whoami, net, systeminfo, etc.) spawned as children of a scripting interpreter |
| LSASS access | `detectors/lsass_access.py` | T1003.001 | Sysmon ProcessAccess events targeting lsass.exe, flagged either by a known credential-dumping access-rights bitmask or by an untrusted source process |

None of these hardcode "mimikatz" as a string — on purpose. Real attackers
don't leave tool names in plaintext; you detect the *behavior*
(obfuscated launcher → logging/AMSI tampering → recon → LSASS access),
not a signature. That's the actual point of this exercise.

## Your job (this is the part that matters)

1. Run the tool, open the HTML report.
2. Read every finding — including the raw decoded PowerShell payload.
3. Figure out the actual order of events and how they connect.
4. Fill in `report_template.md` **in your own words**. Don't paste detector
   output into it — synthesize it into an analyst write-up.
5. Map each stage to MITRE ATT&CK yourself (a starting technique ID is
   given per-detector above, but the tactic/sub-technique write-up should
   be yours).

This is deliberately the same lesson as before: a tool that hands you a
finished report isn't evidence you did the investigation. Do the reading.

## Bonus: real Sigma rule

`rules/lsass_access.yml` is a working Sigma rule matching the LSASS
detector's logic, in the actual format used by real detection engineering
teams. If you want to go further, try running it through the
[Sigma CLI (`sigma-cli`)](https://github.com/SigmaHQ/sigma-cli) converted
to a Splunk/Elastic query against this same dataset.

## Project structure

```
threat-hunt/
├── data/
│   └── empire_mimikatz_logonpasswords_2020-08-07103224.json   # real Mordor dataset
├── detectors/
│   ├── encoded_powershell.py
│   ├── lsass_access.py
│   └── suspicious_children.py
├── rules/
│   └── lsass_access.yml        # Sigma rule, same logic as the LSASS detector
├── data_loader.py
├── main.py                     # orchestrates detectors, builds the HTML report
├── report_template.html.j2     # HTML report template (Jinja2)
├── report_template.md          # BLANK - your incident report goes here
├── reports/                    # generated timeline.html lands here
└── requirements.txt
```
