# Incident Report — [Give it a short title once you know what happened]

**Analyst:** [Your name]
**Date of analysis:** [Date]
**Dataset:** empire_mimikatz_logonpasswords (Mordor / Security-Datasets, OTRF)

> Fill this in after reviewing `reports/timeline.html`. Don't copy detector
> output verbatim — write it in your own words, the way you'd explain it to
> a shift lead. If you get stuck on what a field means, that's a sign to go
> re-read the raw event in `data/*.json`, not to guess.

---

## 1. Summary

_One or two sentences: what happened, on which host, to which account?_

---

## 2. Timeline of Events

_Build your own chronological table from the three detector sections in the
report. Include timestamps, host, user, and what happened at each stage._

| Time (UTC) | Host | Event | MITRE Technique |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

---

## 3. Root Cause / Initial Access

_How did this start? What was the very first suspicious action, and what
does it tell you about how the attacker got code execution in the first
place? (Note: this dataset starts mid-attack — say what you can conclude
from what's visible, and note what's NOT visible / would need more data.)_

---

## 4. What the Attacker Did (Attack Narrative)

_Walk through the encoded PowerShell stage -> what it did once decoded ->
the recon commands -> the LSASS access. Explain WHY each stage matters,
not just what happened._

---

## 5. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Host | |
| User account | |
| Suspicious process | |
| Parent process | |
| Encoded command (truncated) | |

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Execution | | |
| Defense Evasion | | |
| Discovery | | |
| Credential Access | | |

---

## 7. Severity & Impact

_If this were a real production alert, how would you triage it? What's
actually at risk if the credential dumping succeeded?_

---

## 8. Recommended Response / Remediation

_What would you tell the SOC to do right now, and what would you recommend
to prevent this class of attack going forward (e.g. logging gaps you
noticed, detection rules worth adding, hardening steps)?_

---

## 9. Detection Gaps Noticed

_Did anything happen that your detectors DIDN'T catch, but you noticed by
eye while reviewing the data? This is often the most impressive part of a
write-up in an interview — it shows you're not just running someone else's
tool blindly._
