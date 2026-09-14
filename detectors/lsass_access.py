"""
Detector: Suspicious LSASS Process Access (T1003.001 - Credential Dumping)

Sysmon Event ID 10 (ProcessAccess) logs every time one process opens a
handle to another. LSASS holds credential material in memory, so tools
like Mimikatz request specific access rights to read it.

Not every access to lsass.exe is malicious - Windows itself does this
constantly (svchost.exe, wininit.exe, etc. with low-privilege access
rights like 0x1000/0x2000 for routine queries). This detector flags
accesses that are either:
  (a) from a process not normally expected to touch lsass.exe, or
  (b) using an access-rights bitmask commonly associated with credential
      dumping tools (these specific values are well documented in public
      Sigma rules for "Lsass Memory Dump" / "Suspicious LSASS Access").
"""

KNOWN_BAD_MASKS = {
    "0x1010", "0x1038", "0x1400", "0x1410",
    "0x1418", "0x143a", "0x1438", "0x1fffff",
}

TRUSTED_SOURCES = {
    "c:\\windows\\system32\\svchost.exe",
    "c:\\windows\\system32\\wininit.exe",
    "c:\\windows\\system32\\services.exe",
    "c:\\windows\\system32\\csrss.exe",
    "c:\\windows\\system32\\wbem\\wmiprvse.exe",
    "c:\\windows\\system32\\lsass.exe",
    "c:\\program files\\windows defender\\msmpeng.exe",
}


def find_lsass_access(events):
    findings = []
    for e in events:
        if e.get("EventID") != 10:
            continue
        target = str(e.get("TargetImage", "")).lower()
        if "lsass.exe" not in target:
            continue

        source = str(e.get("SourceImage", "")).lower()
        granted = str(e.get("GrantedAccess", "")).lower()
        untrusted_source = source not in TRUSTED_SOURCES
        bad_mask = granted in KNOWN_BAD_MASKS
        flagged = untrusted_source or bad_mask

        reasons = []
        if bad_mask:
            reasons.append(f"GrantedAccess {granted} matches known credential-dumping access mask")
        if untrusted_source:
            reasons.append(f"source process ({e.get('SourceImage')}) is not on the expected allowlist")

        findings.append({
            "utc_time": e.get("UtcTime"),
            "hostname": e.get("Hostname"),
            "source_image": e.get("SourceImage"),
            "source_pid": e.get("SourceProcessId"),
            "granted_access": e.get("GrantedAccess"),
            "flagged": flagged,
            "reasons": reasons,
            "technique": "T1003.001 (OS Credential Dumping: LSASS Memory)",
        })
    return findings
