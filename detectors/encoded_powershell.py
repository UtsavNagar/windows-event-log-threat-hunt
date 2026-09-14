"""
Detector: Encoded PowerShell Execution (T1059.001, T1027)

Looks for '-enc' / '-EncodedCommand' on any command line captured in the
dataset (Sysmon CommandLine/ParentCommandLine fields), then automatically
Base64/UTF-16LE decodes the payload and flags it if it contains markers
commonly seen in loader/stager scripts (logging bypass, AMSI tampering,
web downloads, IEX execution).

Why this approach instead of just string-matching 'mimikatz': attackers
rarely leave the tool name in plaintext. What's actually visible on the
wire is the *behavior* - an obfuscated launcher that disables logging and
pulls down a second-stage payload. That's what this detector looks for.
"""
import base64
import re

SUSPICIOUS_MARKERS = [
    "downloadstring", "downloaddata", "invoke-expression", "iex(", "|iex",
    "amsiinitfailed", "enablescriptblocklogging", "webclient",
    "net.webrequest", "frombase64string", "-windowstyle hidden",
]

ENC_PATTERN = re.compile(r"-[eE][nN]?[cC]?(?:odedCommand)?\s+([A-Za-z0-9+/=]{40,})")


def decode_encoded_command(b64_string):
    """PowerShell -enc payloads are Base64 of UTF-16LE text."""
    try:
        raw = base64.b64decode(b64_string + "=" * (-len(b64_string) % 4))
        return raw.decode("utf-16le", errors="ignore")
    except Exception:
        return None


def find_encoded_powershell(events):
    findings = []
    seen_cmdlines = set()

    for e in events:
        for field in ("CommandLine", "ParentCommandLine"):
            cmdline = e.get(field)
            if not cmdline:
                continue
            match = ENC_PATTERN.search(cmdline)
            if not match:
                continue
            if cmdline in seen_cmdlines:
                continue
            seen_cmdlines.add(cmdline)

            decoded = decode_encoded_command(match.group(1))
            hits = []
            if decoded:
                low = decoded.lower()
                hits = [m for m in SUSPICIOUS_MARKERS if m in low]

            findings.append({
                "utc_time": e.get("UtcTime") or e.get("EventTime"),
                "hostname": e.get("Hostname"),
                "user": e.get("User"),
                "field_source": field,
                "raw_commandline": cmdline[:160] + ("..." if len(cmdline) > 160 else ""),
                "decoded_snippet": (decoded[:500] + "...") if decoded and len(decoded) > 500 else decoded,
                "suspicious_markers": hits,
                "technique": "T1059.001 (PowerShell) + T1027 (Obfuscation)",
            })

    return findings
