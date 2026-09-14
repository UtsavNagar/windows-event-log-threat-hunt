"""
Detector: Suspicious Child Process of a Scripting Interpreter (T1033/T1087 - Discovery)

Attackers frequently run built-in recon commands (whoami, net, systeminfo,
etc.) immediately after gaining code execution, to figure out who they are
and what they have access to. This is rarely how those binaries get
launched by a normal user - a human runs whoami.exe from a shell they
typed into, not as a child of a scripting engine invoked with -enc.
"""

RECON_BINARIES = {
    "whoami.exe", "net.exe", "net1.exe", "nltest.exe", "systeminfo.exe",
    "ipconfig.exe", "tasklist.exe", "quser.exe", "hostname.exe", "arp.exe",
}

SUSPICIOUS_PARENTS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe",
}


def find_suspicious_children(events):
    findings = []
    for e in events:
        if e.get("EventID") != 1:  # Sysmon process creation
            continue
        image = str(e.get("Image", "")).lower()
        parent = str(e.get("ParentImage", "")).lower()
        image_name = image.split("\\")[-1]
        parent_name = parent.split("\\")[-1]

        if image_name in RECON_BINARIES and parent_name in SUSPICIOUS_PARENTS:
            findings.append({
                "utc_time": e.get("UtcTime"),
                "hostname": e.get("Hostname"),
                "user": e.get("User"),
                "child_image": e.get("Image"),
                "child_cmdline": e.get("CommandLine"),
                "parent_image": e.get("ParentImage"),
                "technique": "T1033/T1087 (System Owner/User Discovery)",
            })
    return findings
