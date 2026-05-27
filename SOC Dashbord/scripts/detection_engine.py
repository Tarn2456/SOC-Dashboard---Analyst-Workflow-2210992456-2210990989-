#!/usr/bin/env python3
"""
detection_engine.py — SOC Detection Engine with Deduplication & Daemon Mode

Features:
  - Runs all detection rules against security-logs-*
  - Deduplicates alerts (same rule+host within 24h → update instead of create)
  - Daemon mode: continuously runs every N seconds
  - Auto-calls notifier.py after each detection cycle

Usage:
  python scripts/detection_engine.py                  # Run once
  python scripts/detection_engine.py --daemon         # Run continuously (60s interval)
  python scripts/detection_engine.py --daemon --interval 30
"""

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

from opensearchpy import OpenSearch

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OPENSEARCH_HOST  = os.environ.get("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT  = int(os.environ.get("OPENSEARCH_PORT", 9200))
DAEMON_INTERVAL  = int(os.environ.get("DAEMON_INTERVAL_SECONDS", 60))

LOGS_INDEX   = "security-logs-*"
ALERTS_INDEX = f"soc-alerts-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"

RULES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "rules", "detection_rules.json"
)

SEVERITY_SCORES = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEDUP_WINDOW_HOURS = 24  # Skip creating new alert if same rule+host fired within this window


# ---------------------------------------------------------------------------
# OpenSearch client
# ---------------------------------------------------------------------------
def get_client():
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_compress=True, use_ssl=False, verify_certs=False, ssl_show_warn=False,
    )


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------
def load_rules(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        rules = json.load(f)
    print(f"[✓] Loaded {len(rules)} detection rules from {os.path.basename(filepath)}")
    return rules


# ---------------------------------------------------------------------------
# Entity extraction
# ---------------------------------------------------------------------------
def extract_related_entities(hits):
    hosts, users, ips, processes = set(), set(), set(), set()
    sample_messages = []
    for hit in hits:
        src = hit["_source"]
        if src.get("host", {}).get("name"):
            hosts.add(src["host"]["name"])
        if src.get("user", {}).get("name"):
            users.add(src["user"]["name"])
        for direction in ("source", "destination"):
            ip = src.get(direction, {}).get("ip")
            if ip:
                ips.add(ip)
        if src.get("process", {}).get("name"):
            processes.add(src["process"]["name"])
        msg = src.get("message", "")
        if msg and len(sample_messages) < 3:
            sample_messages.append(msg)
    return {
        "hosts": list(hosts), "users": list(users),
        "ips": list(ips), "processes": list(processes),
    }, sample_messages


# ---------------------------------------------------------------------------
# Deduplication check
# ---------------------------------------------------------------------------
def find_existing_alert(client, rule_id: str, hosts: list) -> dict | None:
    """Check if same rule fired for any of the same hosts within the dedup window."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=DEDUP_WINDOW_HOURS)).isoformat()
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"alert.rule_id": rule_id}},
                    {"range": {"@timestamp": {"gte": cutoff}}},
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 1,
    }
    try:
        resp = client.search(index="soc-alerts-*", body=query)
        hits = resp["hits"]["hits"]
        if hits:
            return hits[0]
    except Exception:
        pass
    return None


def update_existing_alert(client, hit: dict, new_count: int, related: dict):
    """Update match count and last_seen on an existing alert (dedup)."""
    try:
        client.update(
            index=hit["_index"],
            id=hit["_id"],
            body={
                "doc": {
                    "alert": {
                        "match_count": new_count,
                        "last_seen": datetime.now(timezone.utc).isoformat(),
                        "status": "new",
                    },
                    "related": related,
                }
            },
        )
    except Exception as e:
        print(f"    [!] Could not update existing alert: {e}")


# ---------------------------------------------------------------------------
# Detection runner
# ---------------------------------------------------------------------------
def run_detection(client, rule, since: str | None = None) -> tuple[list, bool]:
    """
    Execute a single rule. Returns (alert_docs, was_deduplicated).
    If since is set, only scan logs from that timestamp onward.
    """
    rule_id   = rule["id"]
    rule_name = rule["name"]

    base_query = rule["query"]
    if since:
        # Wrap the rule query with a time filter to only look at new logs
        base_query = {
            "bool": {
                "must": [
                    rule["query"],
                    {"range": {"@timestamp": {"gte": since}}},
                ]
            }
        }

    try:
        response = client.search(
            index=LOGS_INDEX,
            body={"query": base_query, "size": 100, "sort": [{"@timestamp": {"order": "desc"}}]},
        )
    except Exception as e:
        print(f"  [✗] Rule {rule_id} ({rule_name}) — query error: {e}")
        return [], False

    total_hits = response["hits"]["total"]["value"]
    hits       = response["hits"]["hits"]

    if total_hits == 0:
        print(f"  [—] {rule_id} ({rule_name}) — 0 matches")
        return [], False

    print(f"  [!] {rule_id} ({rule_name}) — {total_hits} match(es)")
    related, sample_messages = extract_related_entities(hits)

    # Deduplication check
    existing = find_existing_alert(client, rule_id, related["hosts"])
    if existing:
        prev_count = existing["_source"].get("alert", {}).get("match_count", 0)
        new_count  = max(prev_count, total_hits)
        update_existing_alert(client, existing, new_count, related)
        print(f"    [↺] Deduplicated — updated existing alert (match_count: {prev_count} → {new_count})")
        return [], True

    # Build new alert document
    now = datetime.now(timezone.utc).isoformat()
    alert_doc = {
        "@timestamp": now,
        "alert": {
            "id":                   str(uuid.uuid4()),
            "rule_id":              rule_id,
            "rule_name":            rule_name,
            "severity":             rule["severity"],
            "severity_score":       SEVERITY_SCORES.get(rule["severity"], 0),
            "category":             rule["category"],
            "description":          rule["description"],
            "mitre_tactic":         rule["mitre_tactic"],
            "mitre_technique_id":   rule["mitre_technique"],
            "mitre_technique_name": rule["mitre_technique_name"],
            "status":               "new",
            "notified":             False,
            "match_count":          total_hits,
            "first_seen":           now,
            "last_seen":            now,
        },
        "related": related,
        "event": {
            "original_category": hits[0]["_source"].get("event", {}).get("category", ""),
            "original_action":   hits[0]["_source"].get("event", {}).get("action", ""),
            "sample_message":    sample_messages[0] if sample_messages else "",
        },
    }
    return [alert_doc], False


# ---------------------------------------------------------------------------
# Single detection cycle
# ---------------------------------------------------------------------------
def run_cycle(client, rules: list, since: str | None = None, run_notify: bool = True) -> int:
    """Run all rules, index alerts, return alert count."""
    log_count = 0
    try:
        log_count = client.count(index=LOGS_INDEX)["count"]
    except Exception:
        print(f"[✗] No documents in {LOGS_INDEX}. Run ingest_logs.py first.")
        return 0

    if log_count == 0:
        print("[✗] No logs to analyze. Run generate_logs.py and ingest_logs.py first.")
        return 0

    time_label = f"since {since}" if since else "all-time"
    print(f"\n[*] Running {len(rules)} rules against {LOGS_INDEX} ({time_label})")
    print("-" * 60)

    all_alerts  = []
    dedup_count = 0

    for rule in rules:
        alerts, was_deduped = run_detection(client, rule, since)
        all_alerts.extend(alerts)
        if was_deduped:
            dedup_count += 1

    print("-" * 60)
    print(f"[*] New alerts: {len(all_alerts)}  |  Deduplicated: {dedup_count}")

    if all_alerts:
        print(f"[*] Indexing {len(all_alerts)} new alert(s) into '{ALERTS_INDEX}'...")
        for alert in all_alerts:
            client.index(index=ALERTS_INDEX, body=alert)
        client.indices.refresh(index=ALERTS_INDEX)

    # Summary table
    if all_alerts:
        print(f"\n{'Rule':<45} {'Severity':<10} {'Matches'}")
        print(f"{'─'*45} {'─'*10} {'─'*7}")
        for a in all_alerts:
            al = a["alert"]
            print(f"{al['rule_name']:<45} {al['severity']:<10} {al['match_count']}")

    # Auto-notify
    if run_notify and all_alerts:
        notifier_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "notifier.py")
        if os.path.exists(notifier_script):
            print("\n[*] Running notifier...")
            subprocess.run([sys.executable, notifier_script], check=False)

    return len(all_alerts)


# ---------------------------------------------------------------------------
# Daemon mode
# ---------------------------------------------------------------------------
def run_daemon(client, rules: list, interval: int):
    """Continuously run detection every `interval` seconds."""
    print(f"\n[*] DAEMON MODE — running every {interval}s. Press Ctrl+C to stop.\n")
    last_run_ts = None

    while True:
        now = datetime.now(timezone.utc)
        print(f"\n{'='*60}")
        print(f"  Detection Cycle — {now.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"{'='*60}")

        run_cycle(client, rules, since=last_run_ts)
        last_run_ts = now.isoformat()

        print(f"\n[⏱] Next run in {interval}s... (Ctrl+C to stop)")
        for remaining in range(interval, 0, -1):
            print(f"\r    {remaining:>3}s remaining...", end="", flush=True)
            time.sleep(1)
        print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="SOC Detection Engine")
    parser.add_argument("--daemon",   action="store_true", help="Run continuously")
    parser.add_argument("--interval", type=int, default=DAEMON_INTERVAL,
                        help=f"Daemon interval in seconds (default: {DAEMON_INTERVAL})")
    parser.add_argument("--no-notify", action="store_true",
                        help="Disable auto-notification after detection")
    args = parser.parse_args()

    print("=" * 60)
    print("  SOC Detection Engine")
    print("=" * 60)

    client = get_client()
    info   = client.info()
    print(f"[✓] Connected to OpenSearch {info['version']['number']}")

    try:
        log_count = client.count(index=LOGS_INDEX)["count"]
        print(f"[*] {log_count} documents in {LOGS_INDEX}")
    except Exception:
        print(f"[✗] Could not count documents in {LOGS_INDEX}")

    rules = load_rules(RULES_FILE)

    if args.daemon:
        run_daemon(client, rules, interval=args.interval)
    else:
        run_cycle(client, rules, since=None, run_notify=not args.no_notify)


if __name__ == "__main__":
    main()
