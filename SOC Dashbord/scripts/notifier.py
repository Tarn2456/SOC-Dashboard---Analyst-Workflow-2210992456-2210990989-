#!/usr/bin/env python3
"""
notifier.py — Real-time Email + Slack Alert Notifications

Reads new high/critical alerts from soc-alerts-* and sends notifications
via Slack webhook and/or Gmail SMTP.

Usage:
  python scripts/notifier.py          # Send notifications for all new alerts
  python scripts/notifier.py --test   # Send a test notification to verify setup
"""

import argparse
import os
import smtplib
import json
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests
from opensearchpy import OpenSearch

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.environ.get("OPENSEARCH_PORT", 9200))

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
SMTP_HOST         = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT         = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER         = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD     = os.environ.get("SMTP_PASSWORD", "")
ALERT_RECIPIENT   = os.environ.get("ALERT_RECIPIENT", "")

NOTIFY_CHANNELS     = [c.strip() for c in os.environ.get("NOTIFY_CHANNELS", "slack,email").split(",") if c.strip()]
NOTIFY_MIN_SEVERITY = os.environ.get("NOTIFY_MIN_SEVERITY", "high")

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_EMOJI = {"low": "🟡", "medium": "🟠", "high": "🔴", "critical": "🚨"}
SEVERITY_COLOR = {"low": "#FFC107", "medium": "#FF9800", "high": "#F44336", "critical": "#9C27B0"}


def get_client():
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_compress=True, use_ssl=False, verify_certs=False, ssl_show_warn=False,
    )


# ---------------------------------------------------------------------------
# Fetch alerts
# ---------------------------------------------------------------------------
def fetch_new_alerts(client, min_severity: str = "high") -> list:
    """Fetch alerts that haven't been notified yet, above min severity."""
    min_score = SEVERITY_ORDER.get(min_severity, 3)
    try:
        resp = client.search(
            index="soc-alerts-*",
            body={
                "query": {
                    "bool": {
                        "must": [{"term": {"alert.status": "new"}}],
                        "must_not": [{"term": {"alert.notified": True}}],
                        "filter": [{"range": {"alert.severity_score": {"gte": min_score}}}],
                    }
                },
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": 20,
            },
        )
        return resp["hits"]["hits"]
    except Exception as e:
        print(f"[✗] Could not fetch alerts: {e}")
        return []


def mark_notified(client, doc_id: str, index: str):
    """Mark an alert as notified so we don't send it again."""
    try:
        client.update(index=index, id=doc_id, body={"doc": {"alert": {"notified": True}}})
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Slack Notification
# ---------------------------------------------------------------------------
def send_slack(alert_data: dict) -> bool:
    """Send a formatted Slack message via webhook."""
    if not SLACK_WEBHOOK_URL or "YOUR/WEBHOOK" in SLACK_WEBHOOK_URL:
        print("  [!] Slack: No webhook URL configured (set SLACK_WEBHOOK_URL in .env)")
        return False

    a = alert_data.get("alert", {})
    severity = a.get("severity", "unknown")
    emoji = SEVERITY_EMOJI.get(severity, "⚠️")
    color = SEVERITY_COLOR.get(severity, "#888888")
    hosts = ", ".join(alert_data.get("related", {}).get("hosts", ["unknown"]))
    users = ", ".join(alert_data.get("related", {}).get("users", ["unknown"]))
    ts = alert_data.get("@timestamp", "")

    payload = {
        "username": "SOC Dashboard Bot",
        "icon_emoji": ":shield:",
        "attachments": [{
            "color": color,
            "title": f"{emoji} SOC ALERT — {a.get('rule_name', 'Unknown Rule')}",
            "fields": [
                {"title": "Severity",        "value": severity.upper(), "short": True},
                {"title": "MITRE Technique", "value": f"{a.get('mitre_technique_id','')} — {a.get('mitre_technique_name','')}", "short": True},
                {"title": "Affected Hosts",  "value": hosts or "N/A", "short": True},
                {"title": "Affected Users",  "value": users or "N/A", "short": True},
                {"title": "Match Count",     "value": str(a.get("match_count", 0)), "short": True},
                {"title": "Timestamp",       "value": ts, "short": True},
                {"title": "Description",     "value": a.get("description", ""), "short": False},
            ],
            "footer": "SOC Dashboard | OpenSearch",
            "footer_icon": "https://opensearch.org/favicon.ico",
        }]
    }

    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        if resp.status_code == 200:
            print(f"  [✓] Slack: Sent alert for '{a.get('rule_name')}'")
            return True
        else:
            print(f"  [✗] Slack: HTTP {resp.status_code} — {resp.text}")
            return False
    except Exception as e:
        print(f"  [✗] Slack: {e}")
        return False


# ---------------------------------------------------------------------------
# Email Notification
# ---------------------------------------------------------------------------
def send_email(alert_data: dict) -> bool:
    """Send an HTML formatted alert email via SMTP."""
    if not SMTP_USER or not SMTP_PASSWORD or not ALERT_RECIPIENT:
        print("  [!] Email: SMTP credentials not configured in .env")
        return False

    a = alert_data.get("alert", {})
    severity = a.get("severity", "unknown")
    color = SEVERITY_COLOR.get(severity, "#888888")
    hosts = ", ".join(alert_data.get("related", {}).get("hosts", ["unknown"]))
    users = ", ".join(alert_data.get("related", {}).get("users", ["unknown"]))

    subject = f"[SOC ALERT] {severity.upper()} — {a.get('rule_name', 'Security Alert')}"

    html_body = f"""
    <html><body style="font-family: Arial, sans-serif; background:#f4f4f4; padding:20px;">
    <div style="max-width:600px;margin:auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
      <div style="background:{color};padding:20px;color:#fff;">
        <h2 style="margin:0;">🔴 SOC Security Alert</h2>
        <p style="margin:5px 0 0;">{a.get('rule_name','Unknown Rule')}</p>
      </div>
      <div style="padding:24px;">
        <table width="100%" cellpadding="8" style="border-collapse:collapse;">
          <tr><td style="font-weight:bold;width:140px;">Severity</td>
              <td><span style="background:{color};color:#fff;padding:3px 10px;border-radius:4px;">{severity.upper()}</span></td></tr>
          <tr style="background:#f9f9f9;">
              <td style="font-weight:bold;">MITRE</td>
              <td>{a.get('mitre_technique_id','')} — {a.get('mitre_technique_name','')}</td></tr>
          <tr><td style="font-weight:bold;">Category</td><td>{a.get('category','').replace('_',' ').title()}</td></tr>
          <tr style="background:#f9f9f9;">
              <td style="font-weight:bold;">Affected Hosts</td><td>{hosts}</td></tr>
          <tr><td style="font-weight:bold;">Affected Users</td><td>{users}</td></tr>
          <tr style="background:#f9f9f9;">
              <td style="font-weight:bold;">Match Count</td><td>{a.get('match_count',0)} events</td></tr>
          <tr><td style="font-weight:bold;">Timestamp</td><td>{alert_data.get('@timestamp','')}</td></tr>
        </table>
        <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">
        <p style="color:#555;font-size:14px;">{a.get('description','')}</p>
        <a href="http://localhost:5601" style="display:inline-block;background:#1a237e;color:#fff;padding:10px 20px;border-radius:4px;text-decoration:none;">
          Open SOC Dashboard →
        </a>
      </div>
      <div style="background:#f0f0f0;padding:12px 24px;font-size:12px;color:#888;">
        SOC Dashboard | Auto-generated alert notification
      </div>
    </div>
    </body></html>
    """

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SMTP_USER
        msg["To"]      = ALERT_RECIPIENT
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, ALERT_RECIPIENT, msg.as_string())

        print(f"  [✓] Email: Sent alert for '{a.get('rule_name')}' → {ALERT_RECIPIENT}")
        return True
    except Exception as e:
        print(f"  [✗] Email: {e}")
        return False


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------
def notify_alert(alert_data: dict) -> int:
    """Send notification via all configured channels. Returns count sent."""
    sent = 0
    if "slack" in NOTIFY_CHANNELS:
        if send_slack(alert_data):
            sent += 1
    if "email" in NOTIFY_CHANNELS:
        if send_email(alert_data):
            sent += 1
    return sent


def make_test_alert() -> dict:
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "alert": {
            "rule_id": "TEST-001",
            "rule_name": "TEST — Notification System Check",
            "severity": "high",
            "severity_score": 3,
            "category": "test",
            "description": "This is a test notification from your SOC Dashboard. If you received this, alerting is configured correctly!",
            "mitre_tactic": "Test",
            "mitre_technique_id": "T0000",
            "mitre_technique_name": "Notification Test",
            "status": "new",
            "match_count": 1,
        },
        "related": {"hosts": ["TEST-HOST-01"], "users": ["test_user"], "ips": ["1.2.3.4"], "processes": []},
        "event": {"original_category": "test", "original_action": "test", "sample_message": "Test alert"},
    }


def main():
    parser = argparse.ArgumentParser(description="SOC Dashboard Alert Notifier")
    parser.add_argument("--test", action="store_true", help="Send a test notification")
    parser.add_argument("--severity", default=NOTIFY_MIN_SEVERITY,
                        choices=["low", "medium", "high", "critical"],
                        help="Minimum severity to notify (default: high)")
    args = parser.parse_args()

    print("=" * 60)
    print("  SOC Dashboard — Alert Notifier")
    print("=" * 60)
    print(f"  Channels:     {', '.join(NOTIFY_CHANNELS) if NOTIFY_CHANNELS else 'none configured'}")
    print(f"  Min Severity: {args.severity}")
    print()

    if args.test:
        print("[*] Sending TEST notification...\n")
        notify_alert(make_test_alert())
        return

    client = get_client()
    info = client.info()
    print(f"[✓] Connected to OpenSearch {info['version']['number']}")

    alerts = fetch_new_alerts(client, min_severity=args.severity)
    if not alerts:
        print(f"[—] No new {args.severity}+ alerts to notify.")
        return

    print(f"[*] Found {len(alerts)} alert(s) to notify\n")
    total_sent = 0
    for hit in alerts:
        alert_data = hit["_source"]
        rule_name = alert_data.get("alert", {}).get("rule_name", "Unknown")
        severity  = alert_data.get("alert", {}).get("severity", "?")
        print(f"[→] Notifying: [{severity.upper()}] {rule_name}")
        sent = notify_alert(alert_data)
        if sent > 0:
            mark_notified(client, hit["_id"], hit["_index"])
            total_sent += 1

    print(f"\n[✓] Done. Notifications sent for {total_sent}/{len(alerts)} alerts.")


if __name__ == "__main__":
    main()
