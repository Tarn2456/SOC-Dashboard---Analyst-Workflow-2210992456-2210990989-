#!/usr/bin/env python3
"""
threat_intel.py — IP Reputation Enrichment via AbuseIPDB

Usage:
  python scripts/threat_intel.py              # Enrich all IPs in logs
  python scripts/threat_intel.py --ip 1.2.3.4 # Check single IP
"""

import argparse
import os
import time
from datetime import datetime, timezone

import requests
from opensearchpy import OpenSearch

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
except ImportError:
    pass

OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.environ.get("OPENSEARCH_PORT", 9200))
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
INTEL_INDEX = "threat-intel-iocs"

PRIVATE_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.", "::1"
)


def get_client():
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_compress=True, use_ssl=False, verify_certs=False, ssl_show_warn=False,
    )


def classify_risk(score: int) -> str:
    if score >= 90: return "critical"
    if score >= 75: return "malicious"
    if score >= 50: return "suspicious"
    if score >= 25: return "low"
    return "clean"


def query_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB — falls back to mock data if no API key set."""
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY_HERE":
        import random
        score = random.choice([0, 0, 5, 12, 45, 78, 92, 100])
        return {
            "ip": ip,
            "is_public": True,
            "abuse_score": score,
            "risk_level": classify_risk(score),
            "total_reports": random.randint(0, 500),
            "country_code": random.choice(["US", "DE", "RU", "CN", "IR"]),
            "domain": None,
            "isp": "Demo ISP (set ABUSEIPDB_API_KEY for real data)",
            "usage_type": "Data Center/Web Hosting/Transit",
            "source": "mock",
        }
    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=10,
        )
        resp.raise_for_status()
        d = resp.json().get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        return {
            "ip": ip,
            "is_public": d.get("isPublic", False),
            "abuse_score": score,
            "risk_level": classify_risk(score),
            "total_reports": d.get("totalReports", 0),
            "country_code": d.get("countryCode", ""),
            "domain": d.get("domain"),
            "isp": d.get("isp", ""),
            "usage_type": d.get("usageType", ""),
            "source": "abuseipdb",
        }
    except Exception as e:
        return {"ip": ip, "abuse_score": -1, "risk_level": "unknown", "source": "error", "error": str(e)}


def ensure_index(client):
    if not client.indices.exists(index=INTEL_INDEX):
        client.indices.create(index=INTEL_INDEX, body={
            "mappings": {"properties": {
                "@timestamp":    {"type": "date"},
                "ip":            {"type": "ip"},
                "abuse_score":   {"type": "integer"},
                "risk_level":    {"type": "keyword"},
                "total_reports": {"type": "integer"},
                "country_code":  {"type": "keyword"},
                "isp":           {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "source":        {"type": "keyword"},
            }}
        })
        print(f"[+] Created index '{INTEL_INDEX}'")


def extract_unique_ips(client) -> set:
    ips = set()
    agg = {"size": 0, "aggs": {
        "src": {"terms": {"field": "source.ip", "size": 500}},
        "dst": {"terms": {"field": "destination.ip", "size": 500}},
    }}
    for index in ("security-logs-*", "soc-alerts-*"):
        try:
            r = client.search(index=index, body=agg)
            for bucket in r["aggregations"]["src"]["buckets"] + r["aggregations"]["dst"]["buckets"]:
                ip = bucket["key"]
                if not any(ip.startswith(p) for p in PRIVATE_PREFIXES):
                    ips.add(ip)
        except Exception:
            pass
    return ips


def enrich_ip(client, ip: str) -> dict:
    intel = query_abuseipdb(ip)
    client.index(index=INTEL_INDEX, body={"@timestamp": datetime.now(timezone.utc).isoformat(), **intel}, id=ip)
    return intel


def run_enrichment(client):
    print("[*] Extracting unique external IPs from logs and alerts...")
    ips = extract_unique_ips(client)
    if not ips:
        print("[—] No external IPs found. Run ingest_logs.py first.")
        return []

    print(f"[*] Found {len(ips)} external IPs to enrich")
    ensure_index(client)

    results = []
    for i, ip in enumerate(sorted(ips), 1):
        intel = enrich_ip(client, ip)
        score = intel.get("abuse_score", 0)
        flag = "🔴" if score >= 75 else "🟡" if score >= 25 else "🟢"
        print(f"  {flag} [{i:>2}/{len(ips)}] {ip:<20} Score:{score:>3}  Risk:{intel.get('risk_level','?')}")
        results.append(intel)
        if i < len(ips):
            time.sleep(1)  # rate limit: 1 req/sec on free tier

    client.indices.refresh(index=INTEL_INDEX)
    high_risk = [r for r in results if r.get("abuse_score", 0) >= 75]
    print(f"\n[✓] Done. {len(results)} IPs enriched, {len(high_risk)} high-risk.")

    if high_risk:
        print("\n[!] HIGH-RISK IPs:")
        for r in sorted(high_risk, key=lambda x: x.get("abuse_score", 0), reverse=True):
            print(f"    {r['ip']:<20} Score={r['abuse_score']}  Country={r.get('country_code','??')}  ISP={str(r.get('isp',''))[:40]}")
    return results


def main():
    parser = argparse.ArgumentParser(description="SOC Threat Intelligence — AbuseIPDB Enrichment")
    parser.add_argument("--ip", help="Check a single IP address")
    args = parser.parse_args()

    print("=" * 60)
    print("  SOC Threat Intelligence — AbuseIPDB IP Enrichment")
    print("=" * 60)

    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY_HERE":
        print("[!] No API key set — running in DEMO MODE (mock scores)")
        print("    Get a FREE key at: https://www.abuseipdb.com/register\n")

    client = get_client()
    info = client.info()
    print(f"[✓] Connected to OpenSearch {info['version']['number']}\n")

    if args.ip:
        ensure_index(client)
        intel = enrich_ip(client, args.ip)
        print(f"\n  IP:            {intel['ip']}")
        print(f"  Abuse Score:   {intel.get('abuse_score', 'N/A')} / 100")
        print(f"  Risk Level:    {intel.get('risk_level', 'N/A').upper()}")
        print(f"  Total Reports: {intel.get('total_reports', 'N/A')}")
        print(f"  Country:       {intel.get('country_code', 'N/A')}")
        print(f"  ISP:           {intel.get('isp', 'N/A')}")
    else:
        run_enrichment(client)


if __name__ == "__main__":
    main()
