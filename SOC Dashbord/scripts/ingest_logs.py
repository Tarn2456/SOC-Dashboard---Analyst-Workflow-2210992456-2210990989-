#!/usr/bin/env python3
"""
ingest_logs.py — Reads synthetic NDJSON logs, enriches with GeoIP data and
host metadata, then bulk-indexes into OpenSearch (security-logs-* index).
"""

import json
import os
import sys
from datetime import datetime, timezone

from opensearchpy import OpenSearch, helpers

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.environ.get("OPENSEARCH_PORT", 9200))
INDEX_NAME = f"security-logs-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
INPUT_FILE = os.path.join(DATA_DIR, "synthetic_logs.ndjson")

BATCH_SIZE = 500

# ---------------------------------------------------------------------------
# GeoIP Demo Lookup (simplified for demo purposes)
# ---------------------------------------------------------------------------
GEOIP_DB = {
    "185.220.101.45": {"country_name": "Germany", "city_name": "Berlin", "location": {"lat": 52.52, "lon": 13.405}},
    "91.219.236.222": {"country_name": "Russia", "city_name": "Moscow", "location": {"lat": 55.7558, "lon": 37.6173}},
    "45.33.32.156": {"country_name": "United States", "city_name": "Fremont", "location": {"lat": 37.5485, "lon": -121.9886}},
    "104.21.45.12": {"country_name": "United States", "city_name": "San Francisco", "location": {"lat": 37.7749, "lon": -122.4194}},
    "198.51.100.78": {"country_name": "Netherlands", "city_name": "Amsterdam", "location": {"lat": 52.3676, "lon": 4.9041}},
}

# Host metadata enrichment
HOST_METADATA = {
    "WS-PC-001": {"department": "Engineering", "criticality": "medium"},
    "WS-PC-002": {"department": "Finance", "criticality": "high"},
    "WS-PC-003": {"department": "HR", "criticality": "medium"},
    "WS-PC-004": {"department": "Marketing", "criticality": "low"},
    "WS-PC-005": {"department": "Engineering", "criticality": "medium"},
    "SRV-DC-01": {"department": "IT", "criticality": "critical"},
    "SRV-DC-02": {"department": "IT", "criticality": "critical"},
    "SRV-WEB-01": {"department": "IT", "criticality": "high"},
    "SRV-DB-01": {"department": "IT", "criticality": "critical"},
    "SRV-FILE-01": {"department": "IT", "criticality": "high"},
}


def enrich_geoip(doc):
    """Add GeoIP data to source and destination IPs if available."""
    for direction in ("source", "destination"):
        if direction in doc and "ip" in doc[direction]:
            ip = doc[direction]["ip"]
            if ip in GEOIP_DB:
                doc[direction].setdefault("geo", {})
                doc[direction]["geo"].update(GEOIP_DB[ip])
    return doc


def enrich_host_metadata(doc):
    """Add department and criticality metadata based on hostname."""
    hostname = doc.get("host", {}).get("name", "")
    if hostname in HOST_METADATA:
        meta = HOST_METADATA[hostname]
        doc["host"]["department"] = meta["department"]
        doc["host"]["criticality"] = meta["criticality"]
    return doc


def generate_bulk_actions(filepath):
    """Read NDJSON file and yield enriched bulk-index actions."""
    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"  [WARN] Skipping line {line_num}: {e}")
                continue

            # Enrich
            doc = enrich_geoip(doc)
            doc = enrich_host_metadata(doc)

            yield {
                "_index": INDEX_NAME,
                "_source": doc,
            }


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"[✗] Input file not found: {INPUT_FILE}")
        print("    Run generate_logs.py first to create synthetic logs.")
        sys.exit(1)

    # Count total lines
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        total_lines = sum(1 for line in f if line.strip())
    print(f"[*] Found {total_lines} log events in {INPUT_FILE}")

    # Connect to OpenSearch
    client = OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        ssl_show_warn=False,
    )

    # Check connection
    info = client.info()
    print(f"[✓] Connected to OpenSearch: {info['version']['distribution']} {info['version']['number']}")

    # Bulk index
    print(f"[*] Indexing into '{INDEX_NAME}' (batch size: {BATCH_SIZE})...")
    success_count = 0
    error_count = 0

    for ok, result in helpers.parallel_bulk(
        client,
        generate_bulk_actions(INPUT_FILE),
        chunk_size=BATCH_SIZE,
        thread_count=2,
    ):
        if ok:
            success_count += 1
        else:
            error_count += 1
            print(f"  [ERROR] {result}")

    # Refresh index
    client.indices.refresh(index=INDEX_NAME)

    # Final count
    count = client.count(index=INDEX_NAME)["count"]
    print(f"\n[✓] Ingestion complete!")
    print(f"    Indexed: {success_count} docs | Errors: {error_count}")
    print(f"    Total docs in '{INDEX_NAME}': {count}")


if __name__ == "__main__":
    main()
