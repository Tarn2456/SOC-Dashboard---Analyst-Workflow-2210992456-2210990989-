import json
import time
import requests
import os

OPENSEARCH_URL = "http://localhost:9200"
DASHBOARDS_URL = "http://localhost:5601"

print(f"Waiting for OpenSearch at {OPENSEARCH_URL}...")
while True:
    try:
        res = requests.get(f"{OPENSEARCH_URL}/_cluster/health")
        if res.status_code == 200:
            status = res.json().get("status")
            if status in ["green", "yellow"]:
                print("OpenSearch is ready!")
                break
    except Exception:
        pass
    print(".", end="", flush=True)
    time.sleep(5)

print("Creating index template for security-logs-*...")
with open("schemas/log_schema.json", "r") as f:
    schema = json.load(f)
res = requests.put(f"{OPENSEARCH_URL}/_index_template/security-logs-template", json=schema)
print("Response:", res.status_code, res.text)

print("Creating index template for soc-alerts-*...")
with open("schemas/alert_schema.json", "r") as f:
    schema = json.load(f)
res = requests.put(f"{OPENSEARCH_URL}/_index_template/soc-alerts-template", json=schema)
print("Response:", res.status_code, res.text)

print(f"Waiting for Dashboards at {DASHBOARDS_URL}...")
while True:
    try:
        res = requests.get(f"{DASHBOARDS_URL}/api/status")
        if res.status_code == 200:
            state = res.json().get("status", {}).get("overall", {}).get("state")
            if state == "green":
                print("Dashboards is ready!")
                break
    except Exception:
        pass
    print(".", end="", flush=True)
    time.sleep(5)

dashboards = [
    "dashboards/soc_overview.ndjson",
    "dashboards/mitre_heatmap.ndjson",
    "dashboards/alert_triage.ndjson"
]

for db in dashboards:
    print(f"Importing dashboard {os.path.basename(db)}...")
    with open(db, "rb") as f:
        files = {"file": (os.path.basename(db), f, "application/ndjson")}
        headers = {"osd-xsrf": "true"}
        res = requests.post(f"{DASHBOARDS_URL}/api/saved_objects/_import?overwrite=true", headers=headers, files=files)
        print("Response:", res.status_code, res.text)

print("Bootstrap completed successfully!")
