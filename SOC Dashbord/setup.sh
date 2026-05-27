#!/bin/bash
# ============================================================
# SOC Dashboard - Bootstrap Script
# Waits for OpenSearch, creates index templates, index patterns,
# and imports saved dashboards.
# ============================================================

set -e

OPENSEARCH_URL="${OPENSEARCH_URL:-http://localhost:9200}"
DASHBOARDS_URL="${DASHBOARDS_URL:-http://localhost:5601}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- Colors for output ----
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ---- 1. Wait for OpenSearch ----
info "Waiting for OpenSearch to be ready at ${OPENSEARCH_URL}..."
MAX_RETRIES=60
RETRY=0
until curl -s "${OPENSEARCH_URL}/_cluster/health" | grep -qE '"status":"(green|yellow)"'; do
    RETRY=$((RETRY + 1))
    if [ $RETRY -ge $MAX_RETRIES ]; then
        error "OpenSearch did not become ready in time. Exiting."
        exit 1
    fi
    echo -n "."
    sleep 5
done
echo ""
info "OpenSearch is ready!"

# ---- 2. Create Index Template for security-logs-* ----
info "Creating index template for security-logs-*..."
curl -s -X PUT "${OPENSEARCH_URL}/_index_template/security-logs-template" \
  -H 'Content-Type: application/json' \
  -d @"${SCRIPT_DIR}/schemas/log_schema.json" | python3 -m json.tool
info "security-logs template created."

# ---- 3. Create Index Template for soc-alerts-* ----
info "Creating index template for soc-alerts-*..."
curl -s -X PUT "${OPENSEARCH_URL}/_index_template/soc-alerts-template" \
  -H 'Content-Type: application/json' \
  -d @"${SCRIPT_DIR}/schemas/alert_schema.json" | python3 -m json.tool
info "soc-alerts template created."

# ---- 4. Wait for Dashboards ----
info "Waiting for OpenSearch Dashboards to be ready at ${DASHBOARDS_URL}..."
RETRY=0
until curl -s "${DASHBOARDS_URL}/api/status" | grep -q '"state":"green"'; do
    RETRY=$((RETRY + 1))
    if [ $RETRY -ge $MAX_RETRIES ]; then
        warn "Dashboards did not report green status. Continuing anyway..."
        break
    fi
    echo -n "."
    sleep 5
done
echo ""
info "OpenSearch Dashboards is ready!"

# ---- 5. Import Dashboards ----
DASHBOARD_FILES=(
    "${SCRIPT_DIR}/dashboards/soc_overview.ndjson"
    "${SCRIPT_DIR}/dashboards/mitre_heatmap.ndjson"
    "${SCRIPT_DIR}/dashboards/alert_triage.ndjson"
)

for DASHBOARD_FILE in "${DASHBOARD_FILES[@]}"; do
    if [ -f "$DASHBOARD_FILE" ]; then
        BASENAME=$(basename "$DASHBOARD_FILE")
        info "Importing dashboard: ${BASENAME}..."
        curl -s -X POST "${DASHBOARDS_URL}/api/saved_objects/_import?overwrite=true" \
            -H "osd-xsrf: true" \
            --form file=@"${DASHBOARD_FILE}" | python3 -m json.tool
        info "${BASENAME} imported successfully."
    else
        warn "Dashboard file not found: ${DASHBOARD_FILE}"
    fi
done

# ---- 6. Summary ----
echo ""
info "============================================"
info "  SOC Dashboard Setup Complete!"
info "============================================"
info "  OpenSearch:    ${OPENSEARCH_URL}"
info "  Dashboards:    ${DASHBOARDS_URL}"
info "============================================"
echo ""
info "Next steps:"
info "  1. python scripts/generate_logs.py"
info "  2. python scripts/ingest_logs.py"
info "  3. python scripts/detection_engine.py"
info "  4. Open Dashboards at ${DASHBOARDS_URL}"
echo ""
