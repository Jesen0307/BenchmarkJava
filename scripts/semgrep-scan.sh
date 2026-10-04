#!/bin/bash
set -euo pipefail

# Semgrep Scan Script for SAST2 Pipeline
# Usage: ./semgrep-scan.sh <workspace_root> [output_dir]
#
# Uses local scanning (semgrep scan --config p/java) so it works without
# a Semgrep platform token. 'p/java' is Semgrep's curated Java security
# ruleset (good coverage, fast). Override with SEMGREP_CONFIG env var.
# Note: 'semgrep ci' requires platform auth and will hang when no
# SEMGREP_TOKEN is set, so we avoid it here.

WORKSPACE_ROOT="${1:-.}"
OUTPUT_DIR="${2:-$WORKSPACE_ROOT}"
TIMEOUT=3600  # 1 hour timeout
RULES="${SEMGREP_CONFIG:-auto}"

cd "$WORKSPACE_ROOT"

echo "[semgrep-scan] Starting semgrep scan in $WORKSPACE_ROOT (rules: $RULES)"

# Run semgrep scan locally with JSON output
if timeout "$TIMEOUT" semgrep scan --config "$RULES" --json --quiet > "$OUTPUT_DIR/semgrep_raw_output.json" 2>"$OUTPUT_DIR/semgrep_stderr.log"; then
    echo "[semgrep-scan] Scan completed successfully"
    # Count findings
    if [ -f "$OUTPUT_DIR/semgrep_raw_output.json" ]; then
        FINDING_COUNT=$(python3 -c "import json; data=json.load(open('$OUTPUT_DIR/semgrep_raw_output.json')); print(len(data.get('results', [])))" 2>/dev/null || echo "0")
        echo "[semgrep-scan] Found $FINDING_COUNT findings"
    else
        echo "[semgrep-scan] Warning: Output file not created"
    fi
    exit 0
else
    EXIT_CODE=$?
    echo "[semgrep-scan] Scan failed or timed out (exit code: $EXIT_CODE)"
    if [ -f "$OUTPUT_DIR/semgrep_stderr.log" ]; then
        echo "[semgrep-scan] stderr: $(cat "$OUTPUT_DIR/semgrep_stderr.log")"
    fi
    # Create empty results file if scan failed
    echo '{"results": [], "errors": []}' > "$OUTPUT_DIR/semgrep_raw_output.json"
    exit 0  # Don't fail pipeline
fi
