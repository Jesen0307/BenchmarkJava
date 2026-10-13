#!/bin/bash
set -euo pipefail

# Semgrep Scan Script for SAST2 Pipeline (testcode-scoped variant)
# Usage: ./changed.sh <workspace_root> [output_dir]
#
# Change vs. semgrep-scan.sh: the scan is restricted to the OWASP Benchmark
# testcode directory. semgrep only scans the paths you hand it, so we pass the
# testcode directory as the scan target instead of the workspace root ('.').
# This removes the workflow/config noise (e.g. .github/dependabot.yml) that
# never maps to a Benchmark test case.
#
# Uses local scanning (semgrep scan --config p/java) so it works without
# a Semgrep platform token. Override with SEMGREP_CONFIG env var.
# Note: 'semgrep ci' requires platform auth and will hang when no
# SEMGREP_TOKEN is set, so we avoid it here.

WORKSPACE_ROOT="${1:-.}"
OUTPUT_DIR="${2:-$WORKSPACE_ROOT}"
TIMEOUT=3600  # 1 hour timeout
RULES="${SEMGREP_CONFIG:-auto}"
# Only the Benchmark test cases are scanned/scored.
TESTCODE_PATH="${TESTCODE_PATH:-src/main/java/org/owasp/benchmark/testcode}"

cd "$WORKSPACE_ROOT"

if [ ! -d "$TESTCODE_PATH" ]; then
    echo "[semgrep-scan] ERROR: testcode path '$TESTCODE_PATH' not found under $WORKSPACE_ROOT" >&2
    exit 2
fi

echo "[semgrep-scan] Starting semgrep scan of '$TESTCODE_PATH' (rules: $RULES)"

# Run semgrep scan locally with JSON output, scoped to the testcode directory.
if timeout "$TIMEOUT" semgrep scan --config "$RULES" --json --quiet "$TESTCODE_PATH" > "$OUTPUT_DIR/semgrep_raw_output.json" 2>"$OUTPUT_DIR/semgrep_stderr.log"; then
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
