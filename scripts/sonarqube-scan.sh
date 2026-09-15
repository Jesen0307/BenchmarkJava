#!/bin/bash
set -euo pipefail

# SonarQube Scan Script for SAST Pipeline
# Usage: ./sonarqube-scan.sh <workspace_root> <project_key> <host_url> <token> [output_dir] [java_binaries]
#   java_binaries = relative path to compiled classes (e.g. target/classes) for
#                   the SonarQube Java analyzer. Optional.
#
# Runs the SonarScanner CLI natively on the same filesystem as the workspace —
# no Docker, no mounts. The CLI must be installed on PATH (see the
# 'Install Dependencies' stage in the Jenkinsfile).

WORKSPACE_ROOT="${1:-.}"
PROJECT_KEY="${2:-}"
HOST_URL="${3:-http://localhost:9000}"
TOKEN="${4:-}"
OUTPUT_DIR="${5:-$WORKSPACE_ROOT}"
JAVA_BINARIES="${6:-}"
SCANNER="${SONAR_SCANNER:-sonar-scanner}"
SCAN_TIMEOUT=600  # 10 minutes for the analysis submission (upload)
POLL_TIMEOUT=900  # 15 minutes to wait for server-side CE completion + export

if [ -z "$PROJECT_KEY" ] || [ -z "$TOKEN" ]; then
    echo "[sonarqube-scan] ERROR: project key and token are required" >&2
    exit 2
fi

if ! command -v "$SCANNER" >/dev/null 2>&1; then
    echo "[sonarqube-scan] ERROR: '$SCANNER' not found on PATH. Install the SonarScanner CLI first (e.g. in the 'Install Dependencies' stage)." >&2
    exit 2
fi

cd "$WORKSPACE_ROOT"
mkdir -p "$OUTPUT_DIR"

echo "[sonarqube-scan] Starting SonarQube scan for project '$PROJECT_KEY'"
echo "[sonarqube-scan] Host: $HOST_URL"
echo "[sonarqube-scan] Scanner: $SCANNER"

SCAN_ARGS=(
    -Dsonar.projectKey="$PROJECT_KEY"
    -Dsonar.projectName="$PROJECT_KEY"
    -Dsonar.sources=src
    -Dsonar.host.url="$HOST_URL"
    -Dsonar.token="$TOKEN"
    # Use the JVM that launched the scanner instead of provisioning a separate
    # JRE (avoids a download + extra failure mode on the agent).
    -Dsonar.scanner.skipJreProvisioning=true
)

# Prefer sonar.java.binaries when provided; otherwise auto-detect the Java binary
# output produced by Maven or Gradle.
BINARIES="$JAVA_BINARIES"
if [ -z "$BINARIES" ]; then
    if [ -d "$WORKSPACE_ROOT/target/classes" ]; then
        BINARIES="target/classes"
    elif [ -d "$WORKSPACE_ROOT/build/classes/java/main" ]; then
        BINARIES="build/classes/java/main"
    fi
fi
if [ -n "$BINARIES" ]; then
    echo "[sonarqube-scan] Using java binaries: $BINARIES"
    SCAN_ARGS+=(-Dsonar.java.binaries="$BINARIES")
else
    echo "[sonarqube-scan] WARNING: no compiled Java classes found. SonarQube Java analysis requires the project to be built first (e.g. ./gradlew classes)." >&2
fi

# Provide a compile classpath so Java analysis is precise instead of degrading to
# "unresolved imports". Best-effort: if we cannot build one, warn but continue.
LIB_CLASSPATH=""
if [ -f "$WORKSPACE_ROOT/build/runtimeClasspath.txt" ]; then
    LIB_CLASSPATH="build/runtimeClasspath.txt"
elif [ -d "$WORKSPACE_ROOT/build" ]; then
    LIB_CLASSPATH=$(find "$WORKSPACE_ROOT/build" -name '*.jar' 2>/dev/null | tr '\n' ':')
fi
if [ -n "${LIB_CLASSPATH:-}" ]; then
    SCAN_ARGS+=(-Dsonar.java.libraries="$LIB_CLASSPATH")
else
    echo "[sonarqube-scan] WARNING: could not build a java classpath; Java analysis may be less precise." >&2
fi

# Run the scanner. Any real failure here is fatal and visible.
SCAN_START=$(date +%s)

if timeout "$SCAN_TIMEOUT" "$SCANNER" "${SCAN_ARGS[@]}" > "$OUTPUT_DIR/sonar_scanner_stdout.log" 2>&1; then
    echo "[sonarqube-scan] Analysis submitted successfully"
else
    EXIT_CODE=$?
    echo "[sonarqube-scan] Scan failed or timed out (exit code: $EXIT_CODE)" >&2
    cat "$OUTPUT_DIR/sonar_scanner_stdout.log" >&2
    exit 1
fi

echo "[sonarqube-scan] Analysis submitted in $(( $(date +%s) - SCAN_START ))s. Waiting for server-side completion..."

# The scanner logs the Compute Engine task id on the "More about the report
# processing at <host>/api/ce/task?id=<uuid>" line. Poll that task endpoint:
# it works with a scan-only token, whereas /api/ce/component requires project
# Browse permission and returns 403 for scan tokens.
TASK_ID=""
if [ -f "$OUTPUT_DIR/sonar_scanner_stdout.log" ]; then
    TASK_ID=$(grep -oE 'api/ce/task\?id=[a-fA-F0-9-]+' "$OUTPUT_DIR/sonar_scanner_stdout.log" \
              | head -1 | sed 's/.*id=//' || true)
fi
if [ -n "$TASK_ID" ]; then
    echo "[sonarqube-scan] Polling CE task: $TASK_ID"
else
    echo "[sonarqube-scan] WARNING: could not find CE task id in scanner log; status cannot be confirmed." >&2
fi

POLL_START=$(date +%s)
TASK_SUCCEEDED=0

while true; do
    if [ -n "$TASK_ID" ]; then
        TASK_JSON=$(curl -sf -u "$TOKEN:" "$HOST_URL/api/ce/task?id=$TASK_ID" 2>/dev/null || echo '{}')
        TASK_STATUS=$(echo "$TASK_JSON" | python3 -c "
import json,sys
try:
    print(json.load(sys.stdin).get('task',{}).get('status','UNKNOWN'))
except Exception:
    print('UNKNOWN')
" 2>/dev/null || echo 'UNKNOWN')
    else
        TASK_STATUS='NO_TASK'
    fi

    case "$TASK_STATUS" in
        SUCCESS)
            echo "[sonarqube-scan] Analysis completed successfully (task: SUCCESS)"
            TASK_SUCCEEDED=1
            break
            ;;
        FAILED|CANCELED)
            echo "[sonarqube-scan] Analysis task $TASK_STATUS" >&2
            exit 1
            ;;
        PENDING|IN_PROGRESS|NO_TASK)
            echo "[sonarqube-scan] Analysis in progress ($TASK_STATUS)..."
            ;;
        *)
            echo "[sonarqube-scan] Unknown task status: $TASK_STATUS" >&2
            exit 1
            ;;
    esac

    if [ $(( $(date +%s) - POLL_START )) -ge "$POLL_TIMEOUT" ]; then
        echo "[sonarqube-scan] Polling timed out after ${POLL_TIMEOUT}s" >&2
        exit 1
    fi

    sleep 10
done

# Export real findings so the downstream processor gets actual data instead of
# an empty placeholder. Issues are the priority; hotspots are best-effort (the
# scan token may not have the privilege to list them).
if [ "$TASK_SUCCEEDED" = "1" ]; then
    echo "[sonarqube-scan] Fetching findings from SonarQube..."
    python3 - "$HOST_URL" "$TOKEN" "$PROJECT_KEY" "$OUTPUT_DIR/sonar_raw.json" <<'PYEOF'
import json
import sys
import urllib.request

host, token, project_key, out_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
page_size = 500
result = {"issues": [], "hotspots": []}


def api_request(path):
    url = f"{host}{path}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Basic " + __import__("base64").b64encode(
        f"{token}:".encode()).decode())
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


# Issues (paged) - only security issues
page = 1
while True:
    try:
        data = api_request(
            f"/api/issues/search?componentKeys={project_key}&impactSoftwareQualities=SECURITY&ps={page_size}&p={page}")
    except Exception as e:
        print(f"[sonarqube-scan] WARNING: could not fetch issues: {e}", file=sys.stderr)
        break
    issues = data.get("issues", [])
    for i in issues:
        result["issues"].append({
            "key": i.get("key"),
            "rule": i.get("rule"),
            "component": i.get("component"),
            "severity": i.get("severity"),
            "message": i.get("message"),
            "line": i.get("line"),
            "textRange": i.get("textRange"),
        })
    total = data.get("total", 0)
    if not issues or page * page_size >= total:
        break
    page += 1

with open(out_path, "w") as f:
    json.dump(result, f)
print(f"[sonarqube-scan] Exported {len(result['issues'])} security issues to {out_path}")
PYEOF
else
    echo "[sonarqube-scan] Analysis did not complete; no findings exported." >&2
    exit 1
fi

echo "[sonarqube-scan] Done."