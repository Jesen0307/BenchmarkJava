#!/bin/bash
set -euo pipefail

# SonarQube Scan Script for SAST Pipeline
# Usage: ./newestsonar.sh <workspace_root> <project_key> <host_url> <token> [output_dir] [java_binaries]
#
# Changes vs. sonarqube-scan.sh:
#   1) FIX classpath: sonar.java.libraries expects a comma-separated list of
#      JAR/ZIP paths (or dirs/globs), NOT the path to a text file that CONTAINS
#      a classpath. The old code passed "build/runtimeClasspath.txt" (a file) and
#      its fallback joined jars with ':' (wrong separator). Both are corrected:
#      the file is read and its ':' separators are turned into ','.
#   2) FIX export cap: the old export fails/truncates above 10,000 issues
#      (SonarQube's /api/issues/search hard cap is page * page_size <= 10000) and
#      its per-rule facet slicing aborts when the rules facet is truncated (>100
#      rules). This version slices recursively: by rule, then by severity, and
#      enumerates ALL Java rule keys via /api/rules/search when the facet is
#      incomplete, so it exports an arbitrarily large result set (e.g. 17k).

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
    # Analyze only the OWASP Benchmark testcode (everything else under src is skipped).
    -Dsonar.inclusions=**/org/owasp/benchmark/testcode/**
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

# Provide the dependency JARs to the Java analyzer so it does not degrade to
# "unresolved imports/types". sonar.java.libraries wants a COMMA-separated list
# of jar/zip paths (dirs and globs are also allowed) — NOT a path to a file that
# contains a classpath. Maven's dependency:build-classpath writes the classpath
# with the platform separator (':' on Linux), so convert it to commas.
LIB_CLASSPATH=""
if [ -f "$WORKSPACE_ROOT/build/runtimeClasspath.txt" ]; then
    LIB_CLASSPATH=$(tr ':' ',' < "$WORKSPACE_ROOT/build/runtimeClasspath.txt" | tr -d '\n')
    ENTRIES=$(printf '%s' "$LIB_CLASSPATH" | tr ',' '\n' | wc -l | tr -d ' ')
    echo "[sonarqube-scan] Using $ENTRIES java libraries from build/runtimeClasspath.txt"
elif [ -d "$WORKSPACE_ROOT/build" ]; then
    LIB_CLASSPATH=$(find "$WORKSPACE_ROOT/build" -name '*.jar' 2>/dev/null | paste -sd, -)
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
# an empty placeholder. Only SonarQube security issues that are still open
# (status OPEN or CONFIRMED, same as the dashboard) are exported; resolved
# issues (FIXED, FALSE_POSITIVE, ACCEPTED) and hotspots are intentionally excluded.
if [ "$TASK_SUCCEEDED" = "1" ]; then
    echo "[sonarqube-scan] Fetching open security issues from SonarQube..."
    python3 - "$HOST_URL" "$TOKEN" "$PROJECT_KEY" "$OUTPUT_DIR/sonar_raw.json" <<'PYEOF'
import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

host, token, project_key, out_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
PAGE_SIZE = 500
MAX_RESULTS = 10000  # SonarQube search API hard cap: page * page_size must stay <= 10000
SEVERITIES = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]

BASE_PARAMS = {
    "componentKeys": project_key,
    "impactSoftwareQualities": "SECURITY",
    "issueStatuses": "OPEN,CONFIRMED",
}


def fail(msg):
    print(f"[sonarqube-scan] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def api_request(path, params):
    url = f"{host}{path}?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{token}:".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:500]
        fail(f"HTTP {e.code} for {url}: {body}")
    except Exception as e:
        fail(f"request failed for {url}: {e}")


def is_security_issue(issue):
    # MQR (multi-quality-rule) mode: keep only SECURITY-impacted issues.
    impacts = issue.get("impacts")
    if impacts:
        return any((i.get("softwareQuality") or "").upper() == "SECURITY" for i in impacts)
    # Legacy mode: security issues are the VULNERABILITY type (hotspots excluded).
    return (issue.get("type") or "").upper() == "VULNERABILITY"


def probe_total(extra):
    return api_request("/api/issues/search", {**BASE_PARAMS, **extra, "ps": 1}).get("total", 0)


def fetch_all(extra):
    """Page one slice. Must stay under the 10,000 cap or the caller must slice more."""
    collected = []
    page = 1
    while True:
        data = api_request("/api/issues/search", {**BASE_PARAMS, **extra, "ps": PAGE_SIZE, "p": page})
        total = data.get("total", 0)
        if total > MAX_RESULTS:
            fail(f"slice {extra or 'ALL'} still has {total} issues, above the {MAX_RESULTS} API cap")
        issues = data.get("issues", [])
        collected.extend(issues)
        if not issues or page * PAGE_SIZE >= total:
            return collected
        page += 1


def all_java_rule_keys():
    """Enumerate every Java rule key (pageable, unlike the issues facet)."""
    keys = []
    page = 1
    while True:
        data = api_request("/api/rules/search", {"languages": "java", "ps": 500, "p": page, "f": "key"})
        rules = data.get("rules", [])
        keys.extend(r.get("key") for r in rules if r.get("key"))
        total = data.get("total", 0)
        if not rules or page * 500 >= total:
            break
        page += 1
    return keys


def slice_fetch(extra):
    """Return all issues for a filter, slicing by severity if it exceeds the cap."""
    total = probe_total(extra)
    if total == 0:
        return []
    if total <= MAX_RESULTS:
        return fetch_all(extra)
    if "severities" not in extra:
        out = []
        for sev in SEVERITIES:
            out.extend(slice_fetch({**extra, "severities": sev}))
        return out
    fail(f"cannot slice further: filter {extra} has {total} issues, above {MAX_RESULTS}")


# 1) How many open security issues are there, and which rules?
probe = api_request("/api/issues/search", {**BASE_PARAMS, "ps": 1, "facets": "rules"})
grand_total = probe.get("total", 0)
print(f"[sonarqube-scan] Server reports {grand_total} open security issues")

facets = {f["property"]: f["values"] for f in probe.get("facets", [])}
facet_rules = facets.get("rules", [])
facet_sum = sum(v["count"] for v in facet_rules)

if grand_total <= MAX_RESULTS:
    raw = fetch_all({})
else:
    # 2) Over the 10,000 cap: slice per rule. The rules facet is truncated to
    #    ~100 values, so enumerate all Java rules when the facet is incomplete.
    if facet_rules and facet_sum == grand_total:
        rule_keys = [v["val"] for v in facet_rules]
        print(f"[sonarqube-scan] Over {MAX_RESULTS}; slicing by {len(rule_keys)} rules (facet complete)")
    else:
        rule_keys = sorted(set(all_java_rule_keys()) | {v["val"] for v in facet_rules})
        print(f"[sonarqube-scan] Over {MAX_RESULTS}; facet partial ({facet_sum}/{grand_total}); "
              f"slicing by {len(rule_keys)} Java rules")
    raw = []
    for rk in rule_keys:
        raw.extend(slice_fetch({"rules": rk}))

# 3) De-duplicate by key and keep security issues only.
seen = set()
result = {"total_reported": grand_total, "issues": []}
for i in raw:
    key = i.get("key")
    if key in seen or not is_security_issue(i):
        continue
    seen.add(key)
    result["issues"].append({
        "key": key,
        "rule": i.get("rule"),
        "component": i.get("component"),
        "severity": i.get("severity"),
        "status": i.get("issueStatus") or i.get("status"),
        "message": i.get("message"),
        "line": i.get("line"),
        "textRange": i.get("textRange"),
    })

if len(result["issues"]) != grand_total:
    print(f"[sonarqube-scan] WARNING: exported {len(result['issues'])} but server reported "
          f"{grand_total}", file=sys.stderr)

with open(out_path, "w") as f:
    json.dump(result, f)
print(f"[sonarqube-scan] Exported {len(result['issues'])} open security issues to {out_path}")
PYEOF
else
    echo "[sonarqube-scan] Analysis did not complete; no findings exported." >&2
    exit 1
fi

echo "[sonarqube-scan] Done."
