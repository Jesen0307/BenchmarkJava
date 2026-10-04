#!/bin/bash
set -euo pipefail

# Semgrep Scan Script (versi eksperimen skripsi)
# Usage: ./semgrep-scan.sh <workspace_root> [output_dir]
#
# Perbedaan dari versi lama:
#  - Aturan WAJIB berupa berkas/folder lokal yang dipatok (default: config/semgrep-rules).
#    '--config auto' ditolak kecuali ALLOW_AUTO=1, karena aturan registry berubah dari waktu ke
#    waktu dan 'auto' memaksa metrik aktif -> hasil antar-iterasi tidak sebanding.
#  - Target pemindaian dibatasi ke folder testcode (override: SEMGREP_PATHS).
#  - FAIL-CLOSED: bila pemindaian gagal atau tidak memindai berkas apa pun, skrip keluar dengan
#    kode 1. Versi lama menulis hasil kosong dan exit 0, sehingga G3 akan lolos palsu.
#  - Mencatat versi, hash aturan, dan jumlah berkas ke semgrep_meta.json (bukti replikasi).

WORKSPACE_ROOT="${1:-.}"
OUTPUT_DIR="${2:-$WORKSPACE_ROOT}"
TIMEOUT=3600
RULES="${SEMGREP_CONFIG:-config/semgrep-rules}"
DEFAULT_TARGET="src/main/java/org/owasp/benchmark/testcode"

cd "$WORKSPACE_ROOT"
mkdir -p "$OUTPUT_DIR"
OUT="$OUTPUT_DIR/semgrep_raw_output.json"
ERR="$OUTPUT_DIR/semgrep_stderr.log"
rm -f "$OUT" "$OUTPUT_DIR/semgrep_meta.json"   # tidak ada hasil lama yang terbawa

if [ "$RULES" = "auto" ] && [ "${ALLOW_AUTO:-0}" != "1" ]; then
    echo "[semgrep-scan] ERROR: --config auto tidak diizinkan (tidak dapat direplikasi). Gunakan aturan lokal yang dipatok." >&2
    exit 2
fi
if [ "$RULES" != "auto" ] && [ ! -e "$RULES" ]; then
    echo "[semgrep-scan] ERROR: aturan '$RULES' tidak ditemukan" >&2
    exit 2
fi

TARGET="${SEMGREP_PATHS:-}"
if [ -z "$TARGET" ]; then
    if [ -d "$DEFAULT_TARGET" ]; then TARGET="$DEFAULT_TARGET"; else TARGET="."; fi
fi

echo "[semgrep-scan] workspace=$WORKSPACE_ROOT rules=$RULES target=$TARGET"

EXTRA=()
[ "$RULES" != "auto" ] && EXTRA+=(--metrics=off)

if ! timeout "$TIMEOUT" semgrep scan --config "$RULES" "${EXTRA[@]}" --disable-version-check \
        --json --quiet -o "$OUT" $TARGET 2>"$ERR"; then
    echo "[semgrep-scan] ERROR: pemindaian gagal atau timeout. stderr:" >&2
    cat "$ERR" >&2 || true
    exit 1
fi

python3 - "$OUT" "$RULES" "$TARGET" "$OUTPUT_DIR/semgrep_meta.json" <<'PYEOF'
import hashlib, json, os, subprocess, sys
out, rules, target, meta = sys.argv[1:5]
try:
    d = json.load(open(out))
except Exception as e:
    sys.exit(f"[semgrep-scan] ERROR: keluaran bukan JSON valid: {e}")
scanned = d.get("paths", {}).get("scanned", [])
if not scanned:
    sys.exit("[semgrep-scan] ERROR: tidak ada berkas yang dipindai (hasil kosong tidak boleh dianggap bersih)")
h = hashlib.sha256()
if os.path.isdir(rules):
    for root, _, files in sorted(os.walk(rules)):
        for f in sorted(files):
            h.update(open(os.path.join(root, f), "rb").read())
elif os.path.isfile(rules):
    h.update(open(rules, "rb").read())
ver = subprocess.run(["semgrep", "--version"], capture_output=True, text=True).stdout.strip().splitlines()[-1]
info = {"semgrep_version": ver, "rules": rules, "rules_sha256": h.hexdigest(), "target": target,
        "files_scanned": len(scanned), "findings": len(d.get("results", [])),
        "parse_errors": len(d.get("errors", []))}
json.dump(info, open(meta, "w"), indent=2)
print(f"[semgrep-scan] OK: {info['findings']} temuan pada {info['files_scanned']} berkas (semgrep {ver})")
PYEOF
exit 0
