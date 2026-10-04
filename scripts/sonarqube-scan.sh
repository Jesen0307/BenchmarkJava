# 1) ganti sumber dan tambah versi
-    -Dsonar.sources=src
+    -Dsonar.sources=src/main/java/org/owasp/benchmark/testcode
+    -Dsonar.projectVersion="${SONAR_PROJECT_VERSION:-0}"

# 2) hapus token dari argumen scanner
-    -Dsonar.token="$TOKEN"
# lalu sebelum baris "SCAN_START=$(date +%s)" tambahkan:
+export SONAR_TOKEN="$TOKEN"

# 3) classpath: pakai ISI berkas, dipisah koma
-    LIB_CLASSPATH="build/runtimeClasspath.txt"
+    LIB_CLASSPATH="$(tr ':' ',' < build/runtimeClasspath.txt)"

# 4) ganti seluruh blok  python3 - ... <<'PYEOF' ... PYEOF  dengan satu baris:
+    python3 "$(dirname "$0")/export_sonar.py" "$HOST_URL" "$TOKEN" "$PROJECT_KEY" "$OUTPUT_DIR/sonar_raw.json"
