#!/usr/bin/env python3
"""
Security Processor — Deduplicates and normalizes SAST findings.

Reads raw JSON output from SonarQube and Semgrep,
extracts essential fields, applies spatial deduplication (±2 lines),
and outputs a single normalized_findings.json optimized for LLM consumption.

Usage:
    python3 scripts/security_processor.py [--workspace <dir>]

Perubahan untuk eksperimen Benchmark (ditandai [BARU]/[UBAH]):
  - kategori berbasis CWE dan kata kunci Java (kripto, hash, random, LDAP, XPath, cmdi, trust boundary)
  - pemilihan kategori tidak lagi memilih "other" secara alfabetis ketika kategori lain tersedia
  - CWE dibawa dari SonarQube (export_sonar.py) dan Semgrep (metadata) hingga ke keluaran
"""

import argparse
import json
import re
import sys
from pathlib import Path


def load_json(path: Path) -> dict | list | None:
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[processor] WARN: Could not parse {path}: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Path normalization — strip project key prefixes like "VulnBank:"
# ---------------------------------------------------------------------------
def _normalize_path(file_path: str) -> str:
    """Remove project key prefix (e.g. 'VulnBank:app.py' -> 'app.py',
    'VulnBank:Dockerfile' -> 'Dockerfile')."""
    if ":" in file_path:
        prefix, rest = file_path.split(":", 1)
        if "." in rest or rest.startswith(("Dockerfile", "Makefile", "Jenkinsfile")):
            return rest
    return file_path


# ---------------------------------------------------------------------------
# Vulnerability category extraction — used to prevent merging unrelated vulns
# ---------------------------------------------------------------------------
# [BARU] CWE -> kategori (prioritas utama bila CWE tersedia; lebih andal daripada kata kunci)
_CWE_CATEGORY = {
    "89": "sql_injection", "79": "xss", "78": "command_injection", "22": "path_traversal",
    "90": "ldap_injection", "643": "xpath_injection",
    "328": "weak_hash", "327": "weak_crypto", "326": "weak_crypto",
    "330": "weak_random", "338": "weak_random",
    "614": "insecure_cookie", "1004": "insecure_cookie", "501": "trust_boundary",
}
# [BARU] urutan prioritas bila satu temuan memiliki beberapa kategori (yang lebih spesifik lebih dulu)
_PRIORITY = ["sql_injection", "xss", "command_injection", "path_traversal", "ldap_injection",
             "xpath_injection", "weak_hash", "weak_crypto", "weak_random", "insecure_cookie",
             "trust_boundary"]

_CATEGORY_KEYWORDS = {
    "sql_injection": ["sql", "injection", "tainted-sql", "generic-sql", "formatted-sql",
                       "sqlalchemy-execute", "db-cursor-execute"],
    "xss": ["xss", "cross-site", "make-response", "render", "escap"],
    "hardcoded_secret": ["hardcoded", "secret", "credential", "token-detected", "s6418"],
    "jwt": ["jwt", "pyjwt", "token", "auth"],
    "ssrf": ["ssrf", "server-side request", "tainted-flask-http"],
    "insecure_cookie": ["cookie", "set-cookie", "samesite", "secure-flag", "s2092", "s3330"],
    # [UBAH] "weak_crypto" sebelumnya memuat kata kunci random; dipisah agar tidak bercampur
    "weak_random": ["random", "prng", "pseudorandom", "s2245"],
    "weak_hash": ["md5", "sha1", "sha-1", "s4790", "hash algorithm", "use-of-md5", "use-of-sha1"],
    "weak_crypto": ["cipher", "des-is-deprecated", "desede", "s5542", "s5547", "s2278", "encryption"],
    "command_injection": ["command-injection", "command injection", "os command", "s2076"],
    "ldap_injection": ["ldap", "s2078"],
    "xpath_injection": ["xpath", "s2091"],
    "trust_boundary": ["trust boundary", "trust-boundary", "tainted-session"],
    "debug": ["debug", "debugger", "s4507"],
    "cors": ["cors", "s5122"],
    "csrf": ["csrf", "s4502", "s3752"],
    "dos": ["dos", "denial", "backtracking", "s5852", "resource-consumption"],
    "path_traversal": ["path", "traversal", "safe_join", "send_from_directory"],
    "docker": ["docker", "container", "s6470", "s6471"],
    "supply_chain": ["unpinned", "mutable", "commit-sha", "supply-chain"],
    "cert_validation": ["certificate", "cert", "ssl", "tls", "s4830", "disabled-cert"],
    "framework_dep": ["affected versions", "vulnerable to", "cve-"],
}


def _classify_finding(rule_id: str, message: str, cwes=()) -> set[str]:
    """Return set of category tags that match this finding.
    [UBAH] CWE (bila ada) menentukan kategori; kata kunci menjadi cadangan."""
    from_cwe = {_CWE_CATEGORY[c] for c in cwes if c in _CWE_CATEGORY}
    if from_cwe:
        return from_cwe
    text = f"{rule_id} {message}".lower()
    cats = set()
    for cat, keywords in _CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                cats.add(cat)
                break
    return cats if cats else {"other"}


def _pick_category(cats: set[str]) -> str:
    """[BARU] Pilih satu kategori representatif. Kode lama memakai sorted(cats)[0], yang memilih
    'other' secara alfabetis setiap kali tag 'other' ikut tergabung (mis. Sonar 'weak' + Semgrep tanpa
    kata kunci), sehingga temuan kripto dan hash terkumpul pada 'other'."""
    real = [c for c in cats if c != "other"]
    if not real:
        return "other"
    return sorted(real, key=lambda c: (_PRIORITY.index(c) if c in _PRIORITY else len(_PRIORITY), c))[0]


def _categories_overlap(cats_a: set[str], cats_b: set[str]) -> bool:
    """Two findings can merge only if they share at least one category,
    or one side is tagged 'other' (generic/unclassified)."""
    if "other" in cats_a or "other" in cats_b:
        return True
    return bool(cats_a & cats_b)


# ---------------------------------------------------------------------------
# SonarQube — expects dict with "issues" and/or "hotspots" keys, or a list
# ---------------------------------------------------------------------------
def parse_sonarqube(data) -> list[dict]:
    if not data:
        return []

    if isinstance(data, list):
        items = data
    else:
        items = []

        # Parse issues
        for issue in data.get("issues", []):
            items.append({
                "tool": "SonarQube",
                "file_path": _normalize_path(issue.get("component", issue.get("file", ""))),
                "line_number": issue.get("line")
                                         or (issue.get("textRange") or {}).get("startLine")
                                         or 0,
                "severity": issue.get("severity",
                                      issue.get("impacts", [{}])[0].get("severity", "UNKNOWN")),
                "rule_id": issue.get("rule", issue.get("key", "")),
                "message": issue.get("message", ""),
                "cwes": [str(c) for c in issue.get("cwes", [])],          # [BARU]
                "_hotspot_key": None,
            })

        # Parse hotspots
        for hs in data.get("hotspots", []):
            items.append({
                "tool": "SonarQube",
                "file_path": _normalize_path(hs.get("component", "")),
                "line_number": hs.get("line")
                                       or (hs.get("textRange") or {}).get("startLine")
                                       or 0,
                "severity": (hs.get("vulnerabilityProbability") or "MEDIUM").upper(),
                "rule_id": hs.get("ruleKey", ""),
                "message": hs.get("message", ""),
                "cwes": [str(c) for c in hs.get("cwes", [])],             # [BARU]
                "_hotspot_key": hs.get("key"),
            })

    out = []
    for item in items:
        out.append({
            "tool": "SonarQube",
            "file_path": item["file_path"],
            "line_number": item["line_number"],
            "severity": item["severity"],
            "rule_id": item["rule_id"],
            "message": item["message"],
            "cwes": item.get("cwes", []),
            "_hotspot_key": item.get("_hotspot_key"),
        })
    return out


# ---------------------------------------------------------------------------
# Semgrep — expects `results` array from `semgrep scan --json`
# ---------------------------------------------------------------------------
def parse_semgrep(data) -> list[dict]:
    if not data:
        return []
    results = data.get("results", []) if isinstance(data, dict) else data
    out = []
    for r in results:
        meta = r.get("extra", {}).get("metadata", {}) or {}               # [BARU] CWE dari metadata aturan
        cw = meta.get("cwe", [])
        cw = cw if isinstance(cw, list) else [cw]
        cwes = sorted(set(re.findall(r"CWE-(\d+)", " ".join(map(str, cw)))))
        out.append({
            "tool": "Semgrep",
            "file_path": r.get("path", ""),
            "line_number": (r.get("start") or {}).get("line") or 0,
            "severity": r.get("extra", {}).get("severity", "UNKNOWN"),
            "rule_id": r.get("check_id", ""),
            "message": r.get("extra", {}).get("message", ""),
            "cwes": cwes,
        })
    return out


# ---------------------------------------------------------------------------
# Spatial deduplication — merge SAST findings that:
#   1. Share the same normalized file path
#   2. Are within ±2 lines
#   3. Share at least one vulnerability category (or one is unclassified)
# ---------------------------------------------------------------------------
def deduplicate_sast(findings: list[dict]) -> list[dict]:
    findings_sorted = sorted(findings, key=lambda f: (f["file_path"], f["line_number"]))
    merged: list[dict] = []

    for f in findings_sorted:
        f_cats = _classify_finding(f["rule_id"], f["message"], f.get("cwes", []))
        attached = False
        for m in merged:
            if m["file_path"] != f["file_path"]:
                continue
            if abs(m["line_number"] - f["line_number"]) > 2:
                continue
            # Category gate: only merge if vulnerability types are related
            if not _categories_overlap(m["_categories"], f_cats):
                continue

            # Merge into existing finding
            if f["tool"] not in m["detected_by"]:
                m["detected_by"].append(f["tool"])
            if f["rule_id"] and f["rule_id"] not in m["rule_ids"]:
                m["rule_ids"].append(f["rule_id"])
            if f["message"] and f["message"] not in m["messages"]:
                m["messages"].append(f["message"])
            if _sev_rank(f["severity"]) > _sev_rank(m["severity"]):
                m["severity"] = f["severity"]
            m["_categories"] |= f_cats
            m["_cwes"] |= set(f.get("cwes", []))                          # [BARU]

            # Carry hotspot key if present
            if f.get("_hotspot_key") and f["_hotspot_key"] not in m.get("_hotspot_keys", []):
                m.setdefault("_hotspot_keys", []).append(f["_hotspot_key"])
            attached = True
            break

        if not attached:
            merged.append({
                "file_path": f["file_path"],
                "line_number": f["line_number"],
                "severity": f["severity"],
                "rule_ids": [f["rule_id"]] if f["rule_id"] else [],
                "messages": [f["message"]] if f["message"] else [],
                "detected_by": [f["tool"]],
                "category": "SAST",
                "_categories": f_cats,
                "_cwes": set(f.get("cwes", [])),                          # [BARU]
                "_hotspot_keys": [f["_hotspot_key"]] if f.get("_hotspot_key") else [],
            })

    # Strip internal fields before returning
    for m in merged:
        cats = m.pop("_categories", set())
        m["category"] = _pick_category(cats)                              # [UBAH]
        m["cwes"] = sorted(m.pop("_cwes", set()), key=int)                # [BARU]
        rule = m["rule_ids"][0] if m.get("rule_ids") else "unknown"
        m["rule_cluster_id"] = f"{m['file_path']}::{rule}"
        keys = m.pop("_hotspot_keys", [])
        if keys:
            m["sonarqube_hotspot_keys"] = keys

    return merged


def _sev_rank(sev: str) -> int:
    return {"BLOCKER": 5, "CRITICAL": 4, "HIGH": 3, "MAJOR": 3, "MEDIUM": 2, "MINOR": 1, "LOW": 0, "INFO": 0}.get(
        sev.upper(), 2
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def build_batches(findings: list[dict], max_per_batch: int = 100) -> list[dict]:
    """Group deduplicated findings into category-based batches for triage."""
    from collections import defaultdict
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_cat[f.get("category", "other")].append(f)

    batches: list[dict] = []
    for cat in by_cat.keys():
        members = by_cat[cat]
        total = len(members)
        for i in range(0, len(members), max_per_batch):
            chunk = members[i : i + max_per_batch]
            batches.append({
                "category": cat,
                "count": len(chunk),
                "category_total": total,
                "findings": chunk,
            })
    return batches


def main():
    parser = argparse.ArgumentParser(description="Normalize & deduplicate security findings")
    parser.add_argument("--workspace", default=".", help="Workspace root containing scanner outputs")
    parser.add_argument("--max-batch", type=int, default=15,
                        help="Max findings per triage batch (default 15)")
    args = parser.parse_args()
    ws = Path(args.workspace)
    sonar_data = load_json(ws / "sonar_raw.json")
    semgrep_data = load_json(ws / "semgrep_raw_output.json")

    raw_sonar = parse_sonarqube(sonar_data)
    raw_semgrep = parse_semgrep(semgrep_data)
    sast_findings = raw_sonar + raw_semgrep
    deduped_sast = deduplicate_sast(sast_findings)

    batches = build_batches(deduped_sast, args.max_batch)

    output = {
        "summary": {
            "sonar_raw_count": len(raw_sonar),
            "semgrep_raw_count": len(raw_semgrep),
            "sast_deduplicated_count": len(deduped_sast),
            "batch_count": len(batches),
        },
        "sast": deduped_sast,
        "triage_batches": batches,
    }

    out_path = ws / "normalized_findings.json"
    batch_path = ws / "triage_batches.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    with open(batch_path, "w") as f:
        json.dump({"triage_batches": batches}, f, indent=2)

    print(f"[processor] Wrote {out_path}  —  SAST: {len(deduped_sast)}")
    print(f"[processor] Wrote {batch_path}  —  batches: {len(batches)}")
    seen = set()
    for b in batches:
        if b['category'] not in seen:
            seen.add(b['category'])
            print(f"  - {b['category']}: {b['category_total']} findings")


if __name__ == "__main__":
    main()
