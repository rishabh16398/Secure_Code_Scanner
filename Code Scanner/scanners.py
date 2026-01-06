import json
import re
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any

# =========================
# Helper: run commands
# =========================

def _run_cmd_to_file(cmd, cwd: Path, outfile: Optional[Path]):
    """
    Run a command and optionally write stdout to a file.
    Returns subprocess.CompletedProcess or None if the binary is missing.
    """
    print(f"[DEBUG] Running (to_file): {' '.join(cmd)} (cwd={cwd})")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except FileNotFoundError as e:
        print(f"[ERROR] Command not found: {cmd[0]} – {e}")
        return None

    if proc.stdout and outfile is not None:
        outfile.write_text(proc.stdout)

    if proc.stderr:
        print(f"[DEBUG] {cmd[0]} stderr (first 400 chars):\n{proc.stderr[:400]}")

    if proc.returncode not in (0, 1):
        print(f"[WARN] {cmd[0]} exited with code {proc.returncode}")

    return proc


def _run_cmd_capture(cmd, cwd: Path):
    """
    Run a command and return (CompletedProcess|None, stdout_text).
    Used when JSON is printed to stdout.
    """
    print(f"[DEBUG] Running (capture): {' '.join(cmd)} (cwd={cwd})")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except FileNotFoundError as e:
        print(f"[ERROR] Command not found: {cmd[0]} – {e}")
        return None, ""

    if proc.stdout:
        print(f"[DEBUG] {cmd[0]} stdout (first 400 chars):\n{proc.stdout[:400]}")
    if proc.stderr:
        print(f"[DEBUG] {cmd[0]} stderr (first 400 chars):\n{proc.stderr[:400]}")

    if proc.returncode not in (0, 1):
        print(f"[WARN] {cmd[0]} exited with code {proc.returncode}")

    return proc, proc.stdout or ""


# =========================
# Shared regex + normalizer
# =========================

CWE_RE = re.compile(r"(CWE-\d+)")
CVE_RE = re.compile(r"(CVE-\d{4}-\d+)")


def normalize_cwe(raw):
    """
    Normalize CWE identifiers so that:
      - 'CWE-79'                      -> 'CWE-79'
      - 'CWE-79: blah blah'           -> 'CWE-79'
      - '79'                          -> 'CWE-79'
      - None / ''                     -> 'CWE-UNKNOWN'
    """
    if not raw:
        return "CWE-UNKNOWN"

    s = str(raw).strip()

    m = CWE_RE.search(s)
    if m:
        return m.group(1)

    if s.isdigit():
        return f"CWE-{s}"

    return s


# =========================
# SEMGREP (SAST #1)
# =========================

def run_semgrep(project_path: Path):
    """
    Run Semgrep with --config auto on the project.
    Produces _semgrep.json in the project root.
    """
    out_json = project_path / "_semgrep.json"
    cmd = [
        "semgrep",
        "scan",
        "--config", "auto",
        "--json",
        "-q",
        str(project_path),
    ]

    _run_cmd_to_file(cmd, project_path, out_json)

    findings = []

    if not out_json.exists():
        print("[WARN] Semgrep JSON not found – skipping.")
        return findings

    try:
        data = json.loads(out_json.read_text() or "{}")
    except Exception as e:
        print(f"[WARN] Could not parse Semgrep JSON: {e}")
        return findings

    for res in data.get("results", []):
        extra = res.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}

        cwes = meta.get("cwe") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        if not cwes:
            cwes = ["CWE-UNKNOWN"]

        severity = extra.get("severity", "INFO")
        path = res.get("path")
        message = extra.get("message", "")
        rule_id = res.get("check_id")

        for cwe in cwes:
            findings.append({
                "scanner": "semgrep",
                "type": "SAST",
                "rule_id": rule_id,
                "cwe": normalize_cwe(cwe),
                "severity": severity.upper(),
                "file": path,
                "line": res.get("start", {}).get("line"),
                "message": message,
            })

    print(f"[DEBUG] Semgrep findings: {len(findings)}")
    return findings


# =========================
# BEARER (SAST #2)
# =========================

def run_bearer(project_path: Path):
    """
    Run Bearer SAST on the project root.
    JSON is often severity buckets at top-level.
    """
    findings = []

    cmd = [
        "bearer",
        "scan",
        str(project_path),
        "--report", "security",
        "--format", "json",
    ]
    proc, out = _run_cmd_capture(cmd, cwd=project_path)

    if proc is None or not out.strip():
        print("[WARN] Bearer produced no JSON – skipping.")
        return findings

    try:
        data = json.loads(out)
    except Exception as e:
        print(f"[WARN] Could not parse Bearer JSON: {e}")
        return findings

    raw_findings: list[tuple[dict, str]] = []

    if isinstance(data, dict):
        for sev_key in ["critical", "high", "medium", "low", "info", "unknown"]:
            items = data.get(sev_key)
            if isinstance(items, list):
                for f in items:
                    if isinstance(f, dict):
                        raw_findings.append((f, sev_key.upper()))

    if not raw_findings:
        if isinstance(data, list):
            for f in data:
                if isinstance(f, dict):
                    raw_findings.append((f, (f.get("severity") or "UNKNOWN").upper()))
        elif isinstance(data, dict) and isinstance(data.get("findings"), list):
            for f in data["findings"]:
                if isinstance(f, dict):
                    raw_findings.append((f, (f.get("severity") or "UNKNOWN").upper()))
        else:
            def _collect(node, default_sev="UNKNOWN"):
                if isinstance(node, dict):
                    if isinstance(node.get("findings"), list):
                        for f in node["findings"]:
                            if isinstance(f, dict):
                                raw_findings.append(
                                    (f, (f.get("severity") or default_sev).upper())
                                )
                    for v in node.values():
                        _collect(v, default_sev)
                elif isinstance(node, list):
                    for item in node:
                        _collect(item, default_sev)

            _collect(data)

    for f, sev in raw_findings:
        cwe_ids = f.get("cwe_ids") or []
        cwe = "CWE-UNKNOWN"
        if isinstance(cwe_ids, list) and cwe_ids:
            first = str(cwe_ids[0])
            if first.startswith("CWE-"):
                cwe = normalize_cwe(first)
            else:
                cwe = normalize_cwe(f"CWE-{first}")

        file_path = f.get("full_filename") or f.get("filename") or f.get("file")
        line = f.get("line_number") or f.get("line")

        rule_id = f.get("id") or f.get("rule_id") or f.get("rule")
        title = f.get("title") or f.get("description") or f.get("message") or ""

        text_for_regex = " ".join([
            title or "",
            f.get("description") or "",
            f.get("message") or "",
        ])
        m_cve = CVE_RE.search(text_for_regex)
        cve = m_cve.group(1) if m_cve else None

        findings.append({
            "scanner": "bearer",
            "type": "SAST",
            "rule_id": rule_id,
            "cwe": cwe,
            "severity": sev,
            "file": file_path,
            "line": line,
            "message": title,
            "cve": cve,
        })

    print(f"[DEBUG] Bearer findings (normalized): {len(findings)}")
    return findings


# =========================
# BANDIT (SAST #3 – Python)
# =========================

def run_bandit(project_path: Path):
    """
    Run Bandit recursively on the project for Python SAST.
    Uses CWE IDs from issue_cwe.id (NOT Bandit test IDs).
    """
    findings = []
    out_json = project_path / "_bandit.json"

    cmd = [
        "bandit",
        "-r",
        str(project_path),
        "-f",
        "json",
        "-o",
        str(out_json),
    ]

    proc, _ = _run_cmd_capture(cmd, cwd=project_path)

    if proc is None:
        print("[WARN] Bandit not found – skipping.")
        return findings

    if not out_json.exists():
        print("[WARN] Bandit JSON not found – skipping.")
        return findings

    try:
        data = json.loads(out_json.read_text() or "{}")
    except Exception as e:
        print(f"[WARN] Could not parse Bandit JSON: {e}")
        return findings

    for issue in data.get("results", []):
        filename = issue.get("filename")
        line = issue.get("line_number")
        severity = (issue.get("issue_severity") or "LOW").upper()
        msg = issue.get("issue_text") or ""

        issue_cwe = issue.get("issue_cwe") or {}
        cwe_id = issue_cwe.get("id")

        cwe = normalize_cwe(f"CWE-{cwe_id}") if cwe_id else "CWE-UNKNOWN"

        findings.append({
            "scanner": "bandit",
            "type": "SAST",
            "rule_id": issue.get("test_id"),  # ok to keep internally
            "cwe": cwe,
            "severity": severity,
            "file": filename,
            "line": line,
            "message": msg,
        })

    print(f"[DEBUG] Bandit findings: {len(findings)}")
    return findings


# =========================
# TRIVY (Dependency #1)
# =========================

def run_trivy(project_path: Path):
    """
    Run Trivy filesystem scan for dependency vulns.
    Produces _trivy.json.
    """
    out_json = project_path / "_trivy.json"
    cmd = [
        "trivy",
        "fs",
        "--security-checks", "vuln",
        "--format", "json",
        "--quiet",
        str(project_path),
    ]

    _run_cmd_to_file(cmd, project_path, out_json)

    findings = []

    if not out_json.exists():
        print("[WARN] Trivy JSON not found – skipping.")
        return findings

    try:
        data = json.loads(out_json.read_text() or "{}")
    except Exception as e:
        print(f"[WARN] Could not parse Trivy JSON: {e}")
        return findings

    for result in data.get("Results", []):
        vulns = result.get("Vulnerabilities") or []
        for v in vulns:
            cve = v.get("VulnerabilityID")
            pkg = v.get("PkgName")
            version = v.get("InstalledVersion")
            severity = v.get("Severity", "UNKNOWN")
            msg = v.get("Title") or v.get("Description") or ""
            cwe_list = v.get("CweIDs") or ["CWE-UNKNOWN"]

            findings.append({
                "scanner": "trivy",
                "type": "DEP",
                "cve": cve,
                "cwes": cwe_list,
                "severity": severity.upper(),
                "package": pkg,
                "version": version,
                "message": msg,
                "path": result.get("Target"),
            })

    print(f"[DEBUG] Trivy findings: {len(findings)}")
    return findings


# =========================
# OSV-SCANNER (Dependency #2)
# =========================

def run_osv(project_path: Path):
    """
    Run OSV-Scanner on lockfiles/manifests.
    """
    findings = []

    manifest_names = [
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gradle.lockfile",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "poetry.lock",
        "Gemfile.lock",
    ]

    manifest_paths: list[Path] = []
    for name in manifest_names:
        manifest_paths.extend(project_path.rglob(name))

    if not manifest_paths:
        print("[WARN] OSV-Scanner: no supported lockfiles found – skipping.")
        return findings

    print("[DEBUG] OSV-Scanner lockfiles to scan:")
    for p in manifest_paths:
        print(f"  - {p}")

    for manifest in manifest_paths:
        cmd = [
            "osv-scanner",
            "scan",
            "--format", "json",
            str(manifest),
        ]

        proc, out = _run_cmd_capture(cmd, cwd=project_path)

        if proc is None or not out.strip():
            print(f"[WARN] OSV-Scanner: no JSON for {manifest} – skipping.")
            continue

        try:
            data = json.loads(out)
        except Exception as e:
            print(f"[WARN] Could not parse OSV JSON for {manifest}: {e}")
            continue

        for result in data.get("results", []):
            source = result.get("source", {}) or {}
            lockfile_path = source.get("path") or str(manifest)

            for pkg in result.get("packages", []) or []:
                pkg_info = pkg.get("package", {}) or {}
                pkg_name = pkg_info.get("name")
                pkg_version = pkg_info.get("version")

                for vuln in pkg.get("vulnerabilities", []) or []:
                    osv_id = vuln.get("id")
                    aliases = vuln.get("aliases") or []
                    cve = next((a for a in aliases if a.startswith("CVE-")), osv_id)

                    summary = (vuln.get("summary") or vuln.get("details") or "").strip()

                    severity = "UNKNOWN"
                    for sev in vuln.get("severity", []) or []:
                        if sev.get("type", "").startswith("CVSS"):
                            severity = sev.get("score")
                            break

                    db_spec = vuln.get("database_specific", {}) or {}
                    cwe_ids = db_spec.get("cwe_ids") or []
                    primary_cwe = normalize_cwe(cwe_ids[0]) if cwe_ids else None

                    findings.append({
                        "scanner": "osv-scanner",
                        "type": "DEP",
                        "package": pkg_name,
                        "version": pkg_version,
                        "cve": cve,
                        "osv_id": osv_id,
                        "severity": severity,
                        "cwe": primary_cwe,
                        "path": lockfile_path,
                        "message": summary,
                    })

    print(f"[DEBUG] OSV-Scanner findings: {len(findings)}")
    return findings


# =========================
# Aggregation & summaries
# =========================

def run_all_scanners(project_path: Path, progress_callback=None):
    """
    Run all tools.
    progress_callback: Optional function to call with progress updates
    """
    print("[DEBUG] Starting all scanners…")
    
    scanners = [
        ("Semgrep", run_semgrep),
        ("Bearer", run_bearer),
        ("Bandit", run_bandit),
        ("Trivy", run_trivy),
        ("OSV-Scanner", run_osv),
    ]
    
    results_sast = {}
    results_dep = {}
    
    for idx, (name, scanner_func) in enumerate(scanners, 1):
        if progress_callback:
            progress_callback(f"Running {name} ({idx}/5)...")
        
        print(f"[DEBUG] Running {name}...")
        findings = scanner_func(project_path)
        
        # Store results
        if name in ["Semgrep", "Bearer", "Bandit"]:
            results_sast[name.lower()] = findings
        else:
            scanner_key = "osv-scanner" if name == "OSV-Scanner" else name.lower()
            results_dep[scanner_key] = findings
    
    if progress_callback:
        progress_callback("All scanners completed!")
    
    print("[DEBUG] Scanners finished")

    return {
        "sast": results_sast,
        "dep": results_dep,
    }


def build_sast_summary(sast_results: dict):
    """
    Per-CWE SAST summary deduped across Semgrep + Bearer + Bandit.
    Adds BOTH 'occurrences' and legacy 'instances'.
    """
    buckets: dict[str, dict] = {}

    severity_rank = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
        "UNKNOWN": 0,
    }

    for scanner_name, findings in sast_results.items():
        for f in findings:
            cwe = normalize_cwe(f.get("cwe"))
            key = cwe

            if key not in buckets:
                buckets[key] = {
                    "cwe": cwe,
                    "severity": "INFO",
                    "scanners": set(),
                    "occurrences": 0,
                    "examples": [],
                }

            b = buckets[key]
            b["scanners"].add(scanner_name)
            b["occurrences"] += 1

            sev = (f.get("severity") or "INFO").upper()
            if severity_rank.get(sev, 0) > severity_rank.get(b["severity"], 0):
                b["severity"] = sev

            if len(b["examples"]) < 3:
                b["examples"].append({
                    "file": f.get("file"),
                    "line": f.get("line"),
                    "message": f.get("message"),
                    "scanner": scanner_name,
                })

    summary = []
    for b in buckets.values():
        b["scanners"] = sorted(b["scanners"])

        # ✅ Backward compatible alias (your template uses row.instances)
        b["instances"] = b["occurrences"]

        summary.append(b)

    summary.sort(key=lambda x: (-severity_rank.get(x["severity"], 0), x["cwe"]))
    return summary


def build_dep_summary(dep_results: dict):
    """
    Per-CVE dependency summary deduped across Trivy + OSV.
    Adds BOTH 'occurrences' and legacy 'instances'.
    """
    buckets: dict[str, dict] = {}

    severity_rank = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0,
    }

    for scanner_name, findings in dep_results.items():
        for f in findings:
            cve = f.get("cve") or f.get("osv_id") or "NO-ID"
            key = cve

            if key not in buckets:
                buckets[key] = {
                    "cve": cve,
                    "severity": "UNKNOWN",
                    "scanners": set(),
                    "occurrences": 0,
                    "packages": set(),
                    "examples": [],
                }

            b = buckets[key]
            b["scanners"].add(scanner_name)
            b["occurrences"] += 1

            pkg = f.get("package")
            if pkg:
                b["packages"].add(pkg)

            sev_raw = str(f.get("severity") or "UNKNOWN").upper()
            sev = sev_raw

            try:
                score = float(sev_raw)
                if score >= 9:
                    sev = "CRITICAL"
                elif score >= 7:
                    sev = "HIGH"
                elif score >= 4:
                    sev = "MEDIUM"
                else:
                    sev = "LOW"
            except ValueError:
                pass

            if severity_rank.get(sev, 0) > severity_rank.get(b["severity"], 0):
                b["severity"] = sev

            if len(b["examples"]) < 3:
                b["examples"].append({
                    "message": f.get("message"),
                    "scanner": scanner_name,
                    "path": f.get("path"),
                    "package": f.get("package"),
                    "version": f.get("version"),
                })

    summary = []
    for b in buckets.values():
        b["scanners"] = sorted(b["scanners"])
        b["packages"] = sorted(b["packages"])

        # ✅ Backward compatible alias
        b["instances"] = b["occurrences"]

        summary.append(b)

    summary.sort(key=lambda x: (-severity_rank.get(x["severity"], 0), x["cve"]))
    return summary
