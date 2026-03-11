from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, Response, stream_with_context
from werkzeug.utils import secure_filename
from pathlib import Path
import tempfile, shutil, uuid
import openpyxl
import json
import time
import math
import numpy as np
from queue import Queue
from threading import Thread

from scanners import run_all_scanners, build_sast_summary, build_dep_summary
from docx import Document  # needs python-docx
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font, Alignment


def calculate_risk_scores(analysis_data, total_runs):
    """
    Calculate risk scores for each CWE using Scoring System v2
    
    Formula: Risk Score = V × I × L × Vol × C × 100 (capped at 100)
    
    V (Validation): 1 if TP exists, 0 otherwise
    I (Impact): Severity-based (0.4 to 1.0)
    L (Likelihood): Percentage of runs with TP (0-1)
    Vol (Volume): log₁₀(TP_file_count + 1) - measures systemic spread
    C (Confidence): Tool count based (0.7, 0.85, 1.0)
    
    Only TRUE POSITIVES are counted (FP ignored)
    Volume uses affected file count to measure systemic spread rather
    than total finding count to avoid overweighting concentrated issues.
    
    Returns TWO dicts:
    - per_language_scores: {language: {cwe_id: score_data}} — isolated per language
    - global_scores: {cwe_id: score_data} — aggregated across languages (for model score)
    """
    
    # Severity mapping
    SEVERITY_MAP = {
        'CRITICAL': 1.0,
        'HIGH': 0.8,
        'ERROR': 0.8,
        'MEDIUM': 0.6,
        'WARNING': 0.6,
        'LOW': 0.4,
        'INFO': 0.4
    }
    
    def _compute_score(tp_count, fp_count, tp_files, runs, tools, severities, total_runs):
        """Compute risk score for a single CWE entry"""
        if tp_count == 0:
            return None
        
        V = 1
        impact_scores = [SEVERITY_MAP.get(s.upper(), 0.5) for s in severities]
        I = max(impact_scores) if impact_scores else 0.5
        
        runs_with_cwe = len(runs)
        L = runs_with_cwe / total_runs if total_runs > 0 else 0
        
        tp_file_count = len(tp_files)
        Vol = math.log10(tp_file_count + 1) if tp_file_count > 0 else 0
        
        tools_count = len(tools)
        if tools_count == 1:
            C = 0.7
        elif tools_count == 2:
            C = 0.85
        else:
            C = 1.0
        
        # Round factors FIRST, then compute score from rounded values
        # This ensures the displayed "Manual Verification" always matches
        I = round(I, 2)
        L = round(L, 2)
        Vol = round(Vol, 2)
        
        risk_score = V * I * L * Vol * C * 100
        risk_score = round(min(risk_score, 100), 2)
        
        if risk_score >= 80:
            risk_level = 'CRITICAL'
            risk_color = 'danger'
        elif risk_score >= 60:
            risk_level = 'HIGH'
            risk_color = 'warning'
        elif risk_score >= 40:
            risk_level = 'MEDIUM'
            risk_color = 'info'
        elif risk_score >= 20:
            risk_level = 'LOW'
            risk_color = 'secondary'
        else:
            risk_level = 'MINIMAL'
            risk_color = 'success'
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_color': risk_color,
            'V': V,
            'I': I,
            'L': L,
            'Vol': Vol,
            'C': C,
            'tp_count': tp_count,
            'tp_file_count': tp_file_count,
            'fp_count': fp_count,
            'runs_count': runs_with_cwe,
            'tools_count': tools_count,
            'severities': severities,
            'tools': tools,
            'runs': runs
        }
    
    # ── Per-Language Scores ──────────────────────────────────────────
    per_language_scores = {}
    
    for language, lang_data in analysis_data['by_language'].items():
        lang_scores = {}
        for cwe_id, cwe_info in lang_data['cwes'].items():
            tp_count = cwe_info['verdicts'].get('true_positive', 0)
            if tp_count == 0:
                continue
            
            fp_count = cwe_info['verdicts'].get('false_positive', 0)
            tp_files = list(cwe_info.get('true_positive_files', []))
            
            # For per-language: only count runs where THIS language had TPs
            # Use found_in_runs which tracks runs where this CWE appeared in this language
            runs = list(cwe_info.get('found_in_runs', []))
            tools = list(cwe_info.get('tools', []))
            # Use TP-only severities for scoring (not FP severities)
            tp_severities = list(cwe_info.get('tp_severities', []))
            # Fall back to all severities if tp_severities empty (shouldn't happen since tp_count > 0)
            severities_for_scoring = tp_severities if tp_severities else list(cwe_info.get('severities', []))
            # Keep all severities for display
            all_severities = list(cwe_info.get('severities', []))
            
            score = _compute_score(tp_count, fp_count, tp_files, runs, tools, severities_for_scoring, total_runs)
            if score:
                # Store all severities for display alongside the TP-only ones used in scoring
                score['severities'] = all_severities
                score['tp_severities'] = tp_severities
                lang_scores[cwe_id] = score
        
        if lang_scores:
            per_language_scores[language] = lang_scores
    
    # ── Global Aggregated Scores (for model-level scoring) ──────────
    global_cwes = {}
    
    for language, lang_data in analysis_data['by_language'].items():
        for cwe_id, cwe_info in lang_data['cwes'].items():
            tp_count = cwe_info['verdicts'].get('true_positive', 0)
            if tp_count == 0:
                continue
            
            if cwe_id in global_cwes:
                existing = global_cwes[cwe_id]
                existing['_tp_count'] += tp_count
                existing['_fp_count'] += cwe_info['verdicts'].get('false_positive', 0)
                existing['_tp_files'] = list(set(existing['_tp_files']) | set(cwe_info.get('true_positive_files', [])))
                existing['_runs'] = list(set(existing['_runs']) | set(cwe_info.get('found_in_runs', [])))
                existing['_tools'] = list(set(existing['_tools']) | set(cwe_info.get('tools', [])))
                existing['_severities'] = list(set(existing['_severities']) | set(cwe_info.get('severities', [])))
                existing['_tp_severities'] = list(set(existing['_tp_severities']) | set(cwe_info.get('tp_severities', [])))
            else:
                global_cwes[cwe_id] = {
                    '_tp_count': tp_count,
                    '_fp_count': cwe_info['verdicts'].get('false_positive', 0),
                    '_tp_files': list(cwe_info.get('true_positive_files', [])),
                    '_runs': list(cwe_info.get('found_in_runs', [])),
                    '_tools': list(cwe_info.get('tools', [])),
                    '_severities': list(cwe_info.get('severities', [])),
                    '_tp_severities': list(cwe_info.get('tp_severities', []))
                }
    
    global_scores = {}
    for cwe_id, agg in global_cwes.items():
        # Use TP-only severities for scoring
        tp_sevs = agg['_tp_severities']
        scoring_sevs = tp_sevs if tp_sevs else agg['_severities']
        score = _compute_score(
            agg['_tp_count'], agg['_fp_count'], agg['_tp_files'],
            agg['_runs'], agg['_tools'], scoring_sevs, total_runs
        )
        if score:
            # Store both for display
            score['severities'] = agg['_severities']
            score['tp_severities'] = tp_sevs
            global_scores[cwe_id] = score
    
    return per_language_scores, global_scores


def calculate_model_score(scored_cwes, total_runs, total_findings, total_tp, total_files_with_tp):
    """
    Calculate overall model security score
    
    Uses composite methodology:
    - 40% weight on top 5 CWE average
    - 30% weight on weighted average risk
    - 30% weight on maximum risk
    
    Combined with vulnerability density (30% weight)
    """
    
    if not scored_cwes:
        return {
            'final_score': 100.0,
            'rating': 'EXCELLENT',
            'color': 'success'
        }
    
    # Sort CWEs by risk score
    sorted_cwes = sorted(scored_cwes.items(), key=lambda x: x[1]['risk_score'], reverse=True)
    
    # Method 1: Top CWE Average
    top_n = min(10, len(sorted_cwes))
    top_scores = [cwe[1]['risk_score'] for cwe in sorted_cwes[:top_n]]
    avg_top_risk = sum(top_scores) / top_n if top_n > 0 else 0
    
    # Method 2: Weighted Average
    total_weighted_risk = sum(
        cwe[1]['risk_score'] * cwe[1]['tp_count'] 
        for cwe in sorted_cwes
    )
    total_tp_sum = sum(cwe[1]['tp_count'] for cwe in sorted_cwes)
    weighted_avg_risk = total_weighted_risk / total_tp_sum if total_tp_sum > 0 else 0
    
    # Method 3: Maximum Risk
    max_risk = sorted_cwes[0][1]['risk_score'] if sorted_cwes else 0
    
    # Method 4: Composite (top 5 average for critical penalty)
    top_5 = min(5, len(sorted_cwes))
    critical_penalty = sum(cwe[1]['risk_score'] for cwe in sorted_cwes[:top_5]) / top_5 if top_5 > 0 else 0
    
    composite_risk = (
        0.4 * critical_penalty +
        0.3 * weighted_avg_risk +
        0.3 * max_risk
    )
    
    # Method 5: Vulnerability Density
    estimated_loc = total_files_with_tp * 200  # Assume 200 lines per file
    if estimated_loc > 0:
        weighted_density = total_weighted_risk / estimated_loc
        density_score = max(0, 100 - (weighted_density * 20))
    else:
        density_score = 100
    
    # Final Score: 70% composite + 30% density
    final_score = ((100 - composite_risk) * 0.7) + (density_score * 0.3)
    final_score = max(0, min(100, final_score))  # Clamp to 0-100
    
    # Determine rating
    if final_score >= 80:
        rating = 'EXCELLENT'
        color = 'success'
    elif final_score >= 60:
        rating = 'GOOD'
        color = 'primary'
    elif final_score >= 40:
        rating = 'FAIR'
        color = 'warning'
    elif final_score >= 20:
        rating = 'POOR'
        color = 'danger'
    else:
        rating = 'CRITICAL'
        color = 'danger'
    
    # Count CWEs by ACTUAL SEVERITY from JSON (not risk score)
    # This counts based on the original scanner severity, not calculated risk
    severity_counts = {
        'critical': set(),
        'high': set(),
        'medium': set(),
        'low': set()
    }
    
    for cwe_id, cwe_data in scored_cwes.items():
        severities = [s.upper() for s in cwe_data.get('severities', [])]
        
        # Categorize by highest severity present
        # Semgrep: ERROR=HIGH, WARNING=MEDIUM, INFO=LOW
        if 'CRITICAL' in severities:
            severity_counts['critical'].add(cwe_id)
        elif any(s in ['HIGH', 'ERROR'] for s in severities):
            severity_counts['high'].add(cwe_id)
        elif any(s in ['MEDIUM', 'WARNING'] for s in severities):
            severity_counts['medium'].add(cwe_id)
        elif any(s in ['LOW', 'INFO'] for s in severities):
            severity_counts['low'].add(cwe_id)
    
    return {
        'final_score': round(final_score, 2),
        'rating': rating,
        'color': color,
        'components': {
            'composite_risk': round(composite_risk, 2),
            'density_score': round(density_score, 2),
            'critical_penalty': round(critical_penalty, 2),
            'weighted_avg_risk': round(weighted_avg_risk, 2),
            'max_risk': round(max_risk, 2),
            'top_cwe_avg': round(avg_top_risk, 2)
        },
        'metrics': {
            'total_cwes': len(scored_cwes),
            'critical_cwes': len(severity_counts['critical']),
            'high_cwes': len(severity_counts['high']),
            'medium_cwes': len(severity_counts['medium']),
            'low_cwes': len(severity_counts['low']),
            'vulnerability_density': round(total_tp / estimated_loc * 1000, 2) if estimated_loc > 0 else 0,
            'tp_rate': round(total_tp / total_findings * 100, 1) if total_findings > 0 else 0
        }
    }

app = Flask(__name__)
app.secret_key = "change-me"

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {"zip"}
ALLOWED_JSON_EXTENSIONS = {"json"}

# Changed to store multiple runs
ALL_RUNS = []  # List of dicts, each containing results for one run

# Multi-model store: {model_name: {analysis: ..., decisions: {...}, model_name: str}}
ALL_MODELS = {}

# Currently selected model name (for backward compat)
CURRENT_MODEL = None

# Store analysis results from JSON (backward compat — points to current model's data)
ANALYSIS_DATA = None

# Store AI decision data indexed by stable_id (backward compat — points to current model's data)
DECISIONS_DATA = {}  # stable_id -> decision dict

# Progress tracking
progress_queues = {}  # scan_id -> Queue for progress updates


def get_model_data(model_name=None):
    """Get analysis and decisions data for a specific model"""
    global ALL_MODELS, CURRENT_MODEL
    if model_name is None:
        model_name = CURRENT_MODEL
    if model_name and model_name in ALL_MODELS:
        return ALL_MODELS[model_name]['analysis'], ALL_MODELS[model_name]['decisions']
    return None, {}


def set_current_model(model_name):
    """Set the current model and update backward-compat globals"""
    global CURRENT_MODEL, ANALYSIS_DATA, DECISIONS_DATA
    CURRENT_MODEL = model_name
    if model_name and model_name in ALL_MODELS:
        ANALYSIS_DATA = ALL_MODELS[model_name]['analysis']
        DECISIONS_DATA = ALL_MODELS[model_name]['decisions']
    else:
        ANALYSIS_DATA = None
        DECISIONS_DATA = {}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def allowed_json_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_JSON_EXTENSIONS


def allowed_zip_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() == "zip"


def get_language_from_file(filepath):
    """Extract language from file extension or filename"""
    if not filepath:
        return 'unknown'
    
    # Get filename and extension
    filename = Path(filepath).name
    ext = Path(filepath).suffix.lower()
    
    # Check for special filenames first (files without extensions)
    filename_map = {
        'dockerfile': 'docker',
        'docker-compose.yml': 'docker',
        'docker-compose.yaml': 'docker',
        'makefile': 'makefile',
        'cmakelists.txt': 'cmake',
        'rakefile': 'ruby',
        'gemfile': 'ruby',
        'vagrantfile': 'ruby',
    }
    
    filename_lower = filename.lower()
    if filename_lower in filename_map:
        return filename_map[filename_lower]
    
    # Check for config files by extension
    if filename_lower.endswith('.conf') or filename_lower.endswith('.config'):
        return 'config'
    
    # Extension-based mapping
    ext_map = {
        '.c': 'c',
        '.h': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.hpp': 'cpp',
        '.java': 'java',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.py': 'python',
        '.rb': 'ruby',
        '.go': 'go',
        '.rs': 'rust',
        '.php': 'php',
        '.cs': 'csharp',
        '.swift': 'swift',
        '.kt': 'kotlin',
        '.scala': 'scala',
        '.sh': 'shell',
        '.bash': 'shell',
        '.sql': 'sql',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.json': 'json',
        '.xml': 'xml',
        '.html': 'html',
        '.css': 'css',
        '.conf': 'config',
        '.config': 'config',
        '.ini': 'config',
        '.toml': 'config',
        '.properties': 'config',
    }
    
    return ext_map.get(ext, 'unknown')


def generate_docx_report(project_name, sast_summary, dep_summary, out_path: Path):
    doc = Document()

    doc.add_heading("Security Scan Report", level=1)
    doc.add_paragraph(f"Project: {project_name}")
    doc.add_paragraph()

    doc.add_heading("SAST CWE Summary", level=2)
    if sast_summary:
        table = doc.add_table(rows=1, cols=5)
        hdr = table.rows[0].cells
        hdr[0].text = "CWE"
        hdr[1].text = "Severity"
        hdr[2].text = "Occurrences"
        hdr[3].text = "Found by"
        hdr[4].text = "Example files / lines"

        for row in sast_summary:
            cells = table.add_row().cells
            cells[0].text = row.get("cwe", "")
            cells[1].text = row.get("severity", "")
            cells[2].text = str(row.get("occurrences", 0))
            cells[3].text = ", ".join(row.get("scanners", []))

            examples = row.get("examples", [])
            if examples:
                lines = []
                for ex in examples:
                    file_ = ex.get("file")
                    line = ex.get("line")
                    scanner = ex.get("scanner")
                    lines.append(f"{file_}:{line} ({scanner})")
                cells[4].text = "\n".join(lines)
            else:
                cells[4].text = "-"

    else:
        doc.add_paragraph("No SAST findings.")

    doc.add_page_break()

    doc.add_heading("Dependency Vulnerability Summary", level=2)
    if dep_summary:
        table = doc.add_table(rows=1, cols=5)
        hdr = table.rows[0].cells
        hdr[0].text = "CVE / ID"
        hdr[1].text = "Severity"
        hdr[2].text = "Occurrences"
        hdr[3].text = "Found by"
        hdr[4].text = "Packages"

        for row in dep_summary:
            cells = table.add_row().cells
            cells[0].text = row.get("cve", "")
            cells[1].text = row.get("severity", "")
            cells[2].text = str(row.get("occurrences", 0))
            cells[3].text = ", ".join(row.get("scanners", []))
            cells[4].text = ", ".join(row.get("packages", []))
    else:
        doc.add_paragraph("No dependency findings.")

    doc.save(out_path)


def normalize_file_path(file_path, run_number=None):
    """
    Normalize file paths to remove run-specific prefixes for accurate unique file counting.
    
    Examples:
    - "run_1/src/main.py" -> "src/main.py"
    - "/tmp/extract_123/run_2/project/app.py" -> "project/app.py"
    - "run_3_code/utils.py" -> "utils.py"
    
    This ensures the same file across different runs is counted as ONE unique file.
    """
    import re
    
    if not file_path:
        return file_path
    
    # Remove common run-specific prefixes
    # Pattern: run_N/, run-N/, runN/, or extract_*/run_N/
    patterns = [
        r'^run[_-]?\d+/',  # run_1/, run-1/, run1/
        r'.*/run[_-]?\d+/',  # /path/to/run_1/
        r'^extract[_-]?\d+/',  # extract_123/
        r'.*/extract[_-]?\d+/',  # /tmp/extract_123/
    ]
    
    normalized = file_path
    for pattern in patterns:
        normalized = re.sub(pattern, '', normalized)
    
    # Also remove leading temp directories
    normalized = re.sub(r'^/tmp/[^/]+/', '', normalized)
    normalized = re.sub(r'^temp[_-]?\d*/', '', normalized)
    
    return normalized


def analyze_json_by_language(json_data):
    """
    Analyze JSON data to group CWEs by language and provide comprehensive statistics
    
    Returns analysis including:
    - Language-wise CWE grouping
    - File impact analysis (how many files each CWE affects)
    - Verdict tracking (true positive vs false positive)
    - Cross-run comparison
    - Tool correlation
    """
    analysis = {
        "metadata": {
            "total_runs": json_data.get("total_runs", 0),
            "project": json_data.get("project", "Unknown"),
            "generated_at": json_data.get("generated_at", "Unknown"),
            "total_findings": 0,
            "true_positives": 0,
            "false_positives": 0,
            "total_unique_cwes": 0,
            "total_languages": 0,
            "languages": []
        },
        "by_language": {},  # language -> {cwes: {}, statistics: {}}
        "overview": {
            "cwes": {}  # Global CWE overview across all languages
        }
    }
    
    # Track global data
    all_languages = set()
    global_cwe_data = {}  # cwe_id -> {languages: set(), total_files: set(), ...}
    
    # Process all runs
    for run in json_data.get("runs", []):
        run_number = run.get("run_number")
        results = run.get("results", {})
        sast_results = results.get("sast", {})
        
        # Process all SAST findings
        for tool_name, findings in sast_results.items():
            for finding in findings:
                analysis["metadata"]["total_findings"] += 1
                
                # Track verdicts
                verdict = finding.get("verdict", "unknown")
                if verdict == "true_positive":
                    analysis["metadata"]["true_positives"] += 1
                elif verdict == "false_positive":
                    analysis["metadata"]["false_positives"] += 1
                
                # Extract data
                cwe_id = finding.get("cwe", "CWE-UNKNOWN")
                raw_file_path = finding.get("file", "")
                
                # CRITICAL FIX: Normalize file paths to count unique files correctly
                # Same file across different runs should count as ONE file, not multiple
                file_path = normalize_file_path(raw_file_path, run_number)
                
                language = get_language_from_file(file_path)
                severity = finding.get("severity", "UNKNOWN")
                line = finding.get("line", 0)
                message = finding.get("message", "")
                scanner = finding.get("scanner", tool_name)
                
                # Track language
                all_languages.add(language)
                
                # Initialize language entry if needed
                if language not in analysis["by_language"]:
                    analysis["by_language"][language] = {
                        "cwes": {},
                        "statistics": {
                            "total_cwes": 0,
                            "total_files": 0,
                            "true_positives": 0,
                            "false_positives": 0,
                            "unique_file_set": set()  # Temporary for tracking
                        }
                    }
                
                lang_data = analysis["by_language"][language]
                
                # Initialize CWE entry for this language
                if cwe_id not in lang_data["cwes"]:
                    lang_data["cwes"][cwe_id] = {
                        "cwe_id": cwe_id,
                        "cwe_name": get_cwe_name(cwe_id),
                        "total_files_affected": 0,
                        "affected_files": set(),  # Temporary set for unique files
                        "verdicts": {"true_positive": 0, "false_positive": 0, "unknown": 0},
                        "severities": set(),       # ALL severities (TP + FP) for display
                        "tp_severities": set(),    # TP-only severities for scoring
                        "tools": set(),
                        "found_in_runs": set(),
                        "file_counts_per_run": {},
                        "run_file_tracking": {},  # Track files per run
                        "examples": []
                    }
                
                cwe_entry = lang_data["cwes"][cwe_id]
                
                # Update CWE data - track files by verdict
                cwe_entry["affected_files"].add(file_path)
                
                # Track files separately by verdict for detailed view
                verdict_key = f"{verdict}_files"
                if verdict_key not in cwe_entry:
                    cwe_entry[verdict_key] = set()
                cwe_entry[verdict_key].add(file_path)
                
                # NEW: Track which runs had which verdicts for each file WITH LINE NUMBERS
                if "file_verdict_by_run" not in cwe_entry:
                    cwe_entry["file_verdict_by_run"] = {}
                
                if file_path not in cwe_entry["file_verdict_by_run"]:
                    cwe_entry["file_verdict_by_run"][file_path] = {
                        "true_positive_details": {},  # Dict of {(run, line): scanner} to deduplicate
                        "false_positive_details": {},
                        "unknown_details": {}
                    }
                
                # Use (run, line) as key to deduplicate scanner reports on same line
                detail_key = (run_number, line)
                
                # Get stableId for linking to AI decisions
                stable_id = finding.get("stableId", "")
                
                # Store the finding (deduplicates automatically since we use dict)
                if verdict == "true_positive":
                    if detail_key not in cwe_entry["file_verdict_by_run"][file_path]["true_positive_details"]:
                        cwe_entry["file_verdict_by_run"][file_path]["true_positive_details"][detail_key] = {
                            "scanner": scanner,
                            "stable_id": stable_id
                        }
                elif verdict == "false_positive":
                    if detail_key not in cwe_entry["file_verdict_by_run"][file_path]["false_positive_details"]:
                        cwe_entry["file_verdict_by_run"][file_path]["false_positive_details"][detail_key] = {
                            "scanner": scanner,
                            "stable_id": stable_id
                        }
                else:
                    if detail_key not in cwe_entry["file_verdict_by_run"][file_path]["unknown_details"]:
                        cwe_entry["file_verdict_by_run"][file_path]["unknown_details"][detail_key] = {
                            "scanner": scanner,
                            "stable_id": stable_id
                        }
                
                cwe_entry["verdicts"][verdict] = cwe_entry["verdicts"].get(verdict, 0) + 1
                cwe_entry["severities"].add(severity)
                if verdict == "true_positive":
                    cwe_entry["tp_severities"].add(severity)
                cwe_entry["tools"].add(scanner)
                cwe_entry["found_in_runs"].add(run_number)
                
                # Track files per run
                if run_number not in cwe_entry["run_file_tracking"]:
                    cwe_entry["run_file_tracking"][run_number] = set()
                cwe_entry["run_file_tracking"][run_number].add(file_path)
                
                # Add example (limited to first 5)
                if len(cwe_entry["examples"]) < 5:
                    cwe_entry["examples"].append({
                        "run": run_number,
                        "file": file_path,
                        "line": line,
                        "scanner": scanner,
                        "message": message,
                        "verdict": verdict
                    })
                
                # Track unique files for language statistics
                lang_data["statistics"]["unique_file_set"].add(file_path)
                
                # Update verdict stats for language
                if verdict == "true_positive":
                    lang_data["statistics"]["true_positives"] += 1
                elif verdict == "false_positive":
                    lang_data["statistics"]["false_positives"] += 1
                
                # Global CWE tracking
                if cwe_id not in global_cwe_data:
                    global_cwe_data[cwe_id] = {
                        "cwe_id": cwe_id,
                        "cwe_name": get_cwe_name(cwe_id),
                        "languages": set(),
                        "total_files_affected": set(),
                        "true_positives": 0,
                        "false_positives": 0,
                        "found_in_runs": set(),
                        "tools": set()
                    }
                
                global_entry = global_cwe_data[cwe_id]
                global_entry["languages"].add(language)
                global_entry["total_files_affected"].add(file_path)
                global_entry["found_in_runs"].add(run_number)
                global_entry["tools"].add(scanner)
                if verdict == "true_positive":
                    global_entry["true_positives"] += 1
                elif verdict == "false_positive":
                    global_entry["false_positives"] += 1
    
    # Post-process: Convert sets to counts/lists
    for language, lang_data in analysis["by_language"].items():
        for cwe_id, cwe_entry in lang_data["cwes"].items():
            # Calculate file counts per run
            for run_num, file_set in cwe_entry["run_file_tracking"].items():
                cwe_entry["file_counts_per_run"][f"run_{run_num}"] = len(file_set)
            
            # Calculate total affected files
            cwe_entry["total_files_affected"] = len(cwe_entry["affected_files"])
            
            # Convert sets to sorted lists
            cwe_entry["affected_files"] = sorted(list(cwe_entry["affected_files"]))
            
            # Convert verdict-separated file sets to lists
            if "true_positive_files" in cwe_entry:
                cwe_entry["true_positive_files"] = sorted(list(cwe_entry["true_positive_files"]))
            else:
                cwe_entry["true_positive_files"] = []
            
            if "false_positive_files" in cwe_entry:
                cwe_entry["false_positive_files"] = sorted(list(cwe_entry["false_positive_files"]))
            else:
                cwe_entry["false_positive_files"] = []
            
            if "unknown_files" in cwe_entry:
                cwe_entry["unknown_files"] = sorted(list(cwe_entry["unknown_files"]))
            else:
                cwe_entry["unknown_files"] = []
            
            # Convert file_verdict_by_run dicts to sorted lists
            if "file_verdict_by_run" in cwe_entry:
                for file_path, verdicts in cwe_entry["file_verdict_by_run"].items():
                    # Convert TP dict to list
                    tp_list = [
                        {"run": run, "line": line, "scanner": info["scanner"], "stable_id": info.get("stable_id", "")}
                        for (run, line), info in verdicts["true_positive_details"].items()
                    ]
                    verdicts["true_positive_details"] = sorted(tp_list, key=lambda x: (x["run"], x["line"]))
                    
                    # Convert FP dict to list
                    fp_list = [
                        {"run": run, "line": line, "scanner": info["scanner"], "stable_id": info.get("stable_id", "")}
                        for (run, line), info in verdicts["false_positive_details"].items()
                    ]
                    verdicts["false_positive_details"] = sorted(fp_list, key=lambda x: (x["run"], x["line"]))
                    
                    # Convert unknown dict to list
                    unknown_list = [
                        {"run": run, "line": line, "scanner": info["scanner"], "stable_id": info.get("stable_id", "")}
                        for (run, line), info in verdicts["unknown_details"].items()
                    ]
                    verdicts["unknown_details"] = sorted(unknown_list, key=lambda x: (x["run"], x["line"]))
            
            cwe_entry["severities"] = sorted(list(cwe_entry["severities"]))
            cwe_entry["tp_severities"] = sorted(list(cwe_entry.get("tp_severities", set())))
            cwe_entry["tools"] = sorted(list(cwe_entry["tools"]))
            cwe_entry["found_in_runs"] = sorted(list(cwe_entry["found_in_runs"]))
            
            # Remove temporary tracking
            del cwe_entry["run_file_tracking"]
        
        # Update language statistics
        lang_data["statistics"]["total_cwes"] = len(lang_data["cwes"])
        lang_data["statistics"]["total_files"] = len(lang_data["statistics"]["unique_file_set"])
        del lang_data["statistics"]["unique_file_set"]  # Remove temporary set
        
        # Sort CWEs by files affected (descending)
        lang_data["cwes"] = dict(sorted(
            lang_data["cwes"].items(),
            key=lambda x: x[1]["total_files_affected"],
            reverse=True
        ))
    
    # Process global CWE overview
    for cwe_id, cwe_data in global_cwe_data.items():
        analysis["overview"]["cwes"][cwe_id] = {
            "cwe_id": cwe_id,
            "cwe_name": cwe_data["cwe_name"],
            "languages": sorted(list(cwe_data["languages"])),
            "total_files_affected": len(cwe_data["total_files_affected"]),
            "true_positives": cwe_data["true_positives"],
            "false_positives": cwe_data["false_positives"],
            "found_in_runs": sorted(list(cwe_data["found_in_runs"])),
            "tools": sorted(list(cwe_data["tools"]))
        }
    
    # Sort overview CWEs by total files affected
    analysis["overview"]["cwes"] = dict(sorted(
        analysis["overview"]["cwes"].items(),
        key=lambda x: x[1]["total_files_affected"],
        reverse=True
    ))
    
    # Update metadata
    analysis["metadata"]["total_unique_cwes"] = len(global_cwe_data)
    analysis["metadata"]["total_languages"] = len(all_languages)
    analysis["metadata"]["languages"] = sorted(list(all_languages))
    
    return analysis


def generate_comparison_excel(all_runs_data, out_path: Path):
    """
    Generate an Excel file comparing CWEs across multiple runs.
    
    Format matches user's manual Excel exactly:
    - Column A: CWE ID
    - Column B: CWE Name
    - Columns C onwards: Run 1, Run 2, ... Run N
    - Then: Runs Found, Total Runs, All Tools Used, Tool Details by Run
    - Cells: ✓ if CWE found in that run, empty otherwise
    """
    wb = Workbook()
    ws = wb.active
    ws.title = "CWE Comparison"
    
    # CWE name mapping (comprehensive list)
    cwe_names = {
        "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
        "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "CWE-125": "Out-of-bounds Read",
        "CWE-190": "Integer Overflow or Wraparound",
        "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
        "CWE-250": "Execution with Unnecessary Privileges",
        "CWE-287": "Improper Authentication",
        "CWE-295": "Improper Certificate Validation",
        "CWE-297": "Improper Validation of Certificate with Host Mismatch",
        "CWE-306": "Missing Authentication for Critical Function",
        "CWE-312": "Cleartext Storage of Sensitive Information",
        "CWE-319": "Cleartext Transmission of Sensitive Information",
        "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
        "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
        "CWE-377": "Insecure Temporary File",
        "CWE-400": "Uncontrolled Resource Consumption",
        "CWE-502": "Deserialization of Untrusted Data",
        "CWE-521": "Weak Password Requirements",
        "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
        "CWE-611": "Improper Restriction of XML External Entity Reference",
        "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "CWE-732": "Incorrect Permission Assignment for Critical Resource",
        "CWE-776": "Unrestricted Recursion",
        "CWE-798": "Use of Hard-coded Credentials",
        "CWE-917": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')",
    }
    
    # Collect all unique CWEs across all runs with detailed info
    cwe_data = {}  # cwe -> {runs: set(), tools_by_run: {run_idx: set()}}
    
    for run_idx, run_data in enumerate(all_runs_data):
        sast_summary = run_data.get("sast_summary", [])
        for item in sast_summary:
            cwe = item.get("cwe")
            if cwe and cwe != "CWE-UNKNOWN":
                if cwe not in cwe_data:
                    cwe_data[cwe] = {
                        "runs": set(),
                        "tools_by_run": {}
                    }
                
                cwe_data[cwe]["runs"].add(run_idx)
                
                # Track which tools found this CWE in this run
                if run_idx not in cwe_data[cwe]["tools_by_run"]:
                    cwe_data[cwe]["tools_by_run"][run_idx] = set()
                
                # Get tools that found this CWE
                scanners = item.get("scanners", [])
                for scanner in scanners:
                    cwe_data[cwe]["tools_by_run"][run_idx].add(scanner)
    
    # Sort CWEs
    sorted_cwes = sorted(cwe_data.keys())
    
    # Define styles
    header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF")
    check_fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
    center_alignment = Alignment(horizontal="center", vertical="center")
    wrap_alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
    
    num_runs = len(all_runs_data)
    
    # Write headers
    headers = ["CWE ID", "CWE Name"]
    for idx in range(1, num_runs + 1):
        headers.append(f"Run {idx}")
    headers.extend(["Runs Found", "Total Runs", "All Tools Used", "Tool Details by Run"])
    
    for col_idx, header in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = center_alignment
    
    # Write CWE data rows
    for row_idx, cwe in enumerate(sorted_cwes, start=2):
        data = cwe_data[cwe]
        
        # Column A: CWE ID
        ws.cell(row=row_idx, column=1, value=cwe)
        
        # Column B: CWE Name
        cwe_name = cwe_names.get(cwe, "")
        ws.cell(row=row_idx, column=2, value=cwe_name)
        
        # Columns for each run (checkmarks)
        for run_idx in range(num_runs):
            col = 3 + run_idx
            cell = ws.cell(row=row_idx, column=col)
            if run_idx in data["runs"]:
                cell.value = "✓"
                cell.fill = check_fill
                cell.alignment = center_alignment
                cell.font = Font(bold=True, size=14)
        
        # Runs Found column
        runs_found_list = sorted([f"Run {i+1}" for i in data["runs"]])
        runs_found_str = ", ".join(runs_found_list)
        ws.cell(row=row_idx, column=3 + num_runs, value=runs_found_str)
        
        # Total Runs column
        total_runs = len(data["runs"])
        ws.cell(row=row_idx, column=4 + num_runs, value=total_runs).alignment = center_alignment
        
        # All Tools Used column
        all_tools = set()
        for tools in data["tools_by_run"].values():
            all_tools.update(tools)
        all_tools_str = ", ".join(sorted(all_tools))
        ws.cell(row=row_idx, column=5 + num_runs, value=all_tools_str)
        
        # Tool Details by Run column
        tool_details = []
        for run_idx in sorted(data["tools_by_run"].keys()):
            tools = sorted(data["tools_by_run"][run_idx])
            tool_details.append(f"Run {run_idx + 1}: {', '.join(tools)}")
        tool_details_str = " | ".join(tool_details)
        cell = ws.cell(row=row_idx, column=6 + num_runs, value=tool_details_str)
        cell.alignment = wrap_alignment
    
    # Adjust column widths
    ws.column_dimensions['A'].width = 12  # CWE ID
    ws.column_dimensions['B'].width = 60  # CWE Name
    
    for col_idx in range(3, 3 + num_runs):
        col_letter = openpyxl.utils.get_column_letter(col_idx)
        ws.column_dimensions[col_letter].width = 10  # Run columns
    
    ws.column_dimensions[openpyxl.utils.get_column_letter(3 + num_runs)].width = 30  # Runs Found
    ws.column_dimensions[openpyxl.utils.get_column_letter(4 + num_runs)].width = 12  # Total Runs
    ws.column_dimensions[openpyxl.utils.get_column_letter(5 + num_runs)].width = 25  # All Tools Used
    ws.column_dimensions[openpyxl.utils.get_column_letter(6 + num_runs)].width = 80  # Tool Details by Run
    
    wb.save(out_path)


def generate_detailed_count_excel(all_runs_data, out_path: Path):
    """
    NEW FEATURE: Generate Excel with FILE COUNTS instead of checkmarks
    
    Instead of ✓, shows the NUMBER OF FILES that CWE was found in
    Example: CWE-79 in Run 1 found in 20 files -> shows "20"
    """
    wb = Workbook()
    ws = wb.active
    ws.title = "CWE Detailed Counts"
    
    # COMPREHENSIVE CWE name mapping (100+ CWEs)
    cwe_names = {
        # Input Validation
        "CWE-20": "Improper Input Validation",
        "CWE-74": "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
        "CWE-75": "Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)",
        "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "CWE-91": "XML Injection (aka Blind XPath Injection)",
        "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
        "CWE-95": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
        "CWE-96": "Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')",
        "CWE-97": "Improper Neutralization of Server-Side Includes (SSI) Within a Web Page",
        "CWE-98": "Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')",
        
        # Path Traversal & File Operations
        "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "CWE-23": "Relative Path Traversal",
        "CWE-36": "Absolute Path Traversal",
        "CWE-73": "External Control of File Name or Path",
        "CWE-434": "Unrestricted Upload of File with Dangerous Type",
        "CWE-59": "Improper Link Resolution Before File Access ('Link Following')",
        "CWE-377": "Insecure Temporary File",
        
        # Command Injection
        "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "CWE-77": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
        
        # Authentication & Access Control
        "CWE-287": "Improper Authentication",
        "CWE-306": "Missing Authentication for Critical Function",
        "CWE-285": "Improper Authorization",
        "CWE-284": "Improper Access Control",
        "CWE-862": "Missing Authorization",
        "CWE-863": "Incorrect Authorization",
        "CWE-276": "Incorrect Default Permissions",
        "CWE-732": "Incorrect Permission Assignment for Critical Resource",
        "CWE-250": "Execution with Unnecessary Privileges",
        "CWE-269": "Improper Privilege Management",
        
        # Cryptography
        "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
        "CWE-328": "Use of Weak Hash",
        "CWE-326": "Inadequate Encryption Strength",
        "CWE-321": "Use of Hard-coded Cryptographic Key",
        "CWE-322": "Key Exchange without Entity Authentication",
        "CWE-323": "Reusing a Nonce, Key Pair in Encryption",
        "CWE-324": "Use of a Key Past its Expiration Date",
        "CWE-325": "Missing Cryptographic Step",
        "CWE-329": "Generation of Predictable IV with CBC Mode",
        "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
        "CWE-330": "Use of Insufficiently Random Values",
        "CWE-331": "Insufficient Entropy",
        "CWE-335": "Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)",
        "CWE-336": "Same Seed in Pseudo-Random Number Generator (PRNG)",
        "CWE-337": "Predictable Seed in Pseudo-Random Number Generator (PRNG)",
        
        # SSL/TLS
        "CWE-295": "Improper Certificate Validation",
        "CWE-296": "Improper Following of a Certificate's Chain of Trust",
        "CWE-297": "Improper Validation of Certificate with Host Mismatch",
        "CWE-298": "Improper Validation of Certificate Expiration",
        "CWE-299": "Improper Check for Certificate Revocation",
        
        # Sensitive Data
        "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
        "CWE-209": "Generation of Error Message Containing Sensitive Information",
        "CWE-215": "Insertion of Sensitive Information Into Debugging Code",
        "CWE-312": "Cleartext Storage of Sensitive Information",
        "CWE-313": "Cleartext Storage in a File or on Disk",
        "CWE-314": "Cleartext Storage in the Registry",
        "CWE-315": "Cleartext Storage of Sensitive Information in a Cookie",
        "CWE-316": "Cleartext Storage of Sensitive Information in Memory",
        "CWE-317": "Cleartext Storage of Sensitive Information in GUI",
        "CWE-318": "Cleartext Storage of Sensitive Information in Executable",
        "CWE-319": "Cleartext Transmission of Sensitive Information",
        "CWE-321": "Use of Hard-coded Cryptographic Key",
        "CWE-798": "Use of Hard-coded Credentials",
        "CWE-259": "Use of Hard-coded Password",
        "CWE-257": "Storing Passwords in a Recoverable Format",
        
        # Session Management
        "CWE-384": "Session Fixation",
        "CWE-613": "Insufficient Session Expiration",
        "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
        "CWE-565": "Reliance on Cookies without Validation and Integrity Checking",
        
        # CSRF & Redirects
        "CWE-352": "Cross-Site Request Forgery (CSRF)",
        "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
        
        # XML & XXE
        "CWE-611": "Improper Restriction of XML External Entity Reference",
        "CWE-827": "Improper Control of Document Type Definition",
        
        # Deserialization
        "CWE-502": "Deserialization of Untrusted Data",
        "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        
        # Resource Management
        "CWE-400": "Uncontrolled Resource Consumption",
        "CWE-404": "Improper Resource Shutdown or Release",
        "CWE-770": "Allocation of Resources Without Limits or Throttling",
        "CWE-771": "Missing Reference to Active Allocated Resource",
        "CWE-772": "Missing Release of Resource after Effective Lifetime",
        "CWE-775": "Missing Release of File Descriptor or Handle after Effective Lifetime",
        "CWE-776": "Unrestricted Recursion",
        "CWE-834": "Excessive Iteration",
        
        # Memory Safety
        "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
        "CWE-121": "Stack-based Buffer Overflow",
        "CWE-122": "Heap-based Buffer Overflow",
        "CWE-125": "Out-of-bounds Read",
        "CWE-787": "Out-of-bounds Write",
        "CWE-416": "Use After Free",
        "CWE-415": "Double Free",
        "CWE-476": "NULL Pointer Dereference",
        "CWE-401": "Missing Release of Memory after Effective Lifetime",
        "CWE-911": "Improper Update of Reference Count",
        
        # Integer & Numeric Errors
        "CWE-190": "Integer Overflow or Wraparound",
        "CWE-191": "Integer Underflow (Wrap or Wraparound)",
        "CWE-680": "Integer Overflow to Buffer Overflow",
        "CWE-681": "Incorrect Conversion between Numeric Types",
        "CWE-682": "Incorrect Calculation",
        "CWE-369": "Divide By Zero",
        
        # Race Conditions
        "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
        "CWE-367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
        "CWE-364": "Signal Handler Race Condition",
        
        # Logic Errors
        "CWE-670": "Always-Incorrect Control Flow Implementation",
        "CWE-571": "Expression is Always True",
        "CWE-570": "Expression is Always False",
        "CWE-561": "Dead Code",
        "CWE-489": "Active Debug Code",
        "CWE-501": "Trust Boundary Violation",
        
        # Logging & Monitoring
        "CWE-117": "Improper Output Neutralization for Logs",
        "CWE-532": "Insertion of Sensitive Information into Log File",
        "CWE-533": "DEPRECATED: Information Exposure Through Server Log Files",
        
        # Configuration
        "CWE-1188": "Insecure Default Initialization of Resource",
        "CWE-426": "Untrusted Search Path",
        "CWE-427": "Uncontrolled Search Path Element",
        "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
        "CWE-830": "Inclusion of Web Functionality from an Untrusted Source",
        
        # Code Quality
        "CWE-477": "Use of Obsolete Function",
        "CWE-478": "Missing Default Case in Multiple Condition Expression",
        "CWE-479": "Signal Handler Use of a Non-reentrant Function",
        "CWE-480": "Use of Incorrect Operator",
        "CWE-483": "Incorrect Block Delimitation",
        "CWE-484": "Omitted Break Statement in Switch",
        
        # Expression Language Injection
        "CWE-917": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')",
        
        # Password & Auth
        "CWE-521": "Weak Password Requirements",
        "CWE-916": "Use of Password Hash With Insufficient Computational Effort",
        
        # Regex
        "CWE-1333": "Inefficient Regular Expression Complexity",
        
        # Prototype Pollution
        "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
        
        # Server-Side Request Forgery
        "CWE-918": "Server-Side Request Forgery (SSRF)",
        
        # Null Byte Injection
        "CWE-158": "Improper Neutralization of Null Byte or NUL Character",
        
        # Format String
        "CWE-134": "Use of Externally-Controlled Format String",
        
        # Uncontrolled Format String
        "CWE-134": "Use of Externally-Controlled Format String",
        
        # Information Disclosure
        "CWE-203": "Observable Discrepancy",
        "CWE-208": "Observable Timing Discrepancy",
        
        # Missing Support
        "CWE-353": "Missing Support for Integrity Check",
        
        # ZIP vulnerabilities
        "CWE-409": "Improper Handling of Highly Compressed Data (Data Amplification)",
        "CWE-410": "Insufficient Resource Pool",
    }
    
    # Collect CWE data with FILE COUNTS per run
    # FIXED: Use RAW scanner results instead of summary (which only has 5 examples)
    cwe_data = {}  # cwe -> {run_idx: {total_count, unique_files, tools}}
    
    for run_idx, run_data in enumerate(all_runs_data):
        # Get RAW SAST results (not summary which only has 5 examples!)
        sast_results = run_data.get("results", {}).get("sast", {})
        
        # Process each scanner's results
        for scanner_name, findings in sast_results.items():
            for finding in findings:
                cwe = finding.get("cwe")
                if cwe and cwe != "CWE-UNKNOWN":
                    if cwe not in cwe_data:
                        cwe_data[cwe] = {}
                    
                    if run_idx not in cwe_data[cwe]:
                        cwe_data[cwe][run_idx] = {
                            "total_count": 0,  # Total occurrences
                            "unique_files": set(),  # Unique files
                            "tools": set()
                        }
                    
                    # Count this occurrence
                    cwe_data[cwe][run_idx]["total_count"] += 1
                    
                    # Add unique file
                    file_path = finding.get("file")
                    if file_path:
                        cwe_data[cwe][run_idx]["unique_files"].add(file_path)
                    
                    # Track tool
                    cwe_data[cwe][run_idx]["tools"].add(scanner_name)
    
    # Sort CWEs
    sorted_cwes = sorted(cwe_data.keys())
    
    # Define styles
    header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF")
    count_fill = PatternFill(start_color="FFE699", end_color="FFE699", fill_type="solid")  # Yellow for counts
    center_alignment = Alignment(horizontal="center", vertical="center")
    wrap_alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
    
    num_runs = len(all_runs_data)
    
    # Write headers - TWO columns per run (Total and Unique)
    headers_row1 = ["CWE ID", "CWE Name"]
    
    # Add run headers (each run gets 2 columns)
    for idx in range(1, num_runs + 1):
        headers_row1.append(f"Run {idx} Total")
        headers_row1.append(f"Run {idx} Unique")
    
    headers_row1.extend(["Grand Total", "Grand Unique", "All Tools Used"])
    
    for col_idx, header in enumerate(headers_row1, start=1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = center_alignment
    
    # Write CWE data rows
    for row_idx, cwe in enumerate(sorted_cwes, start=2):
        data = cwe_data[cwe]
        
        # Column A: CWE ID
        ws.cell(row=row_idx, column=1, value=cwe)
        
        # Column B: CWE Name
        cwe_name = cwe_names.get(cwe, "")
        ws.cell(row=row_idx, column=2, value=cwe_name)
        
        grand_total_count = 0
        grand_unique_files = set()
        
        # Columns for each run (TWO columns: Total and Unique)
        col = 3
        for run_idx_col in range(num_runs):
            if run_idx_col in data:
                # Total Count
                total_count = data[run_idx_col]["total_count"]
                cell = ws.cell(row=row_idx, column=col)
                cell.value = total_count
                cell.fill = PatternFill(start_color="FFE699", end_color="FFE699", fill_type="solid")  # Yellow
                cell.alignment = center_alignment
                cell.font = Font(bold=True, size=11)
                
                # Unique File Count
                unique_count = len(data[run_idx_col]["unique_files"])
                cell = ws.cell(row=row_idx, column=col+1)
                cell.value = unique_count
                cell.fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")  # Green
                cell.alignment = center_alignment
                cell.font = Font(bold=True, size=11)
                
                grand_total_count += total_count
                grand_unique_files.update(data[run_idx_col]["unique_files"])
            else:
                # No data for this run
                ws.cell(row=row_idx, column=col, value=0).alignment = center_alignment
                ws.cell(row=row_idx, column=col+1, value=0).alignment = center_alignment
            
            col += 2
        
        # Grand Total column
        cell = ws.cell(row=row_idx, column=col)
        cell.value = grand_total_count
        cell.alignment = center_alignment
        cell.font = Font(bold=True, size=12)
        cell.fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")  # Light red
        
        # Grand Unique column
        cell = ws.cell(row=row_idx, column=col+1)
        cell.value = len(grand_unique_files)
        cell.alignment = center_alignment
        cell.font = Font(bold=True, size=12)
        cell.fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")  # Light green
        
        # All Tools Used column
        all_tools = set()
        for run_data in data.values():
            all_tools.update(run_data["tools"])
        all_tools_str = ", ".join(sorted(all_tools))
        ws.cell(row=row_idx, column=col+2, value=all_tools_str)
    
    # Adjust column widths
    ws.column_dimensions['A'].width = 12  # CWE ID
    ws.column_dimensions['B'].width = 60  # CWE Name
    
    # Each run has 2 columns (Total and Unique)
    col_idx = 3
    for _ in range(num_runs):
        col_letter_total = openpyxl.utils.get_column_letter(col_idx)
        col_letter_unique = openpyxl.utils.get_column_letter(col_idx + 1)
        ws.column_dimensions[col_letter_total].width = 12  # Total column
        ws.column_dimensions[col_letter_unique].width = 12  # Unique column
        col_idx += 2
    
    # Grand total columns and tools
    ws.column_dimensions[openpyxl.utils.get_column_letter(col_idx)].width = 12  # Grand Total
    ws.column_dimensions[openpyxl.utils.get_column_letter(col_idx + 1)].width = 12  # Grand Unique
    ws.column_dimensions[openpyxl.utils.get_column_letter(col_idx + 2)].width = 25  # All Tools Used
    
    wb.save(out_path)


def clean_file_paths(results, tmp_dir, project_name):
    """
    Remove temp directory prefix from all file paths in results.
    
    Before: /var/folders/.../T/scanproj_xyz123/python-flask-gemini/app.py
    After:  python-flask-gemini/app.py
    """
    import re
    from pathlib import Path
    
    # Convert tmp_dir to string for matching
    tmp_dir_str = str(tmp_dir)
    
    def clean_path(file_path):
        if not file_path:
            return file_path
        
        # Convert to string
        path_str = str(file_path)
        
        # Remove the temp directory prefix
        # Pattern: /path/to/temp/scanproj_xxx/
        if tmp_dir_str in path_str:
            # Remove everything up to and including the temp directory
            path_str = path_str.replace(tmp_dir_str + "/", "")
            path_str = path_str.replace(tmp_dir_str, "")
        
        # Also handle if scanners return relative paths
        # Just make sure we keep the project structure
        return path_str
    
    # Clean SAST results
    if "sast" in results:
        for scanner_name, findings in results["sast"].items():
            for finding in findings:
                if "file" in finding:
                    finding["file"] = clean_path(finding["file"])
    
    # Clean dependency results
    if "dep" in results:
        for scanner_name, findings in results["dep"].items():
            for finding in findings:
                if "file" in finding:
                    finding["file"] = clean_path(finding["file"])
                if "path" in finding:
                    finding["path"] = clean_path(finding["path"])
    
    return results


def scan_projects_background(files_info, clear_previous, scan_id):
    """Background task to scan projects and send progress updates"""
    global ALL_RUNS
    
    queue = progress_queues.get(scan_id)
    if not queue:
        return
    
    try:
        # Clear previous runs if requested
        if clear_previous:
            ALL_RUNS = []
            queue.put({"type": "info", "message": "Cleared previous runs"})
        
        total_files = len(files_info)
        
        # Process each uploaded file
        for idx, (filename, upload_path) in enumerate(files_info, 1):
            queue.put({
                "type": "progress",
                "current": idx,
                "total": total_files,
                "filename": filename,
                "stage": "extracting"
            })

            tmp_dir = Path(tempfile.mkdtemp(prefix="scanproj_"))

            try:
                # Extract
                queue.put({
                    "type": "status",
                    "message": f"[{idx}/{total_files}] Extracting {filename}..."
                })
                shutil.unpack_archive(str(upload_path), str(tmp_dir))
                
                # Delete the uploaded ZIP immediately after extraction
                try:
                    upload_path.unlink()
                    queue.put({
                        "type": "status",
                        "message": f"[{idx}/{total_files}] Cleaned up {filename}"
                    })
                except Exception as e:
                    print(f"Warning: Could not delete {upload_path}: {e}")

                # Scan
                queue.put({
                    "type": "progress",
                    "current": idx,
                    "total": total_files,
                    "filename": filename,
                    "stage": "scanning"
                })
                queue.put({
                    "type": "status",
                    "message": f"[{idx}/{total_files}] Scanning {filename} with 5 tools..."
                })
                
                # Run scanners (this is where most time is spent)
                def scanner_progress(message):
                    queue.put({
                        "type": "status",
                        "message": f"[{idx}/{total_files}] {message}"
                    })
                
                results = run_all_scanners(tmp_dir, progress_callback=scanner_progress)
                
                # Clean file paths - remove temp directory prefix
                project_name = filename.rsplit(".", 1)[0]
                results = clean_file_paths(results, tmp_dir, project_name)
                
                # Build summaries
                queue.put({
                    "type": "status",
                    "message": f"[{idx}/{total_files}] Building summaries for {filename}..."
                })
                sast_summary = build_sast_summary(results["sast"])
                dep_summary = build_dep_summary(results["dep"])

                project_name = filename.rsplit(".", 1)[0]

                # Store this run
                ALL_RUNS.append({
                    "scan_id": str(uuid.uuid4()),
                    "project_name": project_name,
                    "results": results,
                    "sast_summary": sast_summary,
                    "dep_summary": dep_summary,
                })
                
                queue.put({
                    "type": "status",
                    "message": f"[{idx}/{total_files}] ✅ Completed {filename}"
                })

            except Exception as e:
                error_msg = str(e)
                # Make timeout errors clearer
                if "timed out after" in error_msg:
                    queue.put({
                        "type": "status",
                        "message": f"[{idx}/{total_files}] ⏱️  {filename}: A scanner timed out (>10 min) - continuing with other scanners"
                    })
                else:
                    queue.put({
                        "type": "error",
                        "message": f"[{idx}/{total_files}] ❌ Error scanning {filename}: {error_msg}"
                    })

            finally:
                # Clean up temp extraction directory
                try:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                    if tmp_dir.exists():
                        # If rmtree failed, try force removal
                        import os
                        os.system(f"rm -rf {tmp_dir}")
                except Exception as e:
                    print(f"Warning: Could not remove temp dir {tmp_dir}: {e}")
        
        # Done
        queue.put({
            "type": "complete",
            "message": f"Successfully scanned {total_files} project(s)!",
            "total_scanned": total_files
        })
        
    except Exception as e:
        queue.put({
            "type": "error",
            "message": f"Fatal error: {str(e)}"
        })


def cleanup_old_reports():
    """Clean up report files older than 1 hour"""
    try:
        import time
        current_time = time.time()
        for file_path in REPORT_DIR.glob("*"):
            if file_path.is_file():
                # Get file age in seconds
                file_age = current_time - file_path.stat().st_mtime
                # Delete if older than 1 hour (3600 seconds)
                if file_age > 3600:
                    file_path.unlink()
                    print(f"Cleaned up old report: {file_path.name}")
    except Exception as e:
        print(f"Warning: Could not clean old reports: {e}")


def cleanup_temp_directories():
    """Clean up any leftover temp directories from crashed scans"""
    try:
        temp_base = Path(tempfile.gettempdir())
        for temp_dir in temp_base.glob("scanproj_*"):
            if temp_dir.is_dir():
                try:
                    shutil.rmtree(temp_dir)
                    print(f"Cleaned up temp directory: {temp_dir.name}")
                except:
                    pass
    except Exception as e:
        print(f"Warning: Could not clean temp directories: {e}")


@app.route("/", methods=["GET", "POST"])
def index():
    global ALL_RUNS

    if request.method == "POST":
        # Clean up old files before starting new scan
        cleanup_old_reports()
        cleanup_temp_directories()
        
        # Handle multiple file uploads
        files = request.files.getlist("project_zip")
        
        if not files or len(files) == 0:
            flash("No files uploaded", "warning")
            return redirect(request.url)
        
        # Filter valid files
        valid_files = [f for f in files if f.filename and allowed_file(f.filename)]
        
        if len(valid_files) == 0:
            flash("No valid .zip files uploaded", "warning")
            return redirect(request.url)
        
        # Save files and prepare info
        files_info = []
        for file in valid_files:
            filename = secure_filename(file.filename)
            upload_path = UPLOAD_DIR / filename
            file.save(upload_path)
            files_info.append((filename, upload_path))
        
        # Create scan ID and progress queue
        scan_id = str(uuid.uuid4())
        progress_queues[scan_id] = Queue()
        
        # Start background scanning
        clear_previous = request.form.get("clear_previous") == "yes"
        thread = Thread(target=scan_projects_background, args=(files_info, clear_previous, scan_id))
        thread.daemon = True
        thread.start()
        
        # Redirect to progress page
        return redirect(url_for("scan_progress", scan_id=scan_id))

    return render_template("index.html", num_runs=len(ALL_RUNS), num_models=len(ALL_MODELS))


@app.route("/scan_progress/<scan_id>")
def scan_progress(scan_id):
    """Display progress page"""
    if scan_id not in progress_queues:
        flash("Invalid scan ID", "danger")
        return redirect(url_for("index"))
    
    return render_template("progress.html", scan_id=scan_id)


@app.route("/upload_json", methods=["POST"])
def upload_json():
    """Upload ZIP files — supports:
    1. Multiple individual ZIPs (one per model, each with verdicted + decisions JSON)
    2. A single mega ZIP containing:
       a. Sub-folders per model (each with verdicted + decisions JSON)
       b. Nested ZIPs per model
    """
    global ALL_MODELS, CURRENT_MODEL, ANALYSIS_DATA, DECISIONS_DATA
    
    zip_files = request.files.getlist("model_zips")
    
    # Fallback: if getlist returns empty, try getting single file
    if not zip_files or all(f.filename == "" for f in zip_files):
        single = request.files.get("model_zips")
        if single and single.filename:
            zip_files = [single]
    
    if not zip_files or all(f.filename == "" for f in zip_files):
        flash("No ZIP files uploaded. Please select .zip files containing your model results.", "warning")
        return redirect(url_for("index"))
    
    models_processed = []
    errors = []
    
    def process_model_pair(verdicted_content, decisions_content, source_label, model_name_hint=""):
        """Process a single model's verdicted + decisions pair. Returns (model_info, error)."""
        try:
            json_data = json.loads(verdicted_content)
            
            if "runs" not in json_data or not isinstance(json_data["runs"], list) or len(json_data["runs"]) == 0:
                return None, f"{source_label}: Invalid JSON — missing 'runs'"
            
            # Derive model name
            model_name = json_data.get("project", "")
            if not model_name:
                model_name = model_name_hint or source_label
            
            # Parse decisions (JSONL or JSON)
            model_decisions = {}
            if decisions_content:
                for line in decisions_content.strip().split('\n'):
                    line = line.strip()
                    if line:
                        try:
                            decision = json.loads(line)
                            stable_id = decision.get('stable_id')
                            if stable_id:
                                model_decisions[stable_id] = decision
                        except json.JSONDecodeError:
                            pass
                
                if not model_decisions:
                    try:
                        data = json.loads(decisions_content)
                        if isinstance(data, list):
                            for decision in data:
                                stable_id = decision.get('stable_id')
                                if stable_id:
                                    model_decisions[stable_id] = decision
                        elif isinstance(data, dict) and 'decisions' in data:
                            for decision in data['decisions']:
                                stable_id = decision.get('stable_id')
                                if stable_id:
                                    model_decisions[stable_id] = decision
                    except json.JSONDecodeError:
                        pass
            
            total_runs = len(json_data["runs"])
            total_sast_findings = 0
            for run in json_data["runs"]:
                if "results" in run and "sast" in run["results"]:
                    for tool, findings in run["results"]["sast"].items():
                        if isinstance(findings, list):
                            total_sast_findings += len(findings)
            
            print(f"\n{'='*60}")
            print(f"📦 Processing: {model_name}")
            print(f"   Source: {source_label}")
            print(f"   Runs: {total_runs}, SAST findings: {total_sast_findings}")
            if model_decisions:
                print(f"   AI decisions: {len(model_decisions)}")
            
            analysis = analyze_json_by_language(json_data)
            per_language_scores, global_risk_scores = calculate_risk_scores(analysis, total_runs)
            analysis['risk_scores'] = global_risk_scores
            analysis['risk_scores_by_language'] = per_language_scores
            
            total_files_with_tp = len(set(
                file 
                for lang_data in analysis['by_language'].values()
                for cwe_data in lang_data['cwes'].values()
                if cwe_data['verdicts'].get('true_positive', 0) > 0
                for file in cwe_data.get('true_positive_files', [])
            ))
            
            model_score = calculate_model_score(
                global_risk_scores, total_runs, total_sast_findings,
                sum(cwe['tp_count'] for cwe in global_risk_scores.values()),
                total_files_with_tp
            )
            analysis['model_score'] = model_score
            analysis['model_name'] = model_name
            
            print(f"   CWEs scored: {len(global_risk_scores)}")
            
            ALL_MODELS[model_name] = {
                'analysis': analysis,
                'decisions': model_decisions,
                'model_name': model_name
            }
            
            return {
                'name': model_name,
                'runs': total_runs,
                'findings': total_sast_findings,
                'decisions': len(model_decisions),
                'cwes': len(global_risk_scores)
            }, None
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return None, f"{source_label}: {str(e)}"
    
    def extract_models_from_zip(zip_bytes, source_filename):
        """Extract model pairs from a ZIP. Handles:
        - Flat ZIP: one verdicted + one decisions = one model
        - Folder ZIP: subfolders each containing verdicted + decisions
        - Nested ZIP: inner .zip files each containing verdicted + decisions
        """
        import zipfile, io
        
        if not zipfile.is_zipfile(zip_bytes):
            return [], [f"{source_filename}: Not a valid ZIP file"]
        
        zip_bytes.seek(0)
        results = []  # list of (verdicted_content, decisions_content, label, hint)
        errs = []
        
        with zipfile.ZipFile(zip_bytes, 'r') as zf:
            names = zf.namelist()
            print(f"\n📦 ZIP contents for {source_filename}: ({len(names)} files)")
            for n in names[:20]:
                print(f"   → {n}")
            if len(names) > 20:
                print(f"   ... and {len(names)-20} more")
            
            # Step 1: Check for nested ZIPs
            inner_zips = [n for n in names if n.lower().endswith('.zip') and '/' not in n.rstrip('/')]
            # Also check one level deep
            if not inner_zips:
                inner_zips = [n for n in names if n.lower().endswith('.zip')]
            
            if inner_zips:
                print(f"   🔍 Found {len(inner_zips)} nested ZIP(s) — extracting each as a model")
                for inner_name in inner_zips:
                    try:
                        inner_bytes = io.BytesIO(zf.read(inner_name))
                        inner_results, inner_errs = extract_models_from_zip(inner_bytes, f"{source_filename}/{inner_name}")
                        results.extend(inner_results)
                        errs.extend(inner_errs)
                    except Exception as e:
                        errs.append(f"{source_filename}/{inner_name}: {str(e)}")
                return results, errs
            
            # Step 2: Group JSON files by their parent folder
            # e.g. "model-a/verdicted.json" → folder "model-a"
            # e.g. "verdicted.json" → folder ""
            folder_files = {}  # folder -> [(basename, full_name)]
            for name in names:
                parts = name.split('/')
                basename = parts[-1]
                if not basename or basename.startswith('.') or basename.startswith('__'):
                    continue
                if not basename.lower().endswith('.json'):
                    continue
                
                # Determine folder: everything except the filename
                if len(parts) >= 2:
                    # Could be "folder/file.json" or "top/folder/file.json"
                    # Use the first meaningful directory as the group key
                    folder = '/'.join(parts[:-1])
                else:
                    folder = ''
                
                if folder not in folder_files:
                    folder_files[folder] = []
                folder_files[folder].append((basename, name))
            
            print(f"   🔍 Found JSON files in {len(folder_files)} folder(s): {list(folder_files.keys())[:10]}")
            
            # Step 3: If all JSONs are in root (no folders), treat as single model
            if len(folder_files) == 1 and '' in folder_files:
                verdicted = None
                decisions = None
                vname = None
                for basename, fullname in folder_files['']:
                    content = zf.read(fullname).decode('utf-8')
                    if 'verdicted' in basename.lower():
                        verdicted = content
                        vname = basename
                        print(f"   ✅ Verdicted: {basename}")
                    elif 'decision' in basename.lower():
                        decisions = content
                        print(f"   ✅ Decisions: {basename}")
                    else:
                        try:
                            test = json.loads(content)
                            if isinstance(test, dict) and 'runs' in test:
                                verdicted = content
                                vname = basename
                                print(f"   ✅ Detected verdicted (by structure): {basename}")
                        except:
                            pass
                
                if verdicted:
                    hint = source_filename.rsplit('.', 1)[0]
                    results.append((verdicted, decisions, source_filename, hint))
                else:
                    errs.append(f"{source_filename}: No verdicted JSON found")
                return results, errs
            
            # Step 4: Multiple folders — each folder is a model
            # Find the deepest folders that actually contain JSON files
            # Group by the leaf folder that has verdicted files
            model_folders = {}
            for folder, files in folder_files.items():
                if folder == '':
                    continue
                has_verdicted = any('verdicted' in b.lower() for b, _ in files)
                has_runs = False
                if not has_verdicted:
                    # Check content structure
                    for basename, fullname in files:
                        try:
                            content = zf.read(fullname).decode('utf-8')
                            test = json.loads(content)
                            if isinstance(test, dict) and 'runs' in test:
                                has_runs = True
                                break
                        except:
                            pass
                if has_verdicted or has_runs:
                    model_folders[folder] = files
            
            # If no folders had verdicted files, check if root has them
            if not model_folders and '' in folder_files:
                verdicted = None
                decisions = None
                for basename, fullname in folder_files['']:
                    content = zf.read(fullname).decode('utf-8')
                    if 'verdicted' in basename.lower():
                        verdicted = content
                    elif 'decision' in basename.lower():
                        decisions = content
                if verdicted:
                    hint = source_filename.rsplit('.', 1)[0]
                    results.append((verdicted, decisions, source_filename, hint))
                else:
                    errs.append(f"{source_filename}: No model data found in any folder")
                return results, errs
            
            print(f"   🔍 Found {len(model_folders)} model folder(s)")
            
            for folder, files in model_folders.items():
                verdicted = None
                decisions = None
                for basename, fullname in files:
                    content = zf.read(fullname).decode('utf-8')
                    if 'verdicted' in basename.lower():
                        verdicted = content
                        print(f"   ✅ [{folder}] Verdicted: {basename}")
                    elif 'decision' in basename.lower():
                        decisions = content
                        print(f"   ✅ [{folder}] Decisions: {basename}")
                    else:
                        try:
                            test = json.loads(content)
                            if isinstance(test, dict) and 'runs' in test:
                                verdicted = content
                                print(f"   ✅ [{folder}] Detected verdicted: {basename}")
                        except:
                            pass
                
                if verdicted:
                    # Use the folder name as model name hint
                    folder_hint = folder.split('/')[-1] if '/' in folder else folder
                    results.append((verdicted, decisions, f"{source_filename}/{folder}", folder_hint))
                else:
                    errs.append(f"{source_filename}/{folder}: No verdicted JSON found")
        
        return results, errs
    
    # ── MAIN PROCESSING LOOP ─────────────────────────────────────
    for zip_file in zip_files:
        if zip_file.filename == "":
            continue
        if not allowed_zip_file(zip_file.filename):
            errors.append(f"{zip_file.filename}: Not a .zip file, skipped")
            continue
        
        try:
            import zipfile, io
            zip_data = io.BytesIO(zip_file.read())
            
            model_pairs, extract_errors = extract_models_from_zip(zip_data, zip_file.filename)
            errors.extend(extract_errors)
            
            print(f"\n📊 Extracted {len(model_pairs)} model(s) from {zip_file.filename}")
            
            for verdicted_content, decisions_content, label, hint in model_pairs:
                info, err = process_model_pair(verdicted_content, decisions_content, label, hint)
                if info:
                    models_processed.append(info)
                if err:
                    errors.append(err)
                    
        except Exception as e:
            errors.append(f"{zip_file.filename}: {str(e)}")
            print(f"ERROR processing {zip_file.filename}: {e}")
            import traceback
            traceback.print_exc()
    
    # Flash results
    if models_processed:
        msg_parts = [f"✅ Processed {len(models_processed)} model(s):"]
        for m in models_processed:
            decisions_info = f" | 🤖 {m['decisions']} decisions" if m['decisions'] > 0 else ""
            msg_parts.append(
                f"  • {m['name']}: "
                f"{m['runs']} runs, {m['findings']} findings, {m['cwes']} CWEs{decisions_info}"
            )
        flash(" | ".join(msg_parts), "success")
        
        # Set the first (or latest) model as current
        set_current_model(models_processed[0]['name'])
    
    if errors:
        flash(f"⚠️ Errors: {' | '.join(errors)}", "warning")
    
    if not models_processed:
        flash("No models were successfully processed", "danger")
        return redirect(url_for("index"))
    
    return redirect(url_for("model_select"))


@app.route("/model_select")
def model_select():
    """Show all loaded models for selection"""
    global ALL_MODELS
    
    if not ALL_MODELS:
        flash("No models loaded. Please upload ZIP files first.", "warning")
        return redirect(url_for("index"))
    
    models_info = []
    for name, data in ALL_MODELS.items():
        analysis = data['analysis']
        models_info.append({
            'name': name,
            'runs': analysis['metadata']['total_runs'],
            'findings': analysis['metadata']['total_findings'],
            'languages': analysis['metadata']['total_languages'],
            'cwes': analysis['metadata']['total_unique_cwes'],
            'has_decisions': bool(data['decisions']),
            'decisions_count': len(data['decisions']),
        })
    
    # Sort by name alphabetically
    models_info.sort(key=lambda x: x['name'])
    
    return render_template("model_select.html", models=models_info)


@app.route("/model_comparison")
def model_comparison():
    """Model comparison dashboard with charts and percentile analysis"""
    global ALL_MODELS
    
    if len(ALL_MODELS) < 2:
        flash("Need at least 2 models loaded for comparison. Please upload more ZIP files.", "warning")
        return redirect(url_for("model_select") if ALL_MODELS else url_for("index"))
    
    # Collect all languages across all models
    all_languages = set()
    for name, data in ALL_MODELS.items():
        all_languages.update(data['analysis']['by_language'].keys())
    all_languages = sorted(all_languages)
    
    return render_template("model_comparison.html", 
                         all_models=ALL_MODELS,
                         all_languages=all_languages)


@app.route("/api/delete_model", methods=["POST"])
def api_delete_model():
    """Delete a model from the loaded models"""
    global ALL_MODELS, CURRENT_MODEL, ANALYSIS_DATA, DECISIONS_DATA
    
    model_name = request.form.get('model_name', '').strip()
    if not model_name:
        return json.dumps({'error': 'No model name provided'}), 400, {'Content-Type': 'application/json'}
    
    if model_name not in ALL_MODELS:
        return json.dumps({'error': 'Model not found: ' + model_name}), 404, {'Content-Type': 'application/json'}
    
    del ALL_MODELS[model_name]
    
    # If we deleted the current model, switch to another or clear
    if CURRENT_MODEL == model_name:
        if ALL_MODELS:
            set_current_model(list(ALL_MODELS.keys())[0])
        else:
            CURRENT_MODEL = None
            ANALYSIS_DATA = None
            DECISIONS_DATA = {}
    
    return json.dumps({
        'success': True, 
        'deleted': model_name, 
        'remaining': len(ALL_MODELS)
    }), 200, {'Content-Type': 'application/json'}


@app.route("/api/delete_all_models", methods=["POST"])
def api_delete_all_models():
    """Delete all loaded models"""
    global ALL_MODELS, CURRENT_MODEL, ANALYSIS_DATA, DECISIONS_DATA
    
    count = len(ALL_MODELS)
    ALL_MODELS.clear()
    CURRENT_MODEL = None
    ANALYSIS_DATA = None
    DECISIONS_DATA = {}
    
    return json.dumps({
        'success': True,
        'deleted': count
    }), 200, {'Content-Type': 'application/json'}


@app.route("/api/comparison_data")
def api_comparison_data():
    """API endpoint returning comparison data for all models, optionally filtered by language"""
    global ALL_MODELS
    
    language_filter = request.args.get('language', 'all')
    
    comparison = {
        'language_filter': language_filter,
        'models': [],
        'all_languages': sorted(set(
            lang
            for data in ALL_MODELS.values()
            for lang in data['analysis']['by_language'].keys()
        )),
        'percentiles': {}
    }
    
    for model_name, model_data in ALL_MODELS.items():
        analysis = model_data['analysis']
        
        if language_filter == 'all':
            # Use global risk scores
            risk_scores = analysis.get('risk_scores', {})
            # Aggregate stats across all languages
            total_tp = sum(
                cwe_data['verdicts'].get('true_positive', 0)
                for lang_data in analysis['by_language'].values()
                for cwe_data in lang_data['cwes'].values()
            )
            total_fp = sum(
                cwe_data['verdicts'].get('false_positive', 0)
                for lang_data in analysis['by_language'].values()
                for cwe_data in lang_data['cwes'].values()
            )
            total_findings = analysis['metadata']['total_findings']
            languages_present = list(analysis['by_language'].keys())
        else:
            # Use per-language risk scores
            risk_scores = analysis.get('risk_scores_by_language', {}).get(language_filter, {})
            lang_data = analysis['by_language'].get(language_filter, {})
            if lang_data:
                total_tp = lang_data.get('statistics', {}).get('true_positives', 0)
                total_fp = lang_data.get('statistics', {}).get('false_positives', 0)
                total_findings = sum(
                    cwe_data['verdicts'].get('true_positive', 0) + cwe_data['verdicts'].get('false_positive', 0)
                    for cwe_data in lang_data.get('cwes', {}).values()
                )
            else:
                total_tp = 0
                total_fp = 0
                total_findings = 0
            languages_present = [language_filter] if lang_data else []
        
        # Calculate metrics from risk scores
        scores_list = [s['risk_score'] for s in risk_scores.values()]
        num_cwes = len(risk_scores)
        sum_risk = sum(scores_list) if scores_list else 0
        max_risk = max(scores_list) if scores_list else 0
        avg_risk = sum_risk / num_cwes if num_cwes > 0 else 0
        
        # Severity breakdown from risk scores
        severity_breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'MINIMAL': 0}
        for s in risk_scores.values():
            severity_breakdown[s['risk_level']] = severity_breakdown.get(s['risk_level'], 0) + 1
        
        # CWE details for the table
        cwe_details = []
        for cwe_id, score_data in sorted(risk_scores.items(), key=lambda x: x[1]['risk_score'], reverse=True):
            cwe_details.append({
                'cwe_id': cwe_id,
                'cwe_name': get_cwe_name(cwe_id),
                'owasp': get_owasp_category(cwe_id),
                'risk_score': score_data['risk_score'],
                'risk_level': score_data['risk_level'],
                'tp_count': score_data['tp_count'],
                'runs_count': score_data['runs_count'],
                'tools_count': score_data['tools_count'],
                'severities': list(score_data.get('severities', [])),
            })
        
        # Data-derived metrics only (no constants)
        total_runs = analysis['metadata']['total_runs']
        
        systematic = sum(1 for s in risk_scores.values() if s['runs_count'] / total_runs > 0.5) if total_runs > 0 else 0
        systematic_ratio = round(systematic / max(num_cwes, 1), 4)
        runs_with_tp = len(set(r for s in risk_scores.values() for r in s.get('runs', [])))
        saturation = round(runs_with_tp / total_runs, 4) if total_runs > 0 else 0
        
        # TP rate
        tp_rate = round(total_tp / (total_tp + total_fp) * 100, 1) if (total_tp + total_fp) > 0 else 0
        
        # ── AGGREGATION METRICS ──────────────────────────────────
        sum_of_squares = sum(s * s for s in scores_list) if scores_list else 0
        rms = math.sqrt(sum_of_squares / num_cwes) if num_cwes > 0 else 0
        sum_sqrt = sum(math.sqrt(s) for s in scores_list) if scores_list else 0
        sum_log = sum(math.log10(s + 1) for s in scores_list) if scores_list else 0
        geometric_mean = math.pow(10, sum_log / num_cwes) - 1 if num_cwes > 0 else 0
        
        comparison['models'].append({
            'name': model_name,
            'num_cwes': num_cwes,
            'sum_risk': round(sum_risk, 2),
            'max_risk': round(max_risk, 2),
            'avg_risk': round(avg_risk, 2),
            'total_tp': total_tp,
            'total_fp': total_fp,
            'tp_rate': tp_rate,
            'total_findings': total_findings,
            'total_runs': total_runs,
            'severity_breakdown': severity_breakdown,
            'systematic_cwes': systematic,
            'systematic_ratio': systematic_ratio,
            'saturation': saturation,
            'runs_with_tp': runs_with_tp,
            'languages_present': languages_present,
            'cwe_details': cwe_details,
            # Aggregation metrics
            'sum_of_squares': round(sum_of_squares, 2),
            'rms': round(rms, 2),
            'sum_sqrt': round(sum_sqrt, 2),
            'geometric_mean': round(geometric_mean, 2),
            # Calculation breakdown
            'calc': {
                'scores_list': [round(s, 2) for s in sorted(scores_list, reverse=True)]
            }
        })
    
    # Sort by sum_of_squares ascending (lowest = most secure)
    comparison['models'].sort(key=lambda x: x['sum_of_squares'])
    
    # Calculate percentiles on sum_risk (lower = better, so invert for percentile)
    all_sum_risk = [m['sum_risk'] for m in comparison['models']]
    if len(all_sum_risk) >= 2:
        arr = np.array(all_sum_risk)
        comparison['percentiles'] = {
            'p95': round(float(np.percentile(arr, 95)), 2),
            'p75': round(float(np.percentile(arr, 75)), 2),
            'p50': round(float(np.percentile(arr, 50)), 2),
            'p25': round(float(np.percentile(arr, 25)), 2),
            'p5': round(float(np.percentile(arr, 5)), 2),
        }
        
        # Percentile rank: lower sum_risk = better, so % of models with HIGHER sum_risk
        for model in comparison['models']:
            model['percentile'] = round(
                float((arr > model['sum_risk']).sum() / len(arr) * 100), 1
            )
    
    return json.dumps(comparison), 200, {'Content-Type': 'application/json'}


@app.route("/analysis_results")
@app.route("/analysis_results/<path:model_name>")
def analysis_results(model_name=None):
    """Display analysis results for a specific model"""
    global ALL_MODELS
    
    # Also support ?model= query param as fallback
    if not model_name:
        model_name = request.args.get('model')
    
    if model_name and model_name in ALL_MODELS:
        set_current_model(model_name)
    elif not ANALYSIS_DATA and ALL_MODELS:
        # No model selected, go to selection
        return redirect(url_for("model_select"))
    
    if ANALYSIS_DATA is None:
        flash("No analysis data available. Please upload ZIP files first.", "warning")
        return redirect(url_for("index"))
    
    return render_template("analysis_results.html", 
                         analysis=ANALYSIS_DATA, 
                         has_decisions=bool(DECISIONS_DATA),
                         all_models=list(ALL_MODELS.keys()),
                         current_model=CURRENT_MODEL)


@app.route("/download_language_analysis_json")
def download_language_analysis_json():
    """Download the language-wise analysis as JSON"""
    global ANALYSIS_DATA
    
    if ANALYSIS_DATA is None:
        flash("No analysis data available", "warning")
        return redirect(url_for("index"))
    
    # Prepare JSON-serializable version (convert remaining sets if any)
    serializable_data = json.loads(json.dumps(ANALYSIS_DATA, default=str))
    
    filename = f"language_cwe_analysis_{ANALYSIS_DATA['metadata']['total_runs']}_runs.json"
    filepath = REPORT_DIR / filename
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(serializable_data, f, indent=2, ensure_ascii=False)
    
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


@app.route("/download_language_analysis_excel")
def download_language_analysis_excel():
    """Download language-wise CWE analysis as Excel"""
    global ANALYSIS_DATA
    
    if ANALYSIS_DATA is None:
        flash("No analysis data available", "warning")
        return redirect(url_for("index"))
    
    wb = Workbook()
    
    # Overview Sheet
    ws_overview = wb.active
    ws_overview.title = "Overview"
    
    # Styles
    header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF")
    center_align = Alignment(horizontal="center", vertical="center")
    
    # Write metadata
    ws_overview.append(["Language-Wise CWE Analysis"])
    ws_overview.append([])
    ws_overview.append(["Total Runs", ANALYSIS_DATA["metadata"]["total_runs"]])
    ws_overview.append(["Total Languages", ANALYSIS_DATA["metadata"]["total_languages"]])
    ws_overview.append(["Total Unique CWEs", ANALYSIS_DATA["metadata"]["total_unique_cwes"]])
    ws_overview.append(["Total Findings", ANALYSIS_DATA["metadata"]["total_findings"]])
    ws_overview.append(["True Positives", ANALYSIS_DATA["metadata"]["true_positives"]])
    ws_overview.append(["False Positives", ANALYSIS_DATA["metadata"]["false_positives"]])
    ws_overview.append([])
    
    # Overview table headers
    headers = ["CWE", "Name", "Languages", "Files Affected", "True Positives", "False Positives", "Runs Found"]
    ws_overview.append(headers)
    
    header_row = ws_overview.max_row
    for col in range(1, len(headers) + 1):
        cell = ws_overview.cell(header_row, col)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = center_align
    
    # Write overview data
    for cwe_id, cwe_data in ANALYSIS_DATA["overview"]["cwes"].items():
        ws_overview.append([
            cwe_id,
            cwe_data["cwe_name"],
            ", ".join(cwe_data["languages"]),
            cwe_data["total_files_affected"],
            cwe_data["true_positives"],
            cwe_data["false_positives"],
            ", ".join(map(str, cwe_data["found_in_runs"]))
        ])
    
    # Adjust column widths
    ws_overview.column_dimensions['A'].width = 15
    ws_overview.column_dimensions['B'].width = 50
    ws_overview.column_dimensions['C'].width = 20
    ws_overview.column_dimensions['D'].width = 15
    ws_overview.column_dimensions['E'].width = 15
    ws_overview.column_dimensions['F'].width = 15
    ws_overview.column_dimensions['G'].width = 20
    
    # Create a sheet for each language
    for lang_name, lang_data in ANALYSIS_DATA["by_language"].items():
        ws = wb.create_sheet(title=lang_name.upper()[:31])  # Sheet name limit is 31 chars
        
        # Language statistics
        ws.append([f"{lang_name.upper()} Statistics"])
        ws.append([])
        ws.append(["Total CWEs", lang_data["statistics"]["total_cwes"]])
        ws.append(["Total Files", lang_data["statistics"]["total_files"]])
        ws.append(["True Positives", lang_data["statistics"]["true_positives"]])
        ws.append(["False Positives", lang_data["statistics"]["false_positives"]])
        ws.append([])
        
        # CWE table headers
        headers = ["CWE", "Name", "Files Affected", "TP", "FP", "Severities", "Tools", "Runs"]
        ws.append(headers)
        
        header_row = ws.max_row
        for col in range(1, len(headers) + 1):
            cell = ws.cell(header_row, col)
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = center_align
        
        # Write CWE data
        for cwe_id, cwe_info in lang_data["cwes"].items():
            ws.append([
                cwe_id,
                cwe_info["cwe_name"],
                cwe_info["total_files_affected"],
                cwe_info["verdicts"]["true_positive"],
                cwe_info["verdicts"]["false_positive"],
                ", ".join(cwe_info["severities"]),
                ", ".join(cwe_info["tools"]),
                ", ".join(map(str, cwe_info["found_in_runs"]))
            ])
        
        # Adjust column widths
        ws.column_dimensions['A'].width = 15
        ws.column_dimensions['B'].width = 50
        ws.column_dimensions['C'].width = 15
        ws.column_dimensions['D'].width = 10
        ws.column_dimensions['E'].width = 10
        ws.column_dimensions['F'].width = 20
        ws.column_dimensions['G'].width = 20
        ws.column_dimensions['H'].width = 15
    
    filename = f"language_cwe_analysis_{ANALYSIS_DATA['metadata']['total_runs']}_runs.xlsx"
    filepath = REPORT_DIR / filename
    wb.save(filepath)
    
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


@app.route("/progress_stream/<scan_id>")
def progress_stream(scan_id):
    """Server-Sent Events stream for progress updates"""
    def generate():
        queue = progress_queues.get(scan_id)
        if not queue:
            yield f"data: {json.dumps({'type': 'error', 'message': 'Invalid scan ID'})}\n\n"
            return
        
        try:
            while True:
                try:
                    # Get update from queue (timeout after 30 seconds)
                    update = queue.get(timeout=30)
                    yield f"data: {json.dumps(update)}\n\n"
                    
                    # If complete or error, clean up and stop
                    if update.get("type") in ["complete", "error"]:
                        # Clean up queue after a delay
                        time.sleep(2)
                        if scan_id in progress_queues:
                            del progress_queues[scan_id]
                        break
                        
                except Exception as e:
                    # Timeout or error - send keepalive
                    yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"
        except GeneratorExit:
            # Client disconnected - clean up silently
            if scan_id in progress_queues:
                del progress_queues[scan_id]
    
    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/results")
def results_page():
    global ALL_RUNS
    if not ALL_RUNS:
        flash("No results yet. Upload projects first.", "warning")
        return redirect(url_for("index"))

    # Show the most recent run by default
    current_run = ALL_RUNS[-1]
    
    return render_template(
        "results.html",
        results=current_run["results"],
        sast_summary=current_run["sast_summary"],
        dep_summary=current_run["dep_summary"],
        project_name=current_run["project_name"],
        all_runs=ALL_RUNS,
        current_index=len(ALL_RUNS) - 1
    )


@app.route("/results/<int:run_index>")
def view_run(run_index):
    global ALL_RUNS
    
    if run_index < 0 or run_index >= len(ALL_RUNS):
        flash("Invalid run index", "danger")
        return redirect(url_for("results_page"))
    
    current_run = ALL_RUNS[run_index]
    
    return render_template(
        "results.html",
        results=current_run["results"],
        sast_summary=current_run["sast_summary"],
        dep_summary=current_run["dep_summary"],
        project_name=current_run["project_name"],
        all_runs=ALL_RUNS,
        current_index=run_index
    )


@app.route("/download_report/<int:run_index>")
def download_report(run_index):
    global ALL_RUNS
    
    if run_index < 0 or run_index >= len(ALL_RUNS):
        flash("Invalid run index", "danger")
        return redirect(url_for("results_page"))
    
    run_data = ALL_RUNS[run_index]
    project_name = run_data["project_name"]
    sast_summary = run_data["sast_summary"]
    dep_summary = run_data["dep_summary"]

    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in project_name)
    filename = f"security_scan_report_{safe_name}.docx"
    out_path = REPORT_DIR / filename

    generate_docx_report(project_name, sast_summary, dep_summary, out_path)

    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


@app.route("/download_comparison")
def download_comparison():
    """Download Excel with checkmarks (original format)"""
    global ALL_RUNS
    
    if len(ALL_RUNS) == 0:
        flash("No runs available to compare", "warning")
        return redirect(url_for("index"))
    
    filename = "cwe_comparison_checkmarks.xlsx"
    out_path = REPORT_DIR / filename
    
    generate_comparison_excel(ALL_RUNS, out_path)
    
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


@app.route("/download_detailed_counts")
def download_detailed_counts():
    """NEW: Download Excel with FILE COUNTS instead of checkmarks"""
    global ALL_RUNS
    
    if len(ALL_RUNS) == 0:
        flash("No runs available to compare", "warning")
        return redirect(url_for("index"))
    
    filename = "cwe_detailed_file_counts.xlsx"
    out_path = REPORT_DIR / filename
    
    generate_detailed_count_excel(ALL_RUNS, out_path)
    
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


@app.route("/download_json/<int:run_index>")
def download_json(run_index):
    """NEW: Download results as JSON in the user's specified format"""
    global ALL_RUNS
    
    if run_index < 0 or run_index >= len(ALL_RUNS):
        flash("Invalid run index", "danger")
        return redirect(url_for("results_page"))
    
    run_data = ALL_RUNS[run_index]
    project_name = run_data["project_name"]
    
    # Get RAW SAST results for accurate data
    sast_results = run_data.get("results", {}).get("sast", {})
    
    # Build JSON in user's format
    vulnerabilities = []
    vuln_id = 1
    
    for scanner_name, findings in sast_results.items():
        for finding in findings:
            cwe = finding.get("cwe", "CWE-UNKNOWN")
            if cwe == "CWE-UNKNOWN":
                continue
            
            vuln_entry = {
                "id": vuln_id,
                "cwe": cwe,
                "name": get_cwe_name(cwe),
                "file": finding.get("file", "unknown"),
                "line": finding.get("line", 0),
                "description": finding.get("message", f"Found by {scanner_name} scanner"),
                "severity": finding.get("severity", "UNKNOWN"),
                "scanner": scanner_name
            }
            vulnerabilities.append(vuln_entry)
            vuln_id += 1
    
    # Create final JSON structure
    output = {
        "run": project_name,
        "model": project_name,
        "language": "Multi-language",
        "vulnerabilities": vulnerabilities
    }
    
    # Save to file
    filename = f"vulnerabilities_{project_name}.json"
    out_path = REPORT_DIR / filename
    
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
    
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


def get_cwe_name(cwe: str) -> str:
    """Get human-readable CWE name - COMPREHENSIVE MAPPING (100+ CWEs)"""
    cwe_names = {
        # Input Validation
        "CWE-20": "Improper Input Validation",
        "CWE-74": "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
        "CWE-75": "Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)",
        "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "CWE-91": "XML Injection (aka Blind XPath Injection)",
        "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
        "CWE-95": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
        "CWE-96": "Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')",
        "CWE-97": "Improper Neutralization of Server-Side Includes (SSI) Within a Web Page",
        "CWE-98": "Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')",
        
        # Path Traversal & File Operations
        "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "CWE-23": "Relative Path Traversal",
        "CWE-36": "Absolute Path Traversal",
        "CWE-73": "External Control of File Name or Path",
        "CWE-434": "Unrestricted Upload of File with Dangerous Type",
        "CWE-59": "Improper Link Resolution Before File Access ('Link Following')",
        "CWE-377": "Insecure Temporary File",
        
        # Command Injection
        "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "CWE-77": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
        
        # Authentication & Access Control
        "CWE-287": "Improper Authentication",
        "CWE-306": "Missing Authentication for Critical Function",
        "CWE-285": "Improper Authorization",
        "CWE-284": "Improper Access Control",
        "CWE-862": "Missing Authorization",
        "CWE-863": "Incorrect Authorization",
        "CWE-276": "Incorrect Default Permissions",
        "CWE-732": "Incorrect Permission Assignment for Critical Resource",
        "CWE-250": "Execution with Unnecessary Privileges",
        "CWE-269": "Improper Privilege Management",
        
        # Cryptography
        "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
        "CWE-328": "Use of Weak Hash",
        "CWE-326": "Inadequate Encryption Strength",
        "CWE-321": "Use of Hard-coded Cryptographic Key",
        "CWE-322": "Key Exchange without Entity Authentication",
        "CWE-323": "Reusing a Nonce, Key Pair in Encryption",
        "CWE-324": "Use of a Key Past its Expiration Date",
        "CWE-325": "Missing Cryptographic Step",
        "CWE-329": "Generation of Predictable IV with CBC Mode",
        "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
        "CWE-330": "Use of Insufficiently Random Values",
        "CWE-331": "Insufficient Entropy",
        "CWE-335": "Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)",
        "CWE-336": "Same Seed in Pseudo-Random Number Generator (PRNG)",
        "CWE-337": "Predictable Seed in Pseudo-Random Number Generator (PRNG)",
        
        # SSL/TLS
        "CWE-295": "Improper Certificate Validation",
        "CWE-296": "Improper Following of a Certificate's Chain of Trust",
        "CWE-297": "Improper Validation of Certificate with Host Mismatch",
        "CWE-298": "Improper Validation of Certificate Expiration",
        "CWE-299": "Improper Check for Certificate Revocation",
        
        # Sensitive Data
        "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
        "CWE-209": "Generation of Error Message Containing Sensitive Information",
        "CWE-215": "Insertion of Sensitive Information Into Debugging Code",
        "CWE-312": "Cleartext Storage of Sensitive Information",
        "CWE-313": "Cleartext Storage in a File or on Disk",
        "CWE-314": "Cleartext Storage in the Registry",
        "CWE-315": "Cleartext Storage of Sensitive Information in a Cookie",
        "CWE-316": "Cleartext Storage of Sensitive Information in Memory",
        "CWE-317": "Cleartext Storage of Sensitive Information in GUI",
        "CWE-318": "Cleartext Storage of Sensitive Information in Executable",
        "CWE-319": "Cleartext Transmission of Sensitive Information",
        "CWE-798": "Use of Hard-coded Credentials",
        "CWE-259": "Use of Hard-coded Password",
        "CWE-257": "Storing Passwords in a Recoverable Format",
        
        # Session Management
        "CWE-384": "Session Fixation",
        "CWE-613": "Insufficient Session Expiration",
        "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
        "CWE-565": "Reliance on Cookies without Validation and Integrity Checking",
        
        # CSRF & Redirects
        "CWE-352": "Cross-Site Request Forgery (CSRF)",
        "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
        
        # XML & XXE
        "CWE-611": "Improper Restriction of XML External Entity Reference",
        "CWE-827": "Improper Control of Document Type Definition",
        
        # Deserialization
        "CWE-502": "Deserialization of Untrusted Data",
        "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        
        # Resource Management
        "CWE-400": "Uncontrolled Resource Consumption",
        "CWE-404": "Improper Resource Shutdown or Release",
        "CWE-770": "Allocation of Resources Without Limits or Throttling",
        "CWE-771": "Missing Reference to Active Allocated Resource",
        "CWE-772": "Missing Release of Resource after Effective Lifetime",
        "CWE-775": "Missing Release of File Descriptor or Handle after Effective Lifetime",
        "CWE-776": "Unrestricted Recursion",
        "CWE-834": "Excessive Iteration",
        
        # Memory Safety
        "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
        "CWE-121": "Stack-based Buffer Overflow",
        "CWE-122": "Heap-based Buffer Overflow",
        "CWE-125": "Out-of-bounds Read",
        "CWE-787": "Out-of-bounds Write",
        "CWE-416": "Use After Free",
        "CWE-415": "Double Free",
        "CWE-476": "NULL Pointer Dereference",
        "CWE-401": "Missing Release of Memory after Effective Lifetime",
        "CWE-911": "Improper Update of Reference Count",
        
        # Integer & Numeric Errors
        "CWE-190": "Integer Overflow or Wraparound",
        "CWE-191": "Integer Underflow (Wrap or Wraparound)",
        "CWE-680": "Integer Overflow to Buffer Overflow",
        "CWE-681": "Incorrect Conversion between Numeric Types",
        "CWE-682": "Incorrect Calculation",
        "CWE-369": "Divide By Zero",
        
        # Race Conditions
        "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
        "CWE-367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
        "CWE-364": "Signal Handler Race Condition",
        
        # Logic Errors
        "CWE-670": "Always-Incorrect Control Flow Implementation",
        "CWE-571": "Expression is Always True",
        "CWE-570": "Expression is Always False",
        "CWE-561": "Dead Code",
        "CWE-489": "Active Debug Code",
        "CWE-501": "Trust Boundary Violation",
        
        # Logging & Monitoring
        "CWE-117": "Improper Output Neutralization for Logs",
        "CWE-532": "Insertion of Sensitive Information into Log File",
        "CWE-533": "DEPRECATED: Information Exposure Through Server Log Files",
        
        # Configuration
        "CWE-1188": "Insecure Default Initialization of Resource",
        "CWE-426": "Untrusted Search Path",
        "CWE-427": "Uncontrolled Search Path Element",
        "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
        "CWE-830": "Inclusion of Web Functionality from an Untrusted Source",
        
        # Code Quality
        "CWE-477": "Use of Obsolete Function",
        "CWE-478": "Missing Default Case in Multiple Condition Expression",
        "CWE-479": "Signal Handler Use of a Non-reentrant Function",
        "CWE-480": "Use of Incorrect Operator",
        "CWE-483": "Incorrect Block Delimitation",
        "CWE-484": "Omitted Break Statement in Switch",
        
        # Expression Language Injection
        "CWE-917": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')",
        
        # Password & Auth
        "CWE-521": "Weak Password Requirements",
        "CWE-916": "Use of Password Hash With Insufficient Computational Effort",
        
        # Regex
        "CWE-1333": "Inefficient Regular Expression Complexity",
        
        # Prototype Pollution
        "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
        
        # Server-Side Request Forgery
        "CWE-918": "Server-Side Request Forgery (SSRF)",
        
        # Null Byte Injection
        "CWE-158": "Improper Neutralization of Null Byte or NUL Character",
        
        # Format String
        "CWE-134": "Use of Externally-Controlled Format String",
        
        # Information Disclosure
        "CWE-203": "Observable Discrepancy",
        "CWE-208": "Observable Timing Discrepancy",
        
        # Missing Support
        "CWE-353": "Missing Support for Integrity Check",
        
        # ZIP vulnerabilities
        "CWE-409": "Improper Handling of Highly Compressed Data (Data Amplification)",
        "CWE-410": "Insufficient Resource Pool",
    }
    return cwe_names.get(cwe, f"Unknown Vulnerability ({cwe})")


def get_owasp_category(cwe: str) -> str:
    """Map a CWE to its OWASP Top 10 2025 category.
    Based on official MITRE CWE View 1436 + Mend.io extended mapping.
    Source: https://cwe.mitre.org/data/definitions/1436.html
            https://docs.mend.io/platform/latest/owasp-top-10-cwe-coverage
            https://owasp.org/Top10/2025/
    Returns short label like 'A01 Broken Access Control' or 'Unmapped'.
    """
    OWASP_MAP = {
        # ── A01:2025 Broken Access Control (40 CWEs) ──────────────
        # Includes SSRF (was A10:2021), path traversal, access control, CSRF
        "CWE-22":  "A01 Broken Access Control",
        "CWE-23":  "A01 Broken Access Control",
        "CWE-35":  "A01 Broken Access Control",
        "CWE-36":  "A01 Broken Access Control",
        "CWE-59":  "A01 Broken Access Control",
        "CWE-200": "A01 Broken Access Control",
        "CWE-201": "A01 Broken Access Control",
        "CWE-219": "A01 Broken Access Control",
        "CWE-250": "A01 Broken Access Control",
        "CWE-264": "A01 Broken Access Control",
        "CWE-269": "A01 Broken Access Control",
        "CWE-275": "A01 Broken Access Control",
        "CWE-276": "A01 Broken Access Control",
        "CWE-284": "A01 Broken Access Control",
        "CWE-285": "A01 Broken Access Control",
        "CWE-352": "A01 Broken Access Control",
        "CWE-359": "A01 Broken Access Control",
        "CWE-377": "A01 Broken Access Control",
        "CWE-402": "A01 Broken Access Control",
        "CWE-425": "A01 Broken Access Control",
        "CWE-441": "A01 Broken Access Control",
        "CWE-497": "A01 Broken Access Control",
        "CWE-538": "A01 Broken Access Control",
        "CWE-540": "A01 Broken Access Control",
        "CWE-548": "A01 Broken Access Control",
        "CWE-552": "A01 Broken Access Control",
        "CWE-566": "A01 Broken Access Control",
        "CWE-601": "A01 Broken Access Control",
        "CWE-639": "A01 Broken Access Control",
        "CWE-651": "A01 Broken Access Control",
        "CWE-668": "A01 Broken Access Control",
        "CWE-706": "A01 Broken Access Control",
        "CWE-732": "A01 Broken Access Control",
        "CWE-749": "A01 Broken Access Control",
        "CWE-862": "A01 Broken Access Control",
        "CWE-863": "A01 Broken Access Control",
        "CWE-913": "A01 Broken Access Control",
        "CWE-918": "A01 Broken Access Control",  # SSRF — was A10:2021, merged into A01:2025
        "CWE-1188": "A01 Broken Access Control",

        # ── A02:2025 Security Misconfiguration (16 CWEs) ──────────
        # Was A05:2021. Includes XXE, debug code, cookie issues, CORS
        "CWE-2":   "A02 Security Misconfig",
        "CWE-11":  "A02 Security Misconfig",
        "CWE-13":  "A02 Security Misconfig",
        "CWE-15":  "A02 Security Misconfig",
        "CWE-16":  "A02 Security Misconfig",
        "CWE-215": "A02 Security Misconfig",
        "CWE-260": "A02 Security Misconfig",
        "CWE-315": "A02 Security Misconfig",
        "CWE-489": "A02 Security Misconfig",
        "CWE-525": "A02 Security Misconfig",
        "CWE-611": "A02 Security Misconfig",
        "CWE-614": "A02 Security Misconfig",
        "CWE-776": "A02 Security Misconfig",
        "CWE-827": "A02 Security Misconfig",
        "CWE-942": "A02 Security Misconfig",
        "CWE-1004": "A02 Security Misconfig",

        # ── A03:2025 Software Supply Chain Failures (5 CWEs) ──────
        # New in 2025. Expands A06:2021 (Vulnerable Components)
        "CWE-426": "A03 Supply Chain",
        "CWE-427": "A03 Supply Chain",
        "CWE-829": "A03 Supply Chain",
        "CWE-830": "A03 Supply Chain",
        "CWE-1104": "A03 Supply Chain",

        # ── A04:2025 Cryptographic Failures (32 CWEs) ─────────────
        # Was A02:2021. Includes weak crypto, hardcoded keys, cleartext
        "CWE-203": "A04 Crypto Failures",
        "CWE-208": "A04 Crypto Failures",
        "CWE-257": "A04 Crypto Failures",
        "CWE-259": "A04 Crypto Failures",
        "CWE-261": "A04 Crypto Failures",
        "CWE-295": "A04 Crypto Failures",
        "CWE-296": "A04 Crypto Failures",
        "CWE-297": "A04 Crypto Failures",
        "CWE-298": "A04 Crypto Failures",
        "CWE-299": "A04 Crypto Failures",
        "CWE-311": "A04 Crypto Failures",
        "CWE-312": "A04 Crypto Failures",
        "CWE-313": "A04 Crypto Failures",
        "CWE-314": "A04 Crypto Failures",
        "CWE-316": "A04 Crypto Failures",
        "CWE-317": "A04 Crypto Failures",
        "CWE-318": "A04 Crypto Failures",
        "CWE-319": "A04 Crypto Failures",
        "CWE-321": "A04 Crypto Failures",
        "CWE-322": "A04 Crypto Failures",
        "CWE-323": "A04 Crypto Failures",
        "CWE-324": "A04 Crypto Failures",
        "CWE-325": "A04 Crypto Failures",
        "CWE-326": "A04 Crypto Failures",
        "CWE-327": "A04 Crypto Failures",
        "CWE-328": "A04 Crypto Failures",
        "CWE-329": "A04 Crypto Failures",
        "CWE-330": "A04 Crypto Failures",
        "CWE-331": "A04 Crypto Failures",
        "CWE-335": "A04 Crypto Failures",
        "CWE-336": "A04 Crypto Failures",
        "CWE-337": "A04 Crypto Failures",
        "CWE-338": "A04 Crypto Failures",
        "CWE-347": "A04 Crypto Failures",
        "CWE-353": "A04 Crypto Failures",
        "CWE-780": "A04 Crypto Failures",
        "CWE-798": "A04 Crypto Failures",
        "CWE-916": "A04 Crypto Failures",

        # ── A05:2025 Injection (38 CWEs) ──────────────────────────
        # Was A03:2021. XSS, SQLi, command injection, SSTI, etc.
        "CWE-20":  "A05 Injection",
        "CWE-74":  "A05 Injection",
        "CWE-75":  "A05 Injection",
        "CWE-77":  "A05 Injection",
        "CWE-78":  "A05 Injection",
        "CWE-79":  "A05 Injection",
        "CWE-89":  "A05 Injection",
        "CWE-90":  "A05 Injection",
        "CWE-91":  "A05 Injection",
        "CWE-94":  "A05 Injection",
        "CWE-95":  "A05 Injection",
        "CWE-96":  "A05 Injection",
        "CWE-97":  "A05 Injection",
        "CWE-98":  "A05 Injection",
        "CWE-113": "A05 Injection",
        "CWE-116": "A05 Injection",
        "CWE-117": "A05 Injection",
        "CWE-134": "A05 Injection",
        "CWE-470": "A05 Injection",
        "CWE-643": "A05 Injection",
        "CWE-917": "A05 Injection",
        "CWE-943": "A05 Injection",
        "CWE-1321": "A05 Injection",
        "CWE-1336": "A05 Injection",

        # ── A06:2025 Insecure Design ──────────────────────────────
        # Was A04:2021. Architecture/logic flaws, dangerous functions
        "CWE-73":  "A06 Insecure Design",
        "CWE-183": "A06 Insecure Design",
        "CWE-209": "A06 Insecure Design",
        "CWE-213": "A06 Insecure Design",
        "CWE-256": "A06 Insecure Design",
        "CWE-434": "A06 Insecure Design",
        "CWE-472": "A06 Insecure Design",
        "CWE-501": "A06 Insecure Design",
        "CWE-522": "A06 Insecure Design",
        "CWE-598": "A06 Insecure Design",
        "CWE-602": "A06 Insecure Design",
        "CWE-620": "A06 Insecure Design",
        "CWE-656": "A06 Insecure Design",
        "CWE-676": "A06 Insecure Design",
        "CWE-799": "A06 Insecure Design",
        "CWE-840": "A06 Insecure Design",
        # Memory safety issues (C/C++ common) → Insecure Design
        "CWE-119": "A06 Insecure Design",
        "CWE-120": "A06 Insecure Design",
        "CWE-121": "A06 Insecure Design",
        "CWE-122": "A06 Insecure Design",
        "CWE-125": "A06 Insecure Design",
        "CWE-190": "A06 Insecure Design",
        "CWE-191": "A06 Insecure Design",
        "CWE-415": "A06 Insecure Design",
        "CWE-416": "A06 Insecure Design",
        "CWE-787": "A06 Insecure Design",
        # Race conditions / resource management → Insecure Design
        "CWE-362": "A06 Insecure Design",
        "CWE-364": "A06 Insecure Design",
        "CWE-367": "A06 Insecure Design",
        "CWE-400": "A06 Insecure Design",
        "CWE-401": "A06 Insecure Design",
        "CWE-404": "A06 Insecure Design",
        "CWE-770": "A06 Insecure Design",
        "CWE-771": "A06 Insecure Design",
        "CWE-772": "A06 Insecure Design",
        "CWE-775": "A06 Insecure Design",
        "CWE-834": "A06 Insecure Design",
        "CWE-1333": "A06 Insecure Design",
        # Code quality → Insecure Design
        "CWE-158": "A06 Insecure Design",
        "CWE-477": "A06 Insecure Design",
        "CWE-478": "A06 Insecure Design",
        "CWE-479": "A06 Insecure Design",
        "CWE-480": "A06 Insecure Design",
        "CWE-483": "A06 Insecure Design",
        "CWE-484": "A06 Insecure Design",
        "CWE-561": "A06 Insecure Design",
        "CWE-570": "A06 Insecure Design",
        "CWE-571": "A06 Insecure Design",
        "CWE-670": "A06 Insecure Design",
        "CWE-680": "A06 Insecure Design",
        "CWE-681": "A06 Insecure Design",
        "CWE-682": "A06 Insecure Design",
        "CWE-911": "A06 Insecure Design",

        # ── A07:2025 Authentication Failures (36 CWEs) ────────────
        # Was A07:2021. Renamed from "Identification and Authentication Failures"
        "CWE-287": "A07 Auth Failures",
        "CWE-306": "A07 Auth Failures",
        "CWE-346": "A07 Auth Failures",
        "CWE-384": "A07 Auth Failures",
        "CWE-521": "A07 Auth Failures",
        "CWE-613": "A07 Auth Failures",
        "CWE-620": "A07 Auth Failures",
        "CWE-640": "A07 Auth Failures",
        "CWE-941": "A07 Auth Failures",

        # ── A08:2025 Software or Data Integrity Failures ──────────
        # Same as A08:2021. Deserialization, unsigned code, etc.
        "CWE-345": "A08 Integrity Failures",
        "CWE-502": "A08 Integrity Failures",
        "CWE-565": "A08 Integrity Failures",
        "CWE-784": "A08 Integrity Failures",
        "CWE-915": "A08 Integrity Failures",

        # ── A09:2025 Security Logging & Alerting Failures ─────────
        # Was A09:2021. Renamed to emphasize alerting
        "CWE-117": "A09 Logging Failures",
        "CWE-223": "A09 Logging Failures",
        "CWE-532": "A09 Logging Failures",
        "CWE-533": "A09 Logging Failures",
        "CWE-778": "A09 Logging Failures",

        # ── A10:2025 Mishandling of Exceptional Conditions (new) ──
        # New in 2025. Error handling, fail-open, null deref, divide-by-zero
        "CWE-209": "A10 Exception Handling",  # also in A06
        "CWE-248": "A10 Exception Handling",
        "CWE-274": "A10 Exception Handling",
        "CWE-280": "A10 Exception Handling",
        "CWE-369": "A10 Exception Handling",
        "CWE-395": "A10 Exception Handling",
        "CWE-396": "A10 Exception Handling",
        "CWE-397": "A10 Exception Handling",
        "CWE-460": "A10 Exception Handling",
        "CWE-476": "A10 Exception Handling",
        "CWE-636": "A10 Exception Handling",
        "CWE-754": "A10 Exception Handling",
        "CWE-755": "A10 Exception Handling",
        "CWE-756": "A10 Exception Handling",
        "CWE-757": "A10 Exception Handling",
        "CWE-390": "A10 Exception Handling",
        "CWE-391": "A10 Exception Handling",
        "CWE-392": "A10 Exception Handling",
        "CWE-393": "A10 Exception Handling",
        "CWE-394": "A10 Exception Handling",
        "CWE-409": "A10 Exception Handling",
        "CWE-410": "A10 Exception Handling",
    }
    return OWASP_MAP.get(cwe, "Unmapped")


@app.route("/download_consolidated_json")
def download_consolidated_json():
    """Download all runs data in a single consolidated JSON file"""
    if not ALL_RUNS:
        flash("No runs available to download", "warning")
        return redirect(url_for("index"))
    
    # Create consolidated data structure
    consolidated_data = {
        "total_runs": len(ALL_RUNS),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "runs": []
    }
    
    for idx, run_data in enumerate(ALL_RUNS):
        # Extract project name without file extension and run numbers
        project_name = run_data.get("project_name", f"unknown_project")
        
        # Remove .zip extension if present
        if project_name.endswith('.zip'):
            project_name = project_name[:-4]
        
        # Remove run numbers like "-run1", "-run2", "_run1", "_run2" at the end
        import re
        project_name = re.sub(r'[-_]run\d+$', '', project_name, flags=re.IGNORECASE)
        
        run_info = {
            "run_number": idx + 1,
            "scan_timestamp": run_data.get("timestamp", "N/A"),
            "results": run_data.get("results", {})  # Only raw tool results
        }
        consolidated_data["runs"].append(run_info)
    
    # Extract unique project name (assume all runs are from same project)
    # Use the first run's project name
    if consolidated_data["runs"]:
        first_run = ALL_RUNS[0]
        project_name = first_run.get("project_name", "unknown_project")
        if project_name.endswith('.zip'):
            project_name = project_name[:-4]
        import re
        project_name = re.sub(r'[-_]run\d+$', '', project_name, flags=re.IGNORECASE)
        consolidated_data["project"] = project_name
    else:
        consolidated_data["project"] = "unknown_project"
    
    # Save to file
    filename = f"consolidated_all_runs_{len(ALL_RUNS)}_runs.json"
    filepath = REPORT_DIR / filename
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(consolidated_data, f, indent=2, ensure_ascii=False)
    
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


@app.route("/download_cwe_analysis_json")
def download_cwe_analysis_json():
    """
    Download detailed CWE analysis JSON with:
    - CWE info
    - What runs they were found in
    - What tools detected them
    - How many unique files per run and total
    - CWE descriptions from tools
    """
    if not ALL_RUNS:
        flash("No runs available to download", "warning")
        return redirect(url_for("index"))
    
    # Collect comprehensive CWE data
    cwe_analysis = {
        "total_runs": len(ALL_RUNS),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cwes": {}
    }
    
    # Process each run to collect CWE information
    for run_idx, run_data in enumerate(ALL_RUNS):
        sast_summary = run_data.get("sast_summary", [])
        results = run_data.get("results", {})
        sast_results = results.get("sast", {})
        
        # First pass: Count files from RAW scanner results (same as Excel!)
        cwe_files_this_run = {}  # cwe -> set of files for THIS run
        
        for scanner_name, findings in sast_results.items():
            for finding in findings:
                cwe = finding.get("cwe")
                if cwe and cwe != "CWE-UNKNOWN":
                    if cwe not in cwe_files_this_run:
                        cwe_files_this_run[cwe] = set()
                    
                    file_path = finding.get("file")
                    if file_path:
                        cwe_files_this_run[cwe].add(file_path)
        
        # Second pass: Build CWE analysis using summary for other data
        for item in sast_summary:
            cwe = item.get("cwe")
            if not cwe or cwe == "CWE-UNKNOWN":
                continue
            
            # Initialize CWE entry if not exists
            if cwe not in cwe_analysis["cwes"]:
                cwe_analysis["cwes"][cwe] = {
                    "cwe_id": cwe,
                    "cwe_name": get_cwe_name(cwe),
                    "found_in_runs": [],
                    "total_runs_found": 0,
                    "tools_detected_by": set(),
                    "severity_levels": set(),
                    "file_counts_per_run": {},
                    "files_per_run": {},  # Track actual file sets per run
                    "total_unique_files": 0,
                    "descriptions": [],
                    "examples": []
                }
            
            cwe_entry = cwe_analysis["cwes"][cwe]
            run_number = run_idx + 1
            
            # Add run information
            if run_number not in cwe_entry["found_in_runs"]:
                cwe_entry["found_in_runs"].append(run_number)
            
            # Add tools
            scanners = item.get("scanners", [])
            for scanner in scanners:
                cwe_entry["tools_detected_by"].add(scanner)
            
            # Add severity
            severity = item.get("severity", "UNKNOWN")
            cwe_entry["severity_levels"].add(severity)
            
            # Use the file count from RAW scanner results (same as Excel!)
            files_in_this_run = cwe_files_this_run.get(cwe, set())
            cwe_entry["files_per_run"][run_number] = files_in_this_run
            cwe_entry["file_counts_per_run"][f"run_{run_number}"] = len(files_in_this_run)
            
            # Store example instances (limited to 3 for display only)
            examples = item.get("examples", [])
            for ex in examples[:3]:  # Limit to 3 examples per run for display
                example_info = {
                    "run": run_number,
                    "file": ex.get("file", ""),
                    "line": ex.get("line", ""),
                    "scanner": ex.get("scanner", ""),
                    "message": ex.get("message", "")
                }
                cwe_entry["examples"].append(example_info)
        
        # Also collect descriptions from raw scanner results
        sast_results = results.get("sast", {})
        
        # Semgrep descriptions
        semgrep_findings = sast_results.get("semgrep", [])
        for finding in semgrep_findings:
            cwe = finding.get("cwe")
            if cwe and cwe in cwe_analysis["cwes"]:
                message = finding.get("message", "")
                if message and message not in cwe_analysis["cwes"][cwe]["descriptions"]:
                    cwe_analysis["cwes"][cwe]["descriptions"].append({
                        "tool": "Semgrep",
                        "description": message
                    })
        
        # Bearer descriptions
        bearer_findings = sast_results.get("bearer", [])
        for finding in bearer_findings:
            cwe = finding.get("cwe")
            if cwe and cwe in cwe_analysis["cwes"]:
                message = finding.get("message", "")
                if message and message not in cwe_analysis["cwes"][cwe]["descriptions"]:
                    cwe_analysis["cwes"][cwe]["descriptions"].append({
                        "tool": "Bearer",
                        "description": message
                    })
        
        # Bandit descriptions
        bandit_findings = sast_results.get("bandit", [])
        for finding in bandit_findings:
            cwe = finding.get("cwe")
            if cwe and cwe in cwe_analysis["cwes"]:
                message = finding.get("message", "")
                if message and message not in cwe_analysis["cwes"][cwe]["descriptions"]:
                    cwe_analysis["cwes"][cwe]["descriptions"].append({
                        "tool": "Bandit",
                        "description": message
                    })
    
    # Post-process: convert sets to lists and calculate totals
    for cwe, data in cwe_analysis["cwes"].items():
        data["tools_detected_by"] = sorted(list(data["tools_detected_by"]))
        data["severity_levels"] = sorted(list(data["severity_levels"]))
        data["total_runs_found"] = len(data["found_in_runs"])
        data["found_in_runs"] = sorted(data["found_in_runs"])
        
        # Calculate total unique files across ALL runs
        all_files = set()
        for run_num, file_set in data["files_per_run"].items():
            all_files.update(file_set)
        data["total_unique_files"] = len(all_files)
        
        # Remove the temporary files_per_run tracking (not needed in output)
        del data["files_per_run"]
        
        # Deduplicate descriptions
        seen_descriptions = set()
        unique_descriptions = []
        for desc in data["descriptions"]:
            desc_text = desc["description"]
            if desc_text not in seen_descriptions:
                seen_descriptions.add(desc_text)
                unique_descriptions.append(desc)
        data["descriptions"] = unique_descriptions[:5]  # Limit to 5 unique descriptions
        
        # Calculate statistics
        file_counts = list(data["file_counts_per_run"].values())
        data["statistics"] = {
            "average_files_per_run": round(sum(file_counts) / len(file_counts), 2) if file_counts else 0,
            "max_files_in_single_run": max(file_counts) if file_counts else 0,
            "min_files_in_single_run": min(file_counts) if file_counts else 0,
            "total_instances_across_runs": sum(file_counts)
        }
    
    # Sort CWEs by total runs found (most common first)
    sorted_cwes = dict(sorted(
        cwe_analysis["cwes"].items(),
        key=lambda x: (x[1]["total_runs_found"], x[1]["total_unique_files"]),
        reverse=True
    ))
    cwe_analysis["cwes"] = sorted_cwes
    cwe_analysis["total_unique_cwes"] = len(sorted_cwes)
    
    # Save to file
    filename = f"cwe_analysis_{len(ALL_RUNS)}_runs.json"
    filepath = REPORT_DIR / filename
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(cwe_analysis, f, indent=2, ensure_ascii=False)
    
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


@app.route("/clear_runs")
def clear_runs():
    global ALL_RUNS
    ALL_RUNS = []
    flash("All previous runs cleared", "info")
    return redirect(url_for("index"))


@app.route("/cleanup_all")
def cleanup_all():
    """Manual cleanup endpoint - removes all temporary files"""
    try:
        # Clean reports
        cleanup_old_reports()
        
        # Clean temp directories
        cleanup_temp_directories()
        
        # Clean uploads
        for file in UPLOAD_DIR.glob("*.zip"):
            file.unlink()
        
        # Force clean ALL reports (not just old ones)
        for file in REPORT_DIR.glob("*"):
            if file.is_file():
                file.unlink()
        
        flash("✅ All temporary files cleaned up!", "success")
    except Exception as e:
        flash(f"Warning: Some files could not be cleaned: {e}", "warning")
    
    return redirect(url_for("index"))


@app.route("/score_calculation")
def score_calculation():
    """
    Show detailed score calculation breakdown for all CWEs
    """
    if not ANALYSIS_DATA:
        flash("No analysis data available. Please upload and analyze a JSON file first.", "warning")
        return redirect(url_for("index"))
    
    return render_template("score_calculation.html", 
                         analysis=ANALYSIS_DATA,
                         total_runs=ANALYSIS_DATA['metadata']['total_runs'])


@app.route("/cwe_calculation/<cwe_id>")
def cwe_calculation(cwe_id):
    """
    Show detailed calculation for a specific CWE
    """
    if not ANALYSIS_DATA or 'risk_scores' not in ANALYSIS_DATA:
        flash("No scoring data available. Please upload and analyze a JSON file first.", "warning")
        return redirect(url_for("index"))
    
    if cwe_id not in ANALYSIS_DATA['risk_scores']:
        flash(f"CWE {cwe_id} not found in current analysis.", "warning")
        return redirect(url_for("analysis_results"))
    
    # Get the score data
    score_data = ANALYSIS_DATA['risk_scores'][cwe_id]
    
    # Find the CWE details from language data
    cwe_details = None
    for lang, lang_data in ANALYSIS_DATA['by_language'].items():
        if cwe_id in lang_data['cwes']:
            cwe_details = lang_data['cwes'][cwe_id]
            cwe_details['language'] = lang
            break
    
    return render_template("cwe_calculation_detail.html",
                         cwe_id=cwe_id,
                         score_data=score_data,
                         cwe_details=cwe_details,
                         total_runs=ANALYSIS_DATA['metadata']['total_runs'])


@app.route("/api/decision/<stable_id>")
def get_decision(stable_id):
    """API endpoint to get AI decision data by stable_id"""
    global DECISIONS_DATA
    
    # Also check for model param
    model_name = request.args.get('model', CURRENT_MODEL)
    decisions = DECISIONS_DATA
    if model_name and model_name in ALL_MODELS:
        decisions = ALL_MODELS[model_name]['decisions']
    
    if not decisions:
        return json.dumps({"error": "No decisions data loaded"}), 404, {'Content-Type': 'application/json'}
    
    decision = decisions.get(stable_id)
    if not decision:
        return json.dumps({"error": f"Decision not found for stable_id: {stable_id}"}), 404, {'Content-Type': 'application/json'}
    
    # Return only the fields needed for the modal (exclude raw_response and prompt to save bandwidth)
    safe_decision = {
        "stable_id": decision.get("stable_id", ""),
        "verdict": decision.get("verdict", ""),
        "confidence": decision.get("confidence", ""),
        "file_relevance": decision.get("file_relevance", ""),
        "file_relevance_reason": decision.get("file_relevance_reason", ""),
        "justification": decision.get("justification", ""),
        "recommended_fix": decision.get("recommended_fix", ""),
        "evidence": decision.get("evidence", []),
        "decision_trace": decision.get("decision_trace", []),
        "scanner": decision.get("scanner", ""),
        "rule_id": decision.get("rule_id", ""),
        "cwe": decision.get("cwe", ""),
        "severity": decision.get("severity", ""),
        "file": decision.get("file", ""),
        "line": decision.get("line", ""),
        "message": decision.get("message", ""),
        "project": decision.get("project", ""),
        "run_number": decision.get("run_number", ""),
    }
    
    return json.dumps(safe_decision), 200, {'Content-Type': 'application/json'}


if __name__ == "__main__":
    print("=" * 60)
    print("Multi-Run Security Scanner Starting...")
    print("=" * 60)
    
    # Cleanup on startup
    print("\n🧹 Cleaning up old files...")
    cleanup_old_reports()
    cleanup_temp_directories()
    
    # Clean uploads directory
    try:
        for file in UPLOAD_DIR.glob("*.zip"):
            file.unlink()
            print(f"Removed old upload: {file.name}")
    except Exception as e:
        print(f"Warning: Could not clean uploads: {e}")
    
    print("\n✅ Cleanup complete!")
    print("\n🚀 Starting server on http://localhost:8080")
    print("=" * 60)
    print()
    
    app.run(host="0.0.0.0", port=8080, debug=True, use_reloader=False)
