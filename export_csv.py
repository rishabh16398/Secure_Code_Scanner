#!/usr/bin/env python3
"""
CLI tool to process Incomplete Run 2 style directories and emit a CSV with
per-model / per-framework / per-language / per-CWE scoring data.

Expected directory layout:
    <input_dir>/
        <Model Name>/
            <model-slug>_<framework-name>/
                Scanning Results/
                    consolidated_all_runs_10_runs.verdicted.json

Usage:
    python export_csv.py [input_dir] [output.csv]

Defaults:
    input_dir  = "input files/Incomplete Run 2"
    output.csv = "results.csv"
"""

import argparse
import csv
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Import scoring/analysis functions from the Flask app.  The app entry-point
# is guarded by __main__, so importing it only creates an in-memory Flask
# object and two harmless directories.
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent))
from app import (
    analyze_json_by_language,
    calculate_risk_scores,
)

# ---------------------------------------------------------------------------
# CSV column order
# ---------------------------------------------------------------------------
FIELDNAMES = [
    "model",
    "framework",
    "language",
    "cwe_id",
    "cwe_name",
    "risk_score",
    "risk_level",
    "V",
    "I",
    "L",
    "Vol",
    "C",
    "tp_count",
    "fp_count",
    "tp_file_count",
    "runs_count",
    "tools_count",
    "tools",
    "severities",
]


def extract_framework(folder_name: str) -> str:
    """
    Given a folder like 'gemini-2.5-pro_python-basic', return 'python-basic'.
    If there is no '_', return the folder name unchanged.
    """
    idx = folder_name.find("_")
    if idx == -1:
        return folder_name
    return folder_name[idx + 1:]


def process_verdicted_json(json_path: Path, model: str, framework: str) -> list[dict]:
    """
    Load one verdicted JSON file and return a list of CSV row dicts —
    one per language × CWE combination that has at least one true positive.
    """
    with open(json_path, encoding="utf-8") as f:
        json_data = json.load(f)

    total_runs = json_data.get("total_runs", 10)

    analysis = analyze_json_by_language(json_data)
    per_language_scores, _ = calculate_risk_scores(analysis, total_runs)

    rows = []
    for language, cwe_scores in per_language_scores.items():
        for cwe_id, score in cwe_scores.items():
            rows.append({
                "model": model,
                "framework": framework,
                "language": language,
                "cwe_id": cwe_id,
                "cwe_name": analysis["by_language"][language]["cwes"][cwe_id].get("cwe_name", ""),
                "risk_score": score["risk_score"],
                "risk_level": score["risk_level"],
                "V": score["V"],
                "I": score["I"],
                "L": score["L"],
                "Vol": score["Vol"],
                "C": score["C"],
                "tp_count": score["tp_count"],
                "fp_count": score["fp_count"],
                "tp_file_count": score["tp_file_count"],
                "runs_count": score["runs_count"],
                "tools_count": score["tools_count"],
                "tools": ";".join(sorted(score["tools"])),
                "severities": ";".join(sorted(score["severities"])),
            })

    return rows


def main():
    parser = argparse.ArgumentParser(description="Export CWE scoring data to CSV.")
    parser.add_argument(
        "input_dir",
        nargs="?",
        default="input files/Incomplete Run 2",
        help="Root directory containing model subdirectories (default: 'input files/Incomplete Run 2')",
    )
    parser.add_argument(
        "output_csv",
        nargs="?",
        default="results.csv",
        help="Output CSV file path (default: results.csv)",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    if not input_dir.is_dir():
        print(f"Error: input directory not found: {input_dir}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output_csv)

    # Find all verdicted JSON files.
    # Expected depth: <input_dir>/<model>/<model-slug_framework>/Scanning Results/*.verdicted.json
    verdicted_files = sorted(input_dir.rglob("*.verdicted.json"))
    if not verdicted_files:
        print(f"No *.verdicted.json files found under {input_dir}", file=sys.stderr)
        sys.exit(1)

    all_rows = []
    for json_path in verdicted_files:
        # Infer model and framework from path components.
        # json_path:  .../Gemini 2.5 Flash/gemini-2.5-flash_python-basic/Scanning Results/...
        # parents[0] = Scanning Results
        # parents[1] = gemini-2.5-flash_python-basic
        # parents[2] = Gemini 2.5 Flash  (model name)
        parts = json_path.parts
        scanning_results_dir = json_path.parent
        framework_dir = scanning_results_dir.parent
        model_dir = framework_dir.parent

        model = model_dir.name
        framework = extract_framework(framework_dir.name)

        print(f"Processing: model={model!r}, framework={framework!r} ...")
        try:
            rows = process_verdicted_json(json_path, model, framework)
            all_rows.extend(rows)
        except Exception as exc:
            print(f"  Warning: failed to process {json_path}: {exc}", file=sys.stderr)

    print(f"\nWriting {len(all_rows)} rows to {output_path} ...")
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(all_rows)

    print("Done.")


if __name__ == "__main__":
    main()
