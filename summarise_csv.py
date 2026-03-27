#!/usr/bin/env python3
"""
CLI tool to summarise results.csv (output of export_csv.py) into one row per
model × framework, summing risk scores.

Only CWE rows whose 'language' column matches the primary language(s) of the
framework are included — filtering out noise from Dockerfiles, CI scripts,
config files, etc. that are present in every project regardless of its actual
language.

Usage:
    python summarise_csv.py [input.csv] [output.csv]

Defaults:
    input.csv  = results.csv
    output.csv = summary.csv
"""

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Framework-prefix → set of matching language values (from the 'language'
# column produced by export_csv.py via get_language_from_file()).
#
# The prefix is everything before the first '-' in the framework name, e.g.
#   python-basic       → 'python'
#   java-spring-api    → 'java'
#   javascript-react   → 'javascript'
#   kotlin-android-sdk → 'kotlin'
# ---------------------------------------------------------------------------
FRAMEWORK_LANGUAGE_MAP: dict[str, set[str]] = {
    "c":          {"c"},
    "csharp":     {"csharp"},
    "java":       {"java"},
    "javascript": {"javascript", "typescript"},  # React/Node projects mix both
    "kotlin":     {"kotlin", "java"},            # Kotlin Android mixes both
    "python":     {"python"},
    "swift":      {"swift"},
}


def primary_languages(framework: str) -> set[str]:
    """Return the set of languages that count as 'native' for this framework."""
    prefix = framework.split("-")[0].lower()
    return FRAMEWORK_LANGUAGE_MAP.get(prefix, set())


FIELDNAMES = [
    "model",
    "framework",
    "primary_languages",
    "total_risk_score",
    "num_cwes",
    "cwes",
]


def main():
    parser = argparse.ArgumentParser(
        description="Summarise per-CWE CSV into per-model/framework totals."
    )
    parser.add_argument(
        "input_csv",
        nargs="?",
        default="results.csv",
        help="Input CSV produced by export_csv.py (default: results.csv)",
    )
    parser.add_argument(
        "output_csv",
        nargs="?",
        default="summary.csv",
        help="Output summary CSV path (default: summary.csv)",
    )
    args = parser.parse_args()

    input_path = Path(args.input_csv)
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output_csv)

    # Accumulate per (model, framework) → {cwe_id: max_risk_score_across_languages}
    # Using max rather than double-counting the same CWE that appears in both
    # 'javascript' and 'typescript' rows for the same framework.
    AccumType = dict[str, dict[str, float]]  # (model,framework) → {cwe: score}
    accum: dict[tuple[str, str], AccumType] = defaultdict(dict)

    skipped = 0
    kept = 0

    with open(input_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            model = row["model"]
            framework = row["framework"]
            language = row["language"]
            cwe_id = row["cwe_id"]
            risk_score = float(row["risk_score"])

            allowed = primary_languages(framework)
            if not allowed:
                # Unknown framework prefix — keep all languages
                pass
            elif language not in allowed:
                skipped += 1
                continue

            kept += 1
            key = (model, framework)
            existing = accum[key].get(cwe_id, 0.0)
            # A CWE may appear in multiple matching language rows (e.g. JS + TS).
            # Take the maximum score so we don't double-count.
            accum[key][cwe_id] = max(existing, risk_score)

    print(f"Rows kept: {kept}, skipped (non-primary language): {skipped}")

    # Build summary rows, sorted by model then framework
    summary_rows = []
    for (model, framework), cwe_scores in sorted(accum.items()):
        total = round(sum(cwe_scores.values()), 2)
        cwe_list = sorted(cwe_scores.keys())
        langs = primary_languages(framework)
        summary_rows.append({
            "model": model,
            "framework": framework,
            "primary_languages": ";".join(sorted(langs)),
            "total_risk_score": total,
            "num_cwes": len(cwe_list),
            "cwes": ";".join(cwe_list),
        })

    print(f"Writing {len(summary_rows)} summary rows to {output_path} ...")
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(summary_rows)

    print("Done.")


if __name__ == "__main__":
    main()
