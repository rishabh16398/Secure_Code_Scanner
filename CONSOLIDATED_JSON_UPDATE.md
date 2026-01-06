# 📦 Updated Consolidated JSON Format

## What Changed

### ✅ Cleaner Structure
Removed unnecessary summaries, kept only what you need:

**Before:**
```json
{
  "runs": [
    {
      "run_number": 1,
      "project_name": "gpt_run1.zip",
      "results": { ... },
      "sast_summary": [ ... ],  // ❌ Removed
      "dep_summary": [ ... ]    // ❌ Removed
    }
  ]
}
```

**After:**
```json
{
  "runs": [
    {
      "run_number": 1,
      "project": "python-flask-gemini-pro-2.5",  // ✅ Clean name
      "results": {  // ✅ Only raw tool outputs
        "sast": {
          "semgrep": [ ... ],
          "bearer": [ ... ],
          "bandit": [ ... ]
        },
        "dep": {
          "trivy": [ ... ],
          "osv-scanner": [ ... ]
        }
      }
    }
  ]
}
```

---

## New Structure

### Top Level:
```json
{
  "total_runs": 10,
  "generated_at": "2026-01-06 10:50:00",
  "runs": [ ... ]
}
```

### Each Run:
```json
{
  "run_number": 1,
  "project": "python-flask-gemini-pro-2.5",  // Clean project identifier
  "scan_timestamp": "2026-01-06 09:15:23",
  "results": {
    "sast": {
      "semgrep": [
        {
          "rule_id": "...",
          "cwe": "CWE-79",
          "severity": "HIGH",
          "file": "app/views/user.py",
          "line": "45",
          "message": "..."
        }
      ],
      "bearer": [ ... ],
      "bandit": [ ... ]
    },
    "dep": {
      "trivy": [ ... ],
      "osv-scanner": [ ... ]
    }
  }
}
```

---

## Benefits

### ✅ Cleaner Data
- No duplicate data (summaries are derived from results)
- Only raw tool outputs
- Smaller file size

### ✅ Clear Project Names
Instead of:
```json
"project_name": "gpt_run1.zip"
```

You get:
```json
"project": "python-flask-gemini-pro-2.5"
```

Perfect for identifying which AI model generated the code!

### ✅ Easy to Process
All CWE information is in the raw tool results:

```python
import json

with open('consolidated_all_runs_10_runs.json') as f:
    data = json.load(f)

# Process each run
for run in data['runs']:
    project = run['project']  # e.g., "python-flask-gemini-pro-2.5"
    
    # Get all Semgrep findings
    semgrep_findings = run['results']['sast']['semgrep']
    
    # Count CWEs
    for finding in semgrep_findings:
        cwe = finding['cwe']
        file = finding['file']
        print(f"{project}: {cwe} in {file}")
```

---

## Use Cases

### 1. AI Model Comparison
```python
# Compare vulnerability counts by AI model
model_stats = {}

for run in data['runs']:
    model = run['project']  # e.g., "gemini-pro-2.5"
    
    if model not in model_stats:
        model_stats[model] = {'total_vulns': 0, 'cwes': set()}
    
    # Count all SAST findings
    for tool in run['results']['sast'].values():
        for finding in tool:
            model_stats[model]['total_vulns'] += 1
            model_stats[model]['cwes'].add(finding['cwe'])

# Results: Which model generates safer code?
for model, stats in model_stats.items():
    print(f"{model}:")
    print(f"  Total vulnerabilities: {stats['total_vulns']}")
    print(f"  Unique CWEs: {len(stats['cwes'])}")
```

### 2. Tool Analysis
```python
# Which tool finds the most issues?
tool_counts = {
    'semgrep': 0,
    'bearer': 0,
    'bandit': 0,
    'trivy': 0,
    'osv-scanner': 0
}

for run in data['runs']:
    for tool_name in ['semgrep', 'bearer', 'bandit']:
        findings = run['results']['sast'].get(tool_name, [])
        tool_counts[tool_name] += len(findings)
    
    for tool_name in ['trivy', 'osv-scanner']:
        findings = run['results']['dep'].get(tool_name, [])
        tool_counts[tool_name] += len(findings)

print("Findings by tool:")
for tool, count in sorted(tool_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"  {tool}: {count}")
```

### 3. File-Level Analysis
```python
# Which files are most vulnerable across all models?
file_vuln_counts = {}

for run in data['runs']:
    for tool_findings in run['results']['sast'].values():
        for finding in tool_findings:
            file = finding.get('file', 'unknown')
            if file not in file_vuln_counts:
                file_vuln_counts[file] = 0
            file_vuln_counts[file] += 1

# Top 10 most vulnerable files
top_files = sorted(file_vuln_counts.items(), key=lambda x: x[1], reverse=True)[:10]
for file, count in top_files:
    print(f"{file}: {count} vulnerabilities")
```

---

## Example Naming Conventions

### Good Project Names:
```
"python-flask-gemini-pro-2.5"
"python-flask-gpt-4o-mini"
"python-flask-claude-sonnet-4"
"javascript-express-gemini-pro-2.5"
"java-spring-gpt-4o"
```

### Format:
```
{language}-{framework}-{ai-model}
```

This makes it easy to:
- Identify the AI model
- Group by language
- Group by framework
- Compare across models

---

## File Size Comparison

### Before (with summaries):
```
consolidated_all_runs_10_runs.json: ~5 MB
```

### After (without summaries):
```
consolidated_all_runs_10_runs.json: ~3 MB
```

**40% smaller!** Just the raw data you need.

---

## Combined with CWE Analysis JSON

Use both JSONs together:

### Consolidated JSON:
- Raw tool outputs per run
- All findings with file/line details
- Tool-specific information

### CWE Analysis JSON:
- Aggregated CWE statistics
- File counts per run
- Total unique files
- Tool descriptions

### Perfect Workflow:
```python
# Load both
with open('consolidated_all_runs_10_runs.json') as f:
    raw_data = json.load(f)

with open('cwe_analysis_10_runs.json') as f:
    cwe_data = json.load(f)

# Use consolidated for: detailed analysis, specific findings
# Use CWE analysis for: statistics, prevalence, research paper
```

---

## Migration from Old Format

If you have old code using `sast_summary`:

**Old:**
```python
for run in data['runs']:
    sast_summary = run['sast_summary']
    for item in sast_summary:
        cwe = item['cwe']
        # ...
```

**New:**
```python
for run in data['runs']:
    # Process raw tool results
    for tool_findings in run['results']['sast'].values():
        for finding in tool_findings:
            cwe = finding['cwe']
            # ...
```

---

## Summary

### What You Get:
✅ Clean project names (no `.zip`, no "run")  
✅ Only raw tool outputs (no summaries)  
✅ Smaller file size  
✅ Perfect for AI model identification  
✅ Easy to process programmatically  

### What You Remove:
❌ `sast_summary` (redundant)  
❌ `dep_summary` (redundant)  
❌ `.zip` extension in names  
❌ "run" prefix in names  

**Result: Clean, focused data for your research!** 🎓
