# 🚀 QUICK REFERENCE GUIDE - New JSON Export Features

## Two New Download Buttons Added

### Location
Results page → Action buttons (top right)

### Available When
Multiple runs have been scanned (2+ runs)

---

## Button 1: 📦 Download All Runs JSON

**File Name:** `consolidated_all_runs_{N}_runs.json`

**Contains:**
- All scan results from all runs in one file
- Complete raw data from all tools
- SAST summaries per run
- Dependency summaries per run
- Timestamps for each run

**Use When:**
- Need complete raw data
- Building custom analysis
- Archiving/backup
- Data migration

**Size:** ~1-5 MB for typical scans

---

## Button 2: 🔍 Download CWE Analysis JSON

**File Name:** `cwe_analysis_{N}_runs.json`

**Contains:**
- CWE-centric aggregated analysis
- Which runs found each CWE
- Which tools detected each CWE
- File counts per run
- Total unique files
- Tool descriptions
- Severity analysis
- Statistical calculations
- Example instances

**Use When:**
- Research analysis
- Creating charts/visualizations
- Comparing CWE prevalence
- Analyzing tool effectiveness
- Writing research papers

**Size:** ~500 KB - 2 MB for typical scans

---

## Key Data Points in CWE Analysis

### For Each CWE You Get:

1. **Basic Info**
   - CWE ID (e.g., CWE-79)
   - Full CWE name/description

2. **Run Coverage**
   - List of runs that found this CWE
   - Total count of runs with this CWE
   - Example: `"found_in_runs": [1, 2, 5, 7, 8]`

3. **Tool Detection**
   - Which tools detected this CWE
   - Sorted list
   - Example: `"tools_detected_by": ["Bearer", "Semgrep"]`

4. **File Counts** ⭐ NEW!
   - Unique files per run
   - Example: `"run_1": 20, "run_2": 15`
   - Total unique files across all runs
   - Example: `"total_unique_files": 45`

5. **Statistics** ⭐ NEW!
   - Average files per run
   - Max/min files in single run
   - Total instances across runs

6. **Descriptions** ⭐ NEW!
   - What tools say about this CWE
   - Up to 5 unique descriptions
   - Example: `"User input flows into HTML without escaping"`

7. **Examples**
   - Actual vulnerability instances
   - File paths, line numbers
   - Which scanner found it
   - Specific messages

8. **Severity**
   - All severity levels observed
   - Example: `["CRITICAL", "HIGH"]`

---

## Example Research Queries

### Most Common CWEs:
```python
import json

with open('cwe_analysis_10_runs.json') as f:
    data = json.load(f)

# Sort by prevalence
for cwe_id, info in data['cwes'].items():
    runs = info['total_runs_found']
    total = data['total_runs']
    print(f"{cwe_id}: {runs}/{total} runs ({runs/total*100:.1f}%)")
```

### Average File Impact:
```python
for cwe_id, info in data['cwes'].items():
    avg = info['statistics']['average_files_per_run']
    print(f"{cwe_id}: avg {avg} files per run")
```

### Tool Effectiveness:
```python
from collections import Counter

tool_counts = Counter()
for cwe_id, info in data['cwes'].items():
    for tool in info['tools_detected_by']:
        tool_counts[tool] += 1

print("CWEs detected by each tool:")
for tool, count in tool_counts.most_common():
    print(f"{tool}: {count} unique CWEs")
```

---

## Data Sorting

**CWE Analysis is automatically sorted by:**
1. Most common (by total_runs_found) 
2. Most files affected (by total_unique_files)

This puts the most significant vulnerabilities first!

---

## File Locations

Downloaded files go to your browser's Downloads folder:
- `consolidated_all_runs_10_runs.json`
- `cwe_analysis_10_runs.json`

Temporary copies in project folder automatically deleted after 1 hour.

---

## Usage Workflow

1. ✅ Scan multiple projects (10+ recommended)
2. ✅ View results in UI
3. ✅ Click download buttons
4. ✅ Open in Python/R/Excel
5. ✅ Analyze for research paper

---

## Python Libraries That Work Great

```python
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load data
with open('cwe_analysis_10_runs.json') as f:
    data = json.load(f)

# Convert to DataFrame
cwe_list = []
for cwe_id, info in data['cwes'].items():
    cwe_list.append({
        'CWE': cwe_id,
        'Runs': info['total_runs_found'],
        'AvgFiles': info['statistics']['average_files_per_run'],
        'Tools': len(info['tools_detected_by'])
    })

df = pd.DataFrame(cwe_list)

# Create visualization
df.plot.bar(x='CWE', y='Runs', figsize=(12,6))
plt.title('CWE Prevalence Across Runs')
plt.tight_layout()
plt.savefig('cwe_prevalence.png', dpi=300)
```

---

## Quick Tips

✅ **Download both JSONs** - consolidated for raw data, analysis for research  
✅ **Use version control** - Keep different experimental runs separate  
✅ **Automate analysis** - Write Python scripts to process JSON  
✅ **Create visualizations** - matplotlib, seaborn, plotly work great  
✅ **Cross-reference** - Use run numbers to match data across files  

---

## Need More Data?

Both JSON files have everything you need, but if you want:
- More example instances → Edit limit in app.py (currently 3 per run)
- More descriptions → Edit limit in app.py (currently 5 unique)
- Different sorting → Process JSON in Python with custom sort

---

## Questions?

Check the full documentation in `UPDATED_FEATURES.md` for:
- Detailed structure explanations
- More Python examples
- Research use cases
- Statistical analysis templates
- Visualization examples

---

**Happy analyzing! 🎓📊**
