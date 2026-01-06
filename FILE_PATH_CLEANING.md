# 🧹 FILE PATH CLEANING - No More Temp Prefixes!

## The Problem

Scanner tools return **full absolute paths** including temp directories:

```json
{
  "file": "/var/folders/kp/xz3tcgld3kv7jjx_8hhhqgn80000gn/T/scanproj_fomlx17q/python-flask-gemini-pro-2.5-run10/tests/test_approval_service.py"
}
```

**Issues:**
- ❌ Unreadable in reports
- ❌ Different paths for each run (random temp dirs)
- ❌ Can't compare files across runs
- ❌ Hard to process programmatically
- ❌ Exposes local machine paths

---

## The Solution

**Automatic path cleaning** removes temp directory prefixes:

```json
{
  "file": "python-flask-gemini-pro-2.5-run10/tests/test_approval_service.py"
}
```

**Benefits:**
- ✅ Clean, readable paths
- ✅ Consistent across runs
- ✅ Easy to compare
- ✅ Ready for analysis
- ✅ No machine-specific info

---

## How It Works

### Function: `clean_file_paths()`

Called automatically after each scan completes:

```python
# After scanning
results = run_all_scanners(tmp_dir, scanner_progress)

# Clean all file paths
results = clean_file_paths(results, tmp_dir, project_name)

# Now all paths are clean!
```

### What It Cleans:

**SAST Results:**
```python
for scanner_name, findings in results["sast"].items():
    for finding in findings:
        finding["file"] = clean_path(finding["file"])
```

**Dependency Results:**
```python
for scanner_name, findings in results["dep"].items():
    for finding in findings:
        finding["file"] = clean_path(finding["file"])
        finding["path"] = clean_path(finding["path"])
```

---

## Examples

### Before (Raw Scanner Output):

#### Semgrep:
```json
{
  "rule_id": "python.flask.security.xss",
  "cwe": "CWE-79",
  "file": "/var/folders/kp/xz3tcgld3kv7jjx_8hhhqgn80000gn/T/scanproj_abc123/python-flask-gemini/app/views/user.py",
  "line": "45"
}
```

#### Bearer:
```json
{
  "rule_id": "bearer:python_lang_weak_encryption",
  "cwe": "CWE-327",
  "file": "/var/folders/kp/xz3tcgld3kv7jjx_8hhhqgn80000gn/T/scanproj_abc123/python-flask-gemini/app/utils/crypto.py",
  "line": "25"
}
```

#### Bandit:
```json
{
  "rule_id": "B105",
  "cwe": "CWE-798",
  "file": "/var/folders/kp/xz3tcgld3kv7jjx_8hhhqgn80000gn/T/scanproj_abc123/python-flask-gemini/config/settings.py",
  "line": "12"
}
```

### After (Cleaned):

#### Semgrep:
```json
{
  "rule_id": "python.flask.security.xss",
  "cwe": "CWE-79",
  "file": "python-flask-gemini/app/views/user.py",
  "line": "45"
}
```

#### Bearer:
```json
{
  "rule_id": "bearer:python_lang_weak_encryption",
  "cwe": "CWE-327",
  "file": "python-flask-gemini/app/utils/crypto.py",
  "line": "25"
}
```

#### Bandit:
```json
{
  "rule_id": "B105",
  "cwe": "CWE-798",
  "file": "python-flask-gemini/config/settings.py",
  "line": "12"
}
```

---

## Impact on Outputs

### 1. Consolidated JSON ✅
```json
{
  "project": "python-flask-gemini-pro-2.5",
  "runs": [
    {
      "run_number": 1,
      "results": {
        "sast": {
          "semgrep": [
            {
              "file": "python-flask-gemini-pro-2.5-run1/app/views/user.py"
            }
          ]
        }
      }
    }
  ]
}
```

### 2. CWE Analysis JSON ✅
```json
{
  "cwes": {
    "CWE-79": {
      "examples": [
        {
          "run": 1,
          "file": "python-flask-gemini-pro-2.5-run1/app/views/user.py",
          "line": "45"
        }
      ]
    }
  }
}
```

### 3. Excel Files ✅
In the "Example files" column:
```
python-flask-gemini/app/views/user.py:45 (Semgrep)
python-flask-gemini/app/utils/crypto.py:25 (Bearer)
```

Instead of:
```
/var/folders/.../scanproj_abc123/python-flask-gemini/app/views/user.py:45
```

### 4. DOCX Reports ✅
Clean paths in all report tables.

---

## Benefits for Research

### 1. **File Comparison Across Runs**

**Before (Can't Compare):**
```python
# Run 1
"/var/.../scanproj_abc123/python-flask-gemini/app.py"
# Run 2
"/var/.../scanproj_xyz789/python-flask-gemini/app.py"
# Different strings! Can't match!
```

**After (Can Compare):**
```python
# Run 1
"python-flask-gemini-run1/app.py"
# Run 2
"python-flask-gemini-run2/app.py"
# Can easily extract and compare!
```

### 2. **Programmatic Analysis**

```python
import json

with open('consolidated_all_runs_10_runs.json') as f:
    data = json.load(f)

# Count which files appear most often
file_counts = {}

for run in data['runs']:
    for finding in run['results']['sast']['semgrep']:
        file = finding['file']
        # Extract just the filename without run number
        filename = file.split('/')[-1]  # Easy!
        file_counts[filename] = file_counts.get(filename, 0) + 1

# Most vulnerable files
for file, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"{file}: {count} vulnerabilities")
```

### 3. **File Structure Analysis**

```python
# Analyze which directories have most vulnerabilities
dir_counts = {}

for run in data['runs']:
    for finding in run['results']['sast']['semgrep']:
        file = finding['file']
        directory = '/'.join(file.split('/')[:-1])  # Get directory
        dir_counts[directory] = dir_counts.get(directory, 0) + 1

# Most vulnerable directories
for dir, count in sorted(dir_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"{dir}: {count} vulnerabilities")
```

---

## Edge Cases Handled

### 1. **No File Path**
```python
if not file_path:
    return file_path  # Return as-is
```

### 2. **Already Clean Path**
```python
# If path doesn't contain temp directory, return as-is
if tmp_dir_str not in path_str:
    return path_str
```

### 3. **Relative Paths**
```python
# Some scanners return relative paths
# These are already clean, just returned as-is
```

### 4. **Path in Dependencies**
```python
# Trivy uses "path" for lockfiles
if "path" in finding:
    finding["path"] = clean_path(finding["path"])
```

---

## Verification

### Check Before/After:

**1. Run a scan**
**2. Download consolidated JSON**
**3. Search for paths:**

```bash
# Should NOT find any temp paths
grep -i "scanproj_" consolidated_all_runs_10_runs.json
# Expected: No results

grep -i "/var/folders" consolidated_all_runs_10_runs.json
# Expected: No results

grep -i "/tmp/" consolidated_all_runs_10_runs.json
# Expected: No results
```

**4. Should only see clean paths:**

```bash
# Should find clean paths
grep -o '"file": "[^"]*"' consolidated_all_runs_10_runs.json | head -5
```

Expected output:
```
"file": "python-flask-gemini-run1/app/views/user.py"
"file": "python-flask-gemini-run1/app/utils/crypto.py"
"file": "python-flask-gemini-run1/config/settings.py"
```

---

## Summary

### ✅ What's Cleaned:
- All SAST results (Semgrep, Bearer, Bandit)
- All dependency results (Trivy, OSV-Scanner)
- Both "file" and "path" fields
- Applied to ALL outputs (JSON, Excel, DOCX)

### ✅ When It's Applied:
- Automatically after each scan
- Before building summaries
- Before storing results
- Zero manual work needed

### ✅ Result:
- Clean, readable file paths
- Consistent across runs
- Easy to analyze
- No machine-specific info
- Ready for research papers

**Engineer-approved! ✨**
