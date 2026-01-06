# Multi-Run Security Scanner with Progress Tracking

## 🎉 Complete Package - Ready to Use!

All necessary files included with TWO new features:
1. ✅ **Real-time progress tracking** - See live updates while scanning
2. ✅ **Detailed file count Excel** - See how many files each CWE was found in (NEW!)

## 📊 Two Excel Export Options

### Option 1: Checkmark Excel (Original)
- Shows ✓ if CWE found in run
- 16 columns including tool details
- Perfect for yes/no analysis

### Option 2: Detailed File Counts (NEW!)
- Shows **NUMBER OF FILES** where CWE was found
- Example: CWE-79 in Run 1 found in **20 files** → shows "20"
- Includes Total Files and Average per Run
- Perfect for severity analysis

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt
pip install semgrep bandit
npm install -g @bearer/bearer
brew install trivy osv-scanner

# 2. Run
python app.py

# 3. Open browser
http://localhost:8080
```

## 📁 Files Included

```
scanner/
├── app.py                  # Flask app with SSE + file counts
├── scanners.py             # Scanner orchestration
├── requirements.txt        # Python dependencies
├── templates/
│   ├── base.html          # Base template
│   ├── index.html         # Upload page
│   ├── progress.html      # Real-time progress (NEW)
│   └── results.html       # Results with 2 download buttons
└── static/
    └── style.css          # Dark theme styling
```

## 🎯 Usage

1. **Upload** multiple ZIP files
2. **Watch** real-time progress with loading bar
3. **View** results for each run
4. **Download** TWO types of Excel:
   - **Checkmarks** - Quick yes/no overview
   - **File Counts** - Detailed severity analysis

## 📊 Excel Examples

### Checkmark Excel
| CWE ID | Run 1 | Run 2 | Run 3 |
|--------|-------|-------|-------|
| CWE-79 | ✓     | ✓     |       |
| CWE-89 | ✓     | ✓     | ✓     |

### File Count Excel (NEW!)
| CWE ID | Run 1 | Run 2 | Run 3 | Total Files | Avg/Run |
|--------|-------|-------|-------|-------------|---------|
| CWE-79 | 20    | 15    | 0     | 35          | 17.5    |
| CWE-89 | 5     | 8     | 12    | 25          | 8.3     |

**Now you can see HOW MANY files have each vulnerability!**

## ✨ Features

✅ Multi-file upload (10+ ZIPs)  
✅ Real-time progress bar  
✅ Live scan log  
✅ 5 security scanners (Semgrep, Bearer, Bandit, Trivy, OSV)  
✅ Two Excel formats (checkmarks + file counts)  
✅ Run navigation  
✅ DOCX reports  
✅ Dark theme UI  

## 🔧 Troubleshooting

```bash
# Check scanner installation
which semgrep bearer bandit trivy osv-scanner

# Install missing scanners
pip install semgrep bandit
npm install -g @bearer/bearer
brew install trivy osv-scanner
```

## 📝 Notes

- Each scan takes 2-5 minutes per project
- Progress updates in real-time
- Results stored in memory (lost on restart)
- Download Excel before closing server

---

**Perfect for comparing LLM-generated code security!** 🎓
