# 🧹 AUTOMATIC CLEANUP - NO MORE JUNK FILES!

## ✅ Problem Solved!

Your scanner now **automatically cleans up** all temporary files!

---

## 🗑️ What Gets Cleaned Up

### 1. **Uploaded ZIP Files**
- ✅ Deleted immediately after extraction
- ✅ No ZIPs left in `uploads/` folder

### 2. **Temp Extraction Directories**
- ✅ Deleted after each scan completes
- ✅ Cleaned up on app startup
- ✅ Force-removed if stuck

### 3. **Old Report Files**
- ✅ Auto-deleted after 1 hour
- ✅ Cleaned before each new scan
- ✅ Excel/DOCX files removed

### 4. **Crashed Scan Leftovers**
- ✅ Temp dirs from failed scans removed
- ✅ Checked on startup and before scans

---

## 🔄 Automatic Cleanup Triggers

### **On App Startup**
```
🧹 Cleaning up old files...
✅ Removed old upload: gpt_run1.zip
✅ Removed old upload: gpt_run2.zip
✅ Cleaned up temp directory: scanproj_abc123
✅ Cleaned up old report: cwe_comparison.xlsx
✅ Cleanup complete!
```

### **Before Each Scan**
- Cleans old reports (>1 hour old)
- Removes leftover temp directories
- Prepares system for new scan

### **After ZIP Extraction**
```
[1/10] Extracting gpt_run1.zip...
[1/10] Cleaned up gpt_run1.zip  ← ZIP deleted immediately
```

### **After Each Scan**
- Temp extraction directory removed
- Only results kept in memory
- No files left on disk

---

## 🧹 Manual Cleanup Button

Added a button on the main page:

```
🧹 Clean Up Temporary Files
```

**Clicking this removes:**
- All uploaded ZIPs
- All temp extraction directories
- All generated reports (Excel/DOCX)
- Any leftover files

**Perfect for when you want a fresh start!**

---

## 📁 What Gets Kept vs Deleted

### **Kept (Important):**
✅ Your application code (`app.py`, `scanners.py`, etc.)
✅ Templates and CSS
✅ Scan results in memory (until server restart)

### **Deleted (Temporary):**
❌ Uploaded ZIP files (after extraction)
❌ Temp extraction directories (`/tmp/scanproj_*`)
❌ Old report files (>1 hour old)
❌ Downloaded Excel/DOCX (you already saved them)

---

## 💾 Storage Usage

### **Before (Without Cleanup):**
```
uploads/
├── gpt_run1.zip         (500 MB)
├── gpt_run2.zip         (500 MB)
├── gpt_run3.zip         (500 MB)
└── ... (keeps growing!)

/tmp/
├── scanproj_abc123/     (500 MB extracted)
├── scanproj_def456/     (500 MB extracted)
└── ... (never cleaned!)

reports/
├── report_1.xlsx
├── report_2.xlsx
└── ... (accumulates!)

TOTAL: GBs of wasted space! ❌
```

### **After (With Cleanup):**
```
uploads/
└── (empty - ZIPs deleted after extraction)

/tmp/
└── (empty - dirs deleted after scan)

reports/
└── (only recent files <1 hour old)

TOTAL: Only active scans use space ✅
```

---

## 🔍 How It Works

### **1. ZIP Cleanup**
```python
# Immediately after extraction
shutil.unpack_archive(zip_path, temp_dir)
zip_path.unlink()  # Delete ZIP
```

### **2. Temp Directory Cleanup**
```python
# After scanning
finally:
    shutil.rmtree(temp_dir)  # Remove extracted files
    if still_exists:
        os.system(f"rm -rf {temp_dir}")  # Force remove
```

### **3. Report Cleanup**
```python
# Before each scan
for report in reports/:
    if file_age > 1_hour:
        report.unlink()
```

### **4. Startup Cleanup**
```python
# When app starts
cleanup_old_reports()
cleanup_temp_directories()
cleanup_uploads()
```

---

## 🎯 Benefits for Your Research

### **Before:**
```
❌ Upload 10 ZIPs = 5 GB
❌ Extract = 5 GB more (10 GB total)
❌ Generate reports = more files
❌ Run 10 experiments = 100 GB!
❌ Mac storage full ❌
```

### **After:**
```
✅ Upload 10 ZIPs = 5 GB temporarily
✅ ZIPs deleted after extraction
✅ Extracts deleted after scan
✅ Only reports kept (small Excel files)
✅ Old reports auto-deleted after 1 hour
✅ Run 100 experiments = same 5 GB space ✅
```

**Your Mac stays clean!** 🎉

---

## 🛠️ Manual Cleanup Commands

If you want to clean manually:

```bash
# Clean everything
curl http://localhost:8080/cleanup_all

# Or click the button in UI
```

Or use system commands:

```bash
# Remove all temp scan directories
rm -rf /tmp/scanproj_*

# Clean uploads folder
rm -rf uploads/*.zip

# Clean reports folder
rm -rf reports/*
```

---

## 📊 What You See in Logs

### **Startup:**
```
====================================================
Multi-Run Security Scanner Starting...
====================================================

🧹 Cleaning up old files...
Removed old upload: gpt_run1.zip
Removed old upload: gpt_run2.zip
Cleaned up temp directory: scanproj_abc123
Cleaned up old report: cwe_comparison.xlsx

✅ Cleanup complete!

🚀 Starting server on http://localhost:8080
====================================================
```

### **During Scan:**
```
[1/10] Extracting gpt_run1.zip...
[1/10] Cleaned up gpt_run1.zip
[1/10] Scanning with 5 tools...
[1/10] Running Semgrep...
...
[1/10] ✅ Completed gpt_run1.zip
Cleaned up temp directory: scanproj_xyz789
```

### **Manual Cleanup:**
```
✅ All temporary files cleaned up!
```

---

## ⚠️ Important Notes

### **Downloads Are Safe**
When you download an Excel or DOCX report, it goes to your Downloads folder. **Those are safe!** The cleanup only removes the temporary copies in the `reports/` folder that were generated for download.

### **Scan Results in Memory**
Results are stored in memory (RAM) until server restart. They're not on disk, so they don't take up storage. If you restart the server, you'll lose the in-memory results, but that's intentional to keep things clean.

### **Restart Cleans Everything**
Every time you start the app:
1. Old uploads removed
2. Temp directories removed  
3. Old reports removed
4. Fresh start!

---

## 🎉 Summary

### **Automatic Cleanup:**
✅ ZIPs deleted after extraction  
✅ Temp dirs deleted after scan  
✅ Old reports deleted after 1 hour  
✅ Crashed scan cleanup on startup  
✅ Force removal if stuck  

### **Manual Cleanup:**
✅ Button in UI: "🧹 Clean Up Temporary Files"  
✅ Endpoint: `/cleanup_all`  
✅ Removes everything temporary  

### **Your Mac:**
✅ No more junk files  
✅ No storage buildup  
✅ Clean and organized  
✅ Run unlimited experiments  

---

**Your scanner is now self-cleaning! No more storage problems!** 🧹✨
