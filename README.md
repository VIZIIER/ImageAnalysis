# 🛡️ Humble yet Effective Image Security Analyzer

A Python GUI application for analyzing image files for potential security threats, including **zero-click vulnerabilities**.  
It detects malicious payloads hidden inside images, steganography attempts, metadata leaks, file integrity issues, and more.

---

## ✨ Features
- 🔐 **Cryptographic Hashes**: MD5, SHA1, SHA256
- 📋 **File Structure Analysis**: Detect mismatched headers/extensions
- 📊 **Metadata Extraction**: EXIF, PNG chunks, general metadata
- 🔍 **Steganography Detection**: Entropy check, LSB indicators, embedded files, trailing data
- 🛡️ **Malicious Content Scan**: Regex patterns for scripts, PHP, SQLi, URLs, IPs, emails, etc.
- 🔧 **File Integrity Check**: Detect truncation, excessive null bytes
- 📊 **Risk Scoring**: Calculates Low / Medium / High risk with warnings
- 📄 **Export Options**: Save results as text report or JSON

---

## 📸 Screenshot
<img width="727" height="1118" alt="image" src="https://github.com/user-attachments/assets/0b03ff13-8e15-46cd-993c-c8e1055a03a9" />


---

## 🚀 Installation
1. Clone the repository:
   ```
   git clone https://github.com/VIZIIER/ImageAnalysis.git
   cd ImageAnalysis
   ```
2. Run with Python 3 (no external dependencies beyond standard library):
   ```
   python3 analyzer.py
   ```
---

## 🖥️ Usage

1. Lunch the app:
```
python3 main.py
```
2. Select an image file (.jpg, .png, .gif, .bmp, .tiff, .webp, .ico).
3. Choose which analysis components to run.
4. Click Start Comprehensive Analysis.
5. View summary, detailed results, and JSON export tabs.
6. Save reports or copy JSON to clipboard.

---

## ⚠️ Disclaimer
This tool is designed for educational and security research purposes.
It does not guarantee detection of all threats. Always exercise caution when handling untrusted files.
