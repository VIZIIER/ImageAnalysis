"""
A Python-based GUI tool to analyze image files for security risks, including zero-click vulnerabilities,
hidden malicious code, metadata leakage, steganography, and integrity issues.
The tool calculates file hashes, inspects file headers, checks for embedded files, scans for suspicious patterns,
and provides a risk score with recommendations. Reports can be exported as text or JSON.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import hashlib
import json
import os
import re
import struct
import threading
import zlib
from datetime import datetime
import binascii


class ComprehensiveImageAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Comprehensive Image Security Analyzer")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        self.selected_file = tk.StringVar()
        self.analysis_results = {}
        self.is_analyzing = False

        #analysis options
        self.show_hashes = tk.BooleanVar(value=True)
        self.show_structure = tk.BooleanVar(value=True)
        self.show_metadata = tk.BooleanVar(value=True)
        self.show_steganography = tk.BooleanVar(value=True)
        self.show_malicious = tk.BooleanVar(value=True)
        self.show_integrity = tk.BooleanVar(value=True)

        #suspicious patterns
        self.suspicious_patterns = {
            'script_tags': rb'<script[^>]*>.*?</script>',
            'javascript': rb'javascript:',
            'eval_calls': rb'eval\s*\(',
            'document_refs': rb'document\.[a-zA-Z]+',
            'iframe_tags': rb'<iframe[^>]*>',
            'php_tags': rb'<\?php',
            'asp_tags': rb'<%.*?%>',
            'sql_injection': rb'(union|select|insert|update|delete|drop)\s+',
            'shell_commands': rb'(system|exec|shell_exec|passthru|popen)\s*\(',
            'base64_long': rb'[A-Za-z0-9+/]{40,}={0,2}',
            'urls': rb'https?://[^\s<>"\']+',
            'ip_addresses': rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'email_addresses': rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        }

        self.setup_ui()

    def setup_ui(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.main_frame = ttk.Frame(notebook)
        notebook.add(self.main_frame, text="🔍 Security Analysis")

        self.results_frame = ttk.Frame(notebook)
        notebook.add(self.results_frame, text="📊 Detailed Results")

        self.json_frame = ttk.Frame(notebook)
        notebook.add(self.json_frame, text="📄 JSON Export")

        self.setup_main_tab()
        self.setup_results_tab()
        self.setup_json_tab()

    def setup_main_tab(self):
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(2, weight=1)

        title_label = ttk.Label(self.main_frame, text="🛡️ Comprehensive Image Security Analyzer",
                                font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, pady=(10, 20))

        top_frame = ttk.Frame(self.main_frame)
        top_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=10, pady=(0, 10))
        top_frame.columnconfigure(0, weight=1)

        file_frame = ttk.LabelFrame(top_frame, text="File Selection", padding="10")
        file_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        file_frame.columnconfigure(1, weight=1)

        ttk.Label(file_frame, text="Selected File:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))

        file_entry = ttk.Entry(file_frame, textvariable=self.selected_file, state="readonly")
        file_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))

        browse_btn = ttk.Button(file_frame, text="Browse...", command=self.browse_file)
        browse_btn.grid(row=0, column=2)

        options_frame = ttk.LabelFrame(top_frame, text="Analysis Components", padding="10")
        options_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        left_frame = ttk.Frame(options_frame)
        left_frame.grid(row=0, column=0, sticky=(tk.W, tk.N), padx=(0, 20))

        right_frame = ttk.Frame(options_frame)
        right_frame.grid(row=0, column=1, sticky=(tk.W, tk.N))

        ttk.Checkbutton(left_frame, text="🔐 File Hashes (MD5, SHA1, SHA256)",
                        variable=self.show_hashes).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(left_frame, text="📋 File Structure Analysis",
                        variable=self.show_structure).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(left_frame, text="📊 Metadata Extraction",
                        variable=self.show_metadata).pack(anchor=tk.W, pady=2)

        ttk.Checkbutton(right_frame, text="🔍 Steganography Detection",
                        variable=self.show_steganography).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(right_frame, text="🛡️ Malicious Content Scan",
                        variable=self.show_malicious).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(right_frame, text="🔧 File Integrity Check",
                        variable=self.show_integrity).pack(anchor=tk.W, pady=2)

        buttons_frame = ttk.Frame(top_frame)
        buttons_frame.grid(row=2, column=0, pady=(0, 10))

        self.analyze_btn = ttk.Button(buttons_frame, text="🔍 Start Comprehensive Analysis",
                                      command=self.start_analysis, style="Accent.TButton")
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.save_report_btn = ttk.Button(buttons_frame, text="📄 Save Report",
                                          command=self.save_report, state="disabled")
        self.save_report_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.save_json_btn = ttk.Button(buttons_frame, text="💾 Save JSON",
                                        command=self.save_json, state="disabled")
        self.save_json_btn.pack(side=tk.LEFT)

        progress_frame = ttk.Frame(top_frame)
        progress_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        progress_frame.columnconfigure(0, weight=1)

        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))

        self.status_label = ttk.Label(progress_frame, text="Ready to analyze image files")
        self.status_label.grid(row=1, column=0, sticky=tk.W)

        summary_frame = ttk.LabelFrame(self.main_frame, text="Analysis Summary", padding="10")
        summary_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=(0, 10))
        summary_frame.columnconfigure(0, weight=1)
        summary_frame.rowconfigure(0, weight=1)

        self.summary_text = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD,
                                                      font=("Consolas", 10), state="disabled")
        self.summary_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.configure_text_tags(self.summary_text)

    def setup_results_tab(self):
        self.results_frame.columnconfigure(0, weight=1)
        self.results_frame.rowconfigure(0, weight=1)

        results_label = ttk.Label(self.results_frame, text="📊 Detailed Analysis Results",
                                  font=("Arial", 14, "bold"))
        results_label.grid(row=0, column=0, pady=(10, 10))

        self.detailed_text = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD,
                                                       font=("Consolas", 9), state="disabled")
        self.detailed_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=(0, 10))

        self.configure_text_tags(self.detailed_text)

    def setup_json_tab(self):
        self.json_frame.columnconfigure(0, weight=1)
        self.json_frame.rowconfigure(1, weight=1)

        json_header = ttk.Frame(self.json_frame)
        json_header.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=10, pady=10)

        ttk.Label(json_header, text="📄 JSON Export Data",
                  font=("Arial", 14, "bold")).pack(side=tk.LEFT)

        self.copy_json_btn = ttk.Button(json_header, text="📋 Copy to Clipboard",
                                        command=self.copy_json, state="disabled")
        self.copy_json_btn.pack(side=tk.RIGHT)

        self.json_text = scrolledtext.ScrolledText(self.json_frame, wrap=tk.WORD,
                                                   font=("Consolas", 9), state="disabled")
        self.json_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=(0, 10))

    def configure_text_tags(self, text_widget):
        text_widget.tag_configure("header", foreground="blue", font=("Consolas", 11, "bold"))
        text_widget.tag_configure("subheader", foreground="darkblue", font=("Consolas", 10, "bold"))
        text_widget.tag_configure("warning", foreground="orange", font=("Consolas", 9, "bold"))
        text_widget.tag_configure("error", foreground="red", font=("Consolas", 9, "bold"))
        text_widget.tag_configure("success", foreground="green", font=("Consolas", 9, "bold"))
        text_widget.tag_configure("metadata", foreground="purple")
        text_widget.tag_configure("suspicious", foreground="red", background="lightyellow")
        text_widget.tag_configure("normal", foreground="black")

    def browse_file(self):
        filetypes = [
            ("All Image Files", "*.jpg;*.jpeg;*.png;*.gif;*.bmp;*.tiff;*.tif;*.webp;*.ico"),
            ("JPEG Files", "*.jpg;*.jpeg"),
            ("PNG Files", "*.png"),
            ("GIF Files", "*.gif"),
            ("BMP Files", "*.bmp"),
            ("TIFF Files", "*.tiff;*.tif"),
            ("WebP Files", "*.webp"),
            ("Icon Files", "*.ico"),
            ("All Files", "*.*")
        ]

        filename = filedialog.askopenfilename(
            title="Select Image File for Security Analysis",
            filetypes=filetypes,
            initialdir=os.path.expanduser("~")
        )

        if filename:
            self.selected_file.set(filename)
            self.clear_results()

    def start_analysis(self):
        if not self.selected_file.get():
            messagebox.showwarning("No File Selected", "Please select an image file to analyze.")
            return

        if not os.path.isfile(self.selected_file.get()):
            messagebox.showerror("File Not Found", f"The file '{self.selected_file.get()}' does not exist.")
            return

        if self.is_analyzing:
            return

        self.is_analyzing = True
        self.analyze_btn.config(state="disabled")
        self.progress.start(10)
        self.status_label.config(text="Performing comprehensive security analysis...")

        analysis_thread = threading.Thread(target=self.perform_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()

    def perform_analysis(self):
        try:
            filepath = self.selected_file.get()

            with open(filepath, 'rb') as f:
                file_data = f.read()

            file_size = len(file_data)
            results = {}

            if self.show_hashes.get():
                self.root.after(0, lambda: self.status_label.config(text="Calculating file hashes..."))
                results['hashes'] = self.calculate_hashes(file_data)

            if self.show_structure.get():
                self.root.after(0, lambda: self.status_label.config(text="Analyzing file structure..."))
                results['structure'] = self.analyze_file_structure(file_data, filepath)

            if self.show_metadata.get():
                self.root.after(0, lambda: self.status_label.config(text="Extracting metadata..."))
                results['metadata'] = self.extract_metadata(file_data)

            if self.show_steganography.get():
                self.root.after(0, lambda: self.status_label.config(text="Detecting steganography..."))
                results['steganography'] = self.detect_steganography(file_data, file_size)

            if self.show_malicious.get():
                self.root.after(0, lambda: self.status_label.config(text="Scanning for malicious content..."))
                results['malicious_content'] = self.detect_malicious_content(file_data)

            if self.show_integrity.get():
                self.root.after(0, lambda: self.status_label.config(text="Checking file integrity..."))
                results['integrity'] = self.check_file_integrity(file_data)

            results['risk_assessment'] = self.calculate_risk_score(results)

            results['file_info'] = {
                'path': filepath,
                'filename': os.path.basename(filepath),
                'size': file_size,
                'analysis_date': datetime.now().isoformat()
            }

            self.root.after(0, self.update_results, results)

        except Exception as e:
            self.root.after(0, self.show_error, str(e))

    def calculate_hashes(self, file_data):
        return {
            'md5': hashlib.md5(file_data).hexdigest(),
            'sha1': hashlib.sha1(file_data).hexdigest(),
            'sha256': hashlib.sha256(file_data).hexdigest()
        }

    def analyze_file_structure(self, file_data, filepath):
        header = file_data[:32]

        signatures = {
            b'\xFF\xD8\xFF': {'type': 'JPEG', 'description': 'JPEG image file', 'extensions': ['.jpg', '.jpeg']},
            b'\x89PNG\r\n\x1A\n': {'type': 'PNG', 'description': 'PNG image file', 'extensions': ['.png']},
            b'GIF87a': {'type': 'GIF87a', 'description': 'GIF image file (1987)', 'extensions': ['.gif']},
            b'GIF89a': {'type': 'GIF89a', 'description': 'GIF image file (1989)', 'extensions': ['.gif']},
            b'BM': {'type': 'BMP', 'description': 'Bitmap image file', 'extensions': ['.bmp']},
            b'RIFF': {'type': 'RIFF', 'description': 'RIFF container (WebP, AVI, WAV)',
                      'extensions': ['.webp', '.avi', '.wav']},
            b'\x00\x00\x01\x00': {'type': 'ICO', 'description': 'Windows icon file', 'extensions': ['.ico']},
            b'II*\x00': {'type': 'TIFF_LE', 'description': 'TIFF image (Little Endian)',
                         'extensions': ['.tif', '.tiff']},
            b'MM\x00*': {'type': 'TIFF_BE', 'description': 'TIFF image (Big Endian)', 'extensions': ['.tif', '.tiff']}
        }

        detected_type = None
        for sig, info in signatures.items():
            if header.startswith(sig):
                detected_type = info
                break

        file_ext = os.path.splitext(filepath)[1].lower()
        extension_mismatch = False
        if detected_type and file_ext not in detected_type['extensions']:
            extension_mismatch = True

        return {
            'header_hex': header.hex(),
            'detected_type': detected_type,
            'file_extension': file_ext,
            'extension_mismatch': extension_mismatch,
            'header_ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in header)
        }

    def extract_metadata(self, file_data):
        metadata = {}

        if file_data.startswith(b'\xFF\xD8'):
            metadata.update(self._extract_jpeg_metadata(file_data))

        elif file_data.startswith(b'\x89PNG'):
            metadata.update(self._extract_png_metadata(file_data))

        metadata.update(self._search_general_metadata(file_data))

        return metadata

    def _extract_jpeg_metadata(self, file_data):
        metadata = {'format': 'JPEG'}

        exif_marker = b'\xFF\xE1'
        pos = file_data.find(exif_marker)
        if pos != -1:
            try:
                exif_length = struct.unpack('>H', file_data[pos + 2:pos + 4])[0]
                exif_data = file_data[pos + 4:pos + 2 + exif_length]

                if exif_data.startswith(b'Exif\x00\x00'):
                    metadata['has_exif'] = True
                    metadata['exif_size'] = exif_length

                    # Look for common EXIF strings
                    exif_strings = self._extract_strings_from_data(exif_data, min_length=3)
                    metadata['exif_strings'] = exif_strings[:10]
            except (struct.error, IndexError):
                pass

        return metadata

    def _extract_png_metadata(self, file_data):
        metadata = {'format': 'PNG'}
        chunks = []

        pos = 8
        while pos < len(file_data) - 8:
            try:
                length = struct.unpack('>I', file_data[pos:pos + 4])[0]
                chunk_type = file_data[pos + 4:pos + 8].decode('ascii', errors='ignore')

                chunk_info = {'type': chunk_type, 'length': length}


                if chunk_type in ['tEXt', 'iTXt', 'zTXt']:
                    chunk_data = file_data[pos + 8:pos + 8 + length]
                    chunk_info['data'] = chunk_data[:100].decode('utf-8', errors='ignore')

                chunks.append(chunk_info)
                pos += 8 + length + 4

                if len(chunks) > 20:
                    break

            except (struct.error, UnicodeDecodeError):
                break

        metadata['chunks'] = chunks
        return metadata

    def _search_general_metadata(self, file_data):
        metadata_patterns = {
            'camera_make': rb'(Canon|Nikon|Sony|Apple|Samsung|Fujifilm)[^\x00]{0,50}',
            'software': rb'(Photoshop|GIMP|Paint|Lightroom)[^\x00]{0,50}',
            'gps_coords': rb'GPS[^\x00]{0,100}',
            'timestamps': rb'(19|20)\d{2}[:-](0[1-9]|1[0-2])[:-](0[1-9]|[12][0-9]|3[01])',
            'copyright': rb'Copyright[^\x00]{0,100}',
        }

        found_metadata = {}
        for pattern_name, pattern in metadata_patterns.items():
            matches = re.findall(pattern, file_data, re.IGNORECASE)
            if matches:
                found_metadata[pattern_name] = [match.decode('utf-8', errors='ignore')
                                                for match in matches[:3]]

        return found_metadata

    def detect_steganography(self, file_data, file_size):
        indicators = {}

        entropy = self._calculate_entropy(file_data)
        indicators['entropy'] = entropy
        indicators['high_entropy'] = entropy > 7.5

        indicators['embedded_files'] = self._detect_embedded_files(file_data)

        indicators['trailing_data'] = self._analyze_trailing_data(file_data)

        indicators['lsb_indicators'] = self._check_lsb_indicators(file_data)

        return indicators

    def _calculate_entropy(self, file_data):
        import math

        if not file_data:
            return 0

        byte_counts = [0] * 256
        for byte in file_data:
            byte_counts[byte] += 1

        entropy = 0
        length = len(file_data)
        for count in byte_counts:
            if count > 0:
                freq = count / length
                entropy -= freq * math.log2(freq)

        return entropy

    def _detect_embedded_files(self, file_data):
        embedded_files = []

        file_signatures = {
            b'PK\x03\x04': 'ZIP/Office document',
            b'Rar!': 'RAR archive',
            b'\x7fELF': 'ELF executable',
            b'MZ': 'DOS/Windows executable',
            b'%PDF': 'PDF document',
            b'ID3': 'MP3 file'
        }

        for signature, file_type in file_signatures.items():
            pos = file_data.find(signature, 100)  # Skip first 100 bytes
            if pos != -1:
                embedded_files.append({'type': file_type, 'position': pos})
                if len(embedded_files) >= 5:
                    break

        return embedded_files

    def _analyze_trailing_data(self, file_data):
        trailing_info = {}

        if file_data.startswith(b'\xFF\xD8'):  # JPEG
            eoi_pos = file_data.rfind(b'\xFF\xD9')
            if eoi_pos != -1 and eoi_pos < len(file_data) - 2:
                trailing_data = file_data[eoi_pos + 2:]
                trailing_info = {
                    'has_trailing_data': True,
                    'trailing_size': len(trailing_data),
                    'trailing_strings': self._extract_strings_from_data(trailing_data)[:5]
                }

        return trailing_info

    def _check_lsb_indicators(self, file_data):
        indicators = {}

        sample_data = file_data[:1000]
        lsb_pattern = [byte & 1 for byte in sample_data]

        if len(lsb_pattern) > 100:
            runs = []
            current_run = 1
            for i in range(1, len(lsb_pattern)):
                if lsb_pattern[i] == lsb_pattern[i - 1]:
                    current_run += 1
                else:
                    runs.append(current_run)
                    current_run = 1

            if runs:
                avg_run = sum(runs) / len(runs)
                indicators['average_lsb_run'] = avg_run
                indicators['suspicious_lsb_pattern'] = avg_run < 2.0

        return indicators

    def detect_malicious_content(self, file_data):
        malicious_indicators = {}

        for pattern_name, pattern in self.suspicious_patterns.items():
            matches = re.findall(pattern, file_data, re.IGNORECASE | re.DOTALL)
            if matches:
                malicious_indicators[pattern_name] = {
                    'count': len(matches),
                    'samples': [match.decode('utf-8', errors='ignore')[:50]
                                for match in matches[:2]]
                }

        return malicious_indicators

    def check_file_integrity(self, file_data):
        integrity_info = {}

        if file_data.startswith(b'\xFF\xD8') and not file_data.endswith(b'\xFF\xD9'):
            integrity_info['jpeg_truncated'] = True

        null_count = file_data.count(b'\x00')
        if null_count > len(file_data) * 0.1:
            integrity_info['excessive_null_bytes'] = {
                'count': null_count,
                'percentage': (null_count / len(file_data)) * 100
            }

        return integrity_info

    def _extract_strings_from_data(self, data, min_length=4):
        strings = []
        ascii_pattern = rb'[ -~]{' + str(min_length).encode() + rb',}'
        matches = re.findall(ascii_pattern, data)

        for match in matches:
            try:
                decoded = match.decode('ascii').strip()
                if len(decoded) >= min_length:
                    strings.append(decoded)
            except UnicodeDecodeError:
                continue

        return strings[:20]

    def calculate_risk_score(self, results):
        score = 0
        warnings = []

        if results.get('structure', {}).get('extension_mismatch'):
            score += 2
            warnings.append("File extension mismatch")

        stego = results.get('steganography', {})
        if stego.get('high_entropy'):
            score += 2
            warnings.append("High entropy (possible hidden data)")

        if stego.get('embedded_files'):
            score += 3
            warnings.append("Embedded files detected")

        if stego.get('trailing_data', {}).get('has_trailing_data'):
            score += 2
            warnings.append("Trailing data after image")

        #malicious content
        if results.get('malicious_content'):
            score += 4
            warnings.append("Suspicious patterns detected")

        #integrity issues
        if results.get('integrity'):
            score += 1
            warnings.append("File integrity issues")

        risk_level = "LOW"
        if score >= 7:
            risk_level = "HIGH"
        elif score >= 3:
            risk_level = "MEDIUM"

        return {
            'score': score,
            'max_score': 10,
            'level': risk_level,
            'warnings': warnings
        }

    def update_results(self, results):
        self.analysis_results = results
        self.update_summary_display(results)
        self.update_detailed_display(results)
        self.update_json_display(results)

        self.save_report_btn.config(state="normal")
        self.save_json_btn.config(state="normal")
        self.copy_json_btn.config(state="normal")
        self.is_analyzing = False
        self.analyze_btn.config(state="normal")
        self.progress.stop()

        risk = results['risk_assessment']
        risk_emoji = {"LOW": "✅", "MEDIUM": "⚠️", "HIGH": "🚨"}
        self.status_label.config(
            text=f"Analysis complete - {risk_emoji[risk['level']]} {risk['level']} RISK (Score: {risk['score']}/10)")

    def update_summary_display(self, results):
        self.summary_text.config(state="normal")
        self.summary_text.delete(1.0, tk.END)

        file_info = results['file_info']
        risk = results['risk_assessment']

        self.summary_text.insert(tk.END, "🛡️ SECURITY ANALYSIS SUMMARY\n", "header")
        self.summary_text.insert(tk.END, "=" * 80 + "\n", "normal")
        self.summary_text.insert(tk.END, f"File: {file_info['filename']}\n", "normal")
        self.summary_text.insert(tk.END, f"Size: {file_info['size']:,} bytes\n", "normal")
        self.summary_text.insert(tk.END,
                                 f"Analysis Date: {datetime.fromisoformat(file_info['analysis_date']).strftime('%Y-%m-%d %H:%M:%S')}\n\n",
                                 "normal")


        risk_emoji = {"LOW": "✅", "MEDIUM": "⚠️", "HIGH": "🚨"}
        self.summary_text.insert(tk.END, f"{risk_emoji[risk['level']]} RISK ASSESSMENT\n", "subheader")

        risk_color = {"LOW": "success", "MEDIUM": "warning", "HIGH": "error"}
        self.summary_text.insert(tk.END, f"Risk Level: {risk['level']} ({risk['score']}/10)\n",
                                 risk_color[risk['level']])

        if risk['warnings']:
            self.summary_text.insert(tk.END, "\nSecurity Concerns:\n", "warning")
            for warning in risk['warnings']:
                self.summary_text.insert(tk.END, f"• {warning}\n", "warning")
        else:
            self.summary_text.insert(tk.END, "No significant security concerns detected.\n", "success")

        self.summary_text.insert(tk.END, "\n" + "=" * 80 + "\n\n", "normal")


        if results.get('hashes'):
            self.summary_text.insert(tk.END, "🔐 FILE HASHES\n", "subheader")
            hashes = results['hashes']
            self.summary_text.insert(tk.END, f"MD5:    {hashes['md5']}\n", "normal")
            self.summary_text.insert(tk.END, f"SHA1:   {hashes['sha1']}\n", "normal")
            self.summary_text.insert(tk.END, f"SHA256: {hashes['sha256']}\n\n", "normal")

        if results.get('structure'):
            struct = results['structure']
            self.summary_text.insert(tk.END, "📋 FILE STRUCTURE\n", "subheader")
            if struct['detected_type']:
                self.summary_text.insert(tk.END, f"Detected Type: {struct['detected_type']['type']}\n", "normal")
            self.summary_text.insert(tk.END, f"File Extension: {struct['file_extension']}\n", "normal")

            if struct['extension_mismatch']:
                self.summary_text.insert(tk.END, "⚠️ WARNING: File extension doesn't match detected type!\n", "warning")
            self.summary_text.insert(tk.END, "\n", "normal")

        if results.get('steganography'):
            stego = results['steganography']
            self.summary_text.insert(tk.END, "🔍 STEGANOGRAPHY ANALYSIS\n", "subheader")
            self.summary_text.insert(tk.END, f"File Entropy: {stego['entropy']:.3f}\n", "normal")

            if stego['high_entropy']:
                self.summary_text.insert(tk.END, "🚨 High entropy detected - possible hidden data!\n", "error")

            if stego['embedded_files']:
                self.summary_text.insert(tk.END, f"🚨 {len(stego['embedded_files'])} embedded file(s) detected:\n",
                                         "error")
                for ef in stego['embedded_files'][:3]:
                    self.summary_text.insert(tk.END, f"  • {ef['type']} at position {ef['position']}\n", "error")

            if stego['trailing_data'].get('has_trailing_data'):
                td = stego['trailing_data']
                self.summary_text.insert(tk.END, f"🚨 {td['trailing_size']} bytes of trailing data detected\n", "error")

            self.summary_text.insert(tk.END, "\n", "normal")

        if results.get('malicious_content'):
            malicious = results['malicious_content']
            self.summary_text.insert(tk.END, "🛡️ MALICIOUS CONTENT SCAN\n", "subheader")

            total_threats = sum(details['count'] for details in malicious.values() if isinstance(details, dict))
            if total_threats > 0:
                self.summary_text.insert(tk.END, f"🚨 {total_threats} suspicious pattern(s) detected:\n", "error")
                for pattern_name, details in list(malicious.items())[:5]:
                    if isinstance(details, dict):
                        self.summary_text.insert(tk.END, f"  • {pattern_name}: {details['count']} matches\n", "error")
            else:
                self.summary_text.insert(tk.END, "✅ No obvious malicious patterns detected\n", "success")

            self.summary_text.insert(tk.END, "\n", "normal")

        #Recommendations
        self.summary_text.insert(tk.END, "💡 RECOMMENDATIONS\n", "subheader")

        if risk['level'] == "LOW":
            self.summary_text.insert(tk.END, "✅ File appears to be a normal image with low security risk.\n", "success")
        elif risk['level'] == "MEDIUM":
            self.summary_text.insert(tk.END, "⚠️ Some suspicious indicators found. Review detailed analysis.\n",
                                     "warning")
        else:
            self.summary_text.insert(tk.END, "🚨 HIGH RISK: Multiple security concerns detected!\n", "error")
            self.summary_text.insert(tk.END, "• Do not open or execute this file\n", "error")
            self.summary_text.insert(tk.END, "• Consider quarantine or deletion\n", "error")
            self.summary_text.insert(tk.END, "• Report to security team if applicable\n", "error")

        self.summary_text.config(state="disabled")

    def update_detailed_display(self, results):

        self.detailed_text.config(state="normal")
        self.detailed_text.delete(1.0, tk.END)

        self.detailed_text.insert(tk.END, "📊 COMPREHENSIVE SECURITY ANALYSIS REPORT\n", "header")
        self.detailed_text.insert(tk.END, "=" * 100 + "\n\n", "normal")

        file_info = results['file_info']
        self.detailed_text.insert(tk.END, f"File: {file_info['filename']}\n", "normal")
        self.detailed_text.insert(tk.END, f"Path: {file_info['path']}\n", "normal")
        self.detailed_text.insert(tk.END, f"Size: {file_info['size']:,} bytes\n", "normal")
        self.detailed_text.insert(tk.END,
                                  f"Analysis: {datetime.fromisoformat(file_info['analysis_date']).strftime('%Y-%m-%d %H:%M:%S')}\n\n",
                                  "normal")

        #Detailed sections
        if results.get('hashes'):
            self.detailed_text.insert(tk.END, "🔐 CRYPTOGRAPHIC HASHES\n", "subheader")
            self.detailed_text.insert(tk.END, "-" * 30 + "\n", "normal")
            hashes = results['hashes']
            for hash_type, hash_value in hashes.items():
                self.detailed_text.insert(tk.END, f"{hash_type.upper()}: {hash_value}\n", "metadata")
            self.detailed_text.insert(tk.END, "\n", "normal")

        if results.get('structure'):
            self.detailed_text.insert(tk.END, "📋 FILE STRUCTURE ANALYSIS\n", "subheader")
            self.detailed_text.insert(tk.END, "-" * 30 + "\n", "normal")
            struct = results['structure']

            self.detailed_text.insert(tk.END, f"Header (Hex): {struct['header_hex']}\n", "metadata")
            self.detailed_text.insert(tk.END, f"Header (ASCII): {struct['header_ascii']}\n", "metadata")

            if struct['detected_type']:
                dt = struct['detected_type']
                self.detailed_text.insert(tk.END, f"Detected Type: {dt['type']} - {dt['description']}\n", "metadata")
                self.detailed_text.insert(tk.END, f"Expected Extensions: {', '.join(dt['extensions'])}\n", "metadata")

            self.detailed_text.insert(tk.END, f"Actual Extension: {struct['file_extension']}\n", "metadata")

            if struct['extension_mismatch']:
                self.detailed_text.insert(tk.END, "⚠️ MISMATCH: Extension doesn't match file signature!\n", "warning")

            self.detailed_text.insert(tk.END, "\n", "normal")

        if results.get('metadata'):
            self.detailed_text.insert(tk.END, "📊 METADATA EXTRACTION\n", "subheader")
            self.detailed_text.insert(tk.END, "-" * 30 + "\n", "normal")
            metadata = results['metadata']

            for key, value in metadata.items():
                if isinstance(value, list):
                    self.detailed_text.insert(tk.END, f"{key}: {', '.join(str(v) for v in value[:3])}\n", "metadata")
                else:
                    self.detailed_text.insert(tk.END, f"{key}: {value}\n", "metadata")

            if not metadata:
                self.detailed_text.insert(tk.END, "No metadata found\n", "normal")

            self.detailed_text.insert(tk.END, "\n", "normal")

        if results.get('steganography'):
            self.detailed_text.insert(tk.END, "🔍 STEGANOGRAPHY DETECTION\n", "subheader")
            self.detailed_text.insert(tk.END, "-" * 30 + "\n", "normal")
            stego = results['steganography']

            self.detailed_text.insert(tk.END, f"Shannon Entropy: {stego['entropy']:.6f}\n", "metadata")
            if stego['high_entropy']:
                self.detailed_text.insert(tk.END, "🚨 HIGH ENTROPY WARNING: Possible compressed/encrypted data\n",
                                          "error")
            else:
                self.detailed_text.insert(tk.END, "✅ Normal entropy levels\n", "success")

            if stego['embedded_files']:
                self.detailed_text.insert(tk.END, f"\n🚨 EMBEDDED FILES DETECTED ({len(stego['embedded_files'])}):\n",
                                          "error")
                for i, ef in enumerate(stego['embedded_files'][:10], 1):
                    self.detailed_text.insert(tk.END, f"{i}. {ef['type']} at byte position {ef['position']}\n", "error")

            if stego['trailing_data'].get('has_trailing_data'):
                td = stego['trailing_data']
                self.detailed_text.insert(tk.END, f"\n🚨 TRAILING DATA: {td['trailing_size']} bytes after image end\n",
                                          "error")
                if td['trailing_strings']:
                    self.detailed_text.insert(tk.END, "Strings in trailing data:\n", "error")
                    for string in td['trailing_strings']:
                        self.detailed_text.insert(tk.END, f"  • {string}\n", "error")

            lsb = stego.get('lsb_indicators', {})
            if lsb.get('suspicious_lsb_pattern'):
                self.detailed_text.insert(tk.END,
                                          f"\n⚠️ LSB Pattern: Average run length {lsb['average_lsb_run']:.2f} (suspicious)\n",
                                          "warning")

            self.detailed_text.insert(tk.END, "\n", "normal")

        if results.get('malicious_content'):
            self.detailed_text.insert(tk.END, "🛡️ MALICIOUS CONTENT ANALYSIS\n", "subheader")
            self.detailed_text.insert(tk.END, "-" * 30 + "\n", "normal")
            malicious = results['malicious_content']

            if malicious:
                for pattern_name, details in malicious.items():
                    if isinstance(details, dict) and 'count' in details:
                        self.detailed_text.insert(tk.END,
                                                  f"🚨 {pattern_name.upper().replace('_', ' ')}: {details['count']} matches\n",
                                                  "error")
                        for sample in details.get('samples', []):
                            self.detailed_text.insert(tk.END, f"    Sample: {sample}...\n", "suspicious")
                        self.detailed_text.insert(tk.END, "\n", "normal")
            else:
                self.detailed_text.insert(tk.END, "✅ No malicious patterns detected\n", "success")

            self.detailed_text.insert(tk.END, "\n", "normal")

        if results.get('integrity'):
            self.detailed_text.insert(tk.END, "🔧 FILE INTEGRITY CHECK\n", "subheader")
            self.detailed_text.insert(tk.END, "-" * 30 + "\n", "normal")
            integrity = results['integrity']

            if integrity:
                for issue, details in integrity.items():
                    self.detailed_text.insert(tk.END, f"⚠️ {issue.upper().replace('_', ' ')}: {details}\n", "warning")
            else:
                self.detailed_text.insert(tk.END, "✅ File structure appears intact\n", "success")

            self.detailed_text.insert(tk.END, "\n", "normal")

        self.detailed_text.config(state="disabled")

    def update_json_display(self, results):
        self.json_text.config(state="normal")
        self.json_text.delete(1.0, tk.END)

        try:
            json_str = json.dumps(results, indent=2, default=str)
            self.json_text.insert(tk.END, json_str)
        except Exception as e:
            self.json_text.insert(tk.END, f"Error generating JSON: {str(e)}")

        self.json_text.config(state="disabled")

    def show_error(self, error_msg):
        self.is_analyzing = False
        self.analyze_btn.config(state="normal")
        self.progress.stop()
        self.status_label.config(text="Analysis failed")
        messagebox.showerror("Analysis Error", f"An error occurred during analysis:\n\n{error_msg}")

    def save_report(self):

        if not self.analysis_results:
            messagebox.showwarning("No Results", "No analysis results to save.")
            return

        filename = filedialog.asksaveasfilename(
            title="Save Analysis Report",
            defaultextension=".txt",
            filetypes=[
                ("Text Files", "*.txt"),
                ("All Files", "*.*")
            ]
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    #Get the text content from detailed display
                    content = self.detailed_text.get(1.0, tk.END)
                    f.write(content)

                messagebox.showinfo("Save Successful", f"Report saved to:\n{filename}")

            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save report:\n\n{str(e)}")

    def save_json(self):
        if not self.analysis_results:
            messagebox.showwarning("No Results", "No analysis results to save.")
            return

        filename = filedialog.asksaveasfilename(
            title="Save JSON Data",
            defaultextension=".json",
            filetypes=[
                ("JSON Files", "*.json"),
                ("All Files", "*.*")
            ]
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.analysis_results, f, indent=2, default=str)

                messagebox.showinfo("Save Successful", f"JSON data saved to:\n{filename}")

            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save JSON:\n\n{str(e)}")

    def copy_json(self):
        """Copy JSON to clipboard"""
        if not self.analysis_results:
            messagebox.showwarning("No Results", "No analysis results to copy.")
            return

        try:
            json_str = json.dumps(self.analysis_results, indent=2, default=str)
            self.root.clipboard_clear()
            self.root.clipboard_append(json_str)
            messagebox.showinfo("Copied", "JSON data copied to clipboard!")

        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy JSON:\n\n{str(e)}")

    def clear_results(self):
        #Clear text widgets
        for text_widget in [self.summary_text, self.detailed_text, self.json_text]:
            text_widget.config(state="normal")
            text_widget.delete(1.0, tk.END)
            text_widget.config(state="disabled")

        #Reset state
        self.analysis_results = {}
        self.save_report_btn.config(state="disabled")
        self.save_json_btn.config(state="disabled")
        self.copy_json_btn.config(state="disabled")
        self.status_label.config(text="Ready to analyze image files")


def main():
    root = tk.Tk()

    try:
        style = ttk.Style()
        available_themes = style.theme_names()
        if 'winnative' in available_themes:
            style.theme_use('winnative')
        elif 'clam' in available_themes:
            style.theme_use('clam')

        style.configure('Accent.TButton', font=('Arial', 10, 'bold'))

    except Exception:
        pass

    app = ComprehensiveImageAnalyzerGUI(root)

    root.update_idletasks()
    x = (root.winfo_screenwidth() - root.winfo_width()) // 2
    y = (root.winfo_screenheight() - root.winfo_height()) // 2
    root.geometry(f"+{x}+{y}")

    root.mainloop()


if __name__ == '__main__':
    main()
