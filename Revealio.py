# Revealio - A Forensic Tool

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import mimetypes
import binascii
import re
import math

THEME_BG = "#7f0909"  
THEME_FG = "gold"

# List of known file signatures (magic numbers)
MAGIC_NUMBERS = {
    b"\x89PNG": "PNG image",
    b"\xFF\xD8\xFF": "JPEG image",
    b"%PDF": "PDF document",
    b"PK\x03\x04": "ZIP archive",
    b"MZ": "Windows EXE",
    b"Rar!": "RAR archive",
    b"\x1F\x8B": "GZIP archive",
    b"ID3": "MP3 audio"
}

# Suspicious shell commands
SUSPICIOUS_KEYWORDS = [
    "powershell", "cmd.exe", "wget", "curl", "Invoke-Expression", "nc.exe",
    "bash -i", "php -r", "python -c", "mshta", "regsvr32", "certutil", "vbs",
    "shellcode", "dropper", "payload", "reverse shell"
]

def get_magic_type(file_path):
    with open(file_path, "rb") as f:
        header = f.read(16)
        for sig, ftype in MAGIC_NUMBERS.items():
            if sig in header:
                return ftype
    return "Unknown"

def calculate_entropy(data):
    if not data:
        return 0
    frequency = {}
    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1
    entropy = 0
    for count in frequency.values():
        p_x = count / len(data)
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)

def detect_eof_anomaly(file_path):
    with open(file_path, "rb") as f:
        content = f.read()
        eof_markers = [b"\x00\x00", b"IEND", b"\xFF\xD9", b"%EOF", b"%%EOF"]
        for marker in eof_markers:
            pos = content.find(marker)
            if pos != -1 and pos + len(marker) < len(content):
                # Data found after EOF marker
                return True
    return False

def find_suspicious_strings(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    text = data.decode(errors="ignore").lower()
    found = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text:
            found.append(keyword)
    return found

class RevealioApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Revealio – Payload & Threat Scanner")
        self.root.geometry("750x520")
        self.root.configure(bg=THEME_BG)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=THEME_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=THEME_BG, foreground=THEME_FG, padding=[10, 5])
        style.map("TNotebook.Tab", background=[("selected", THEME_FG)], foreground=[("selected", THEME_BG)])

        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill="both", expand=True)

        self.create_scanner_tab()
        self.create_how_to_use_tab()

    def create_scanner_tab(self):
        tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(tab, text="🛡️ Scan File")

        tk.Label(tab, text="🔍 Select any file to scan:", font=("Georgia", 14), fg=THEME_FG, bg=THEME_BG).pack(pady=10)
        tk.Button(tab, text="Browse", command=self.browse_file, bg="gold").pack()

        self.result_box = tk.Text(tab, height=22, width=80, wrap="word", bg="#f5f5dc", fg="black")
        self.result_box.pack(pady=15)

    def create_how_to_use_tab(self):
        tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(tab, text="📖 How to Use")

        help_text = """
🧙 Welcome to Revealio – Forensic Threat Detector 🧙

This tool helps you scan ANY file for signs of suspicious payloads, embedded scripts, or hidden data.
Revealio performs the following checks:

✅ File Signature Check — detects actual file type based on magic bytes
✅ MIME Type Guess — compares extension vs internal structure
✅ Entropy Analysis — flags encrypted/compressed embedded blobs
✅ EOF Anomaly Scan — finds hidden data after end-of-file
✅ Suspicious Command Search — flags shell keywords and scripts

How to use:
1. Click on Scan tab
2. Browse and select any file (.jpg, .pdf, .exe, etc.)
3. View color-coded flags and detailed findings in result area

🛡️ WE protects those who protect others!
        """
        tk.Label(tab, text=help_text, justify="left", wraplength=720, fg=THEME_FG, bg=THEME_BG, font=("Georgia", 11)).pack(padx=10, pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        self.result_box.delete(1.0, tk.END)
        self.result_box.insert(tk.END, f"📂 File Selected: {file_path}\n\n")

        result = self.analyze_file(file_path)
        self.result_box.insert(tk.END, result)

    def analyze_file(self, file_path):
        findings = []

        # Magic bytes check
        magic_type = get_magic_type(file_path)
        extension_type = mimetypes.guess_type(file_path)[0]
        findings.append(f"🧙 Detected Type (Magic Bytes): {magic_type}")
        findings.append(f"📁 Extension MIME Type: {extension_type if extension_type else 'Unknown'}")

        if extension_type and magic_type != "Unknown" and magic_type.lower() not in extension_type.lower():
            findings.append("❗ [WARNING] File extension does NOT match detected type!")

        # Entropy check
        with open(file_path, "rb") as f:
            data = f.read()
        entropy = calculate_entropy(data)
        findings.append(f"📊 File Entropy: {entropy}")

        if entropy > 7.5:
            findings.append("⚠️ [WARNING] High entropy! File may contain encrypted or compressed payloads.")

        # EOF Check
        if detect_eof_anomaly(file_path):
            findings.append("🔴 [CRITICAL] File contains extra data after end-of-file marker!")

        # Suspicious keywords
        suspicious = find_suspicious_strings(file_path)
        if suspicious:
            findings.append(f"🛑 [ALERT] Suspicious keywords found: {', '.join(suspicious)}")

        if not suspicious and entropy <= 7.5 and not detect_eof_anomaly(file_path):
            findings.append("✅ [SAFE] No critical anomalies detected.")

        return "\n".join(findings)

if __name__ == "__main__":
    root = tk.Tk()
    app = RevealioApp(root)
    root.mainloop()
