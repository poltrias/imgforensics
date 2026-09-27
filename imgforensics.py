#!/usr/bin/env python3
"""
imgforensics.py — all-in-one image forensics tool for CTF/pentesting.

Instead of just chaining exiftool/binwalk/steghide, this tool adds its
own checks (container-format parsing, polyglot detection, visual
bit-plane extraction...) that no single existing tool gives you on its
own, and ends with an aggregated verdict so you don't have to read
through 8 separate blocks of output to decide whether an image is
worth investigating further.

Checks:
  File level:
    - Hashes (MD5/SHA1/SHA256)
    - Real magic signature vs. declared file extension
    - Trailing data after the official end-of-file marker
    - Polyglot detection (a valid ZIP/other file hidden inside the image)
  Format level:
    - PNG chunk parsing (tEXt/zTXt/iTXt and non-standard chunks)
    - EXIF/XMP/IPTC metadata (exiftool)
    - Embedded files/signatures (binwalk)
  Content level:
    - Interesting printable strings
    - Embedded QR codes / barcodes (pyzbar, optional)
    - Custom LSB heuristic (statistical bias, no dependencies)
    - Visual bit-plane extraction (like Stegsolve, done locally)
    - zsteg (PNG/BMP)
  Passphrase-based steganography:
    - steghide (JPEG/BMP/WAV/AU) — empty-passphrase extraction + brute force (stegseek)
    - outguess (JPEG) — empty-passphrase extraction

Signal filtering: binwalk and zsteg both report a lot of expected
"noise" on completely ordinary images (a PNG always contains a Zlib
stream — that's just the picture; zsteg tries every bit-plane
combination and randomly finds printable-looking garbage in real
photo noise). Raw output is always shown, but the final verdict only
counts findings that go beyond that expected baseline.

Author: Pol Trias
"""

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

try:
    from rich.console import Console
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None

try:
    from PIL import Image
except ImportError:
    Image = None

try:
    from pyzbar.pyzbar import decode as zbar_decode
    PYZBAR = True
except ImportError:
    PYZBAR = False


# ---------- output helpers ----------

def info(msg):
    console.print(f"[bold cyan][*][/bold cyan] {msg}") if RICH else print(f"[*] {msg}")


def warn(msg):
    console.print(f"[bold yellow][!][/bold yellow] {msg}") if RICH else print(f"[!] {msg}")


def ok(msg):
    console.print(f"[bold green][+][/bold green] {msg}") if RICH else print(f"[+] {msg}")


# ---------- utilities ----------

def tool_available(name):
    return shutil.which(name) is not None


def run(cmd, timeout=60):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return None, f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return None, f"{cmd[0]} timed out"


# ==========================================================================
# FILE LEVEL — checks that don't depend on any external tool
# ==========================================================================

MAGIC_SIGNATURES = {
    b"\xff\xd8\xff": "jpg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"BM": "bmp",
    b"PK\x03\x04": "zip",
    b"%PDF": "pdf",
    b"Rar!\x1a\x07": "rar",
    b"RIFF": "wav/webp",
}

# Known end-of-format markers, used to detect trailing data appended after them
EOF_MARKERS = {
    "jpg": b"\xff\xd9",
    "jpeg": b"\xff\xd9",
    "png": b"IEND\xaeB`\x82",
    "gif": b"\x3b",  # GIF trailer (single byte, less reliable)
}


def compute_hashes(path):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def check_magic_mismatch(path):
    """Compare the file's real magic signature against its declared extension."""
    with open(path, "rb") as f:
        header = f.read(16)

    detected = None
    for sig, fmt in MAGIC_SIGNATURES.items():
        if header.startswith(sig):
            detected = fmt
            break

    ext = path.suffix.lower().lstrip(".")
    mismatch = detected is not None and ext not in detected.split("/")
    return {"declared_extension": ext or "(none)", "detected_format": detected or "unknown", "mismatch": mismatch}


def check_trailing_data(path):
    """
    Looks for data appended after the official end-of-format marker. One
    of the most classic CTF tricks: hiding a ZIP, a text message or
    another file right after the EOF marker that image viewers ignore.
    """
    ext = path.suffix.lower().lstrip(".")
    marker = EOF_MARKERS.get(ext)
    if not marker:
        return None

    data = path.read_bytes()
    idx = data.rfind(marker)
    if idx == -1:
        return {"found": False}

    end_of_official_data = idx + len(marker)
    trailing = data[end_of_official_data:]
    if not trailing:
        return {"found": False}

    return {
        "found": True,
        "extra_bytes": len(trailing),
        "offset": end_of_official_data,
        "preview_hex": trailing[:32].hex(),
        "preview_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in trailing[:64]),
    }


def check_polyglot_zip(path):
    """
    zipfile.is_zipfile() looks for the 'end of central directory' record
    starting from the end of the file and working backwards, so it
    correctly detects an appended ZIP even when the file starts with
    valid image data (the classic PNG+ZIP or JPEG+ZIP polyglot).
    """
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
            return {"is_zip_polyglot": True, "contents": names[:30]}
    except (zipfile.BadZipFile, OSError):
        pass
    return {"is_zip_polyglot": False}


# ==========================================================================
# FORMAT LEVEL — own container parsing
# ==========================================================================

PNG_STANDARD_CHUNKS = {
    "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP",
    "sBIT", "sRGB", "bKGD", "hIST", "pHYs", "sPLT", "tIME",
}
PNG_TEXT_CHUNKS = {"tEXt", "zTXt", "iTXt"}


def parse_png_chunks(path):
    """
    Manually parses a PNG's chunk structure (no libpng involved):
    length(4) + type(4) + data(length) + crc(4), repeated. Flags any
    non-standard chunk and shows the content of text chunks, which are
    often used to hide messages directly in the container.
    """
    if path.suffix.lower() != ".png":
        return None

    data = path.read_bytes()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None

    chunks = []
    offset = 8
    while offset + 8 <= len(data):
