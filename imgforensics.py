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
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        ctype = data[offset + 4:offset + 8].decode("ascii", errors="replace")
        chunk_data = data[offset + 8:offset + 8 + length]

        entry = {"type": ctype, "length": length, "standard": ctype in PNG_STANDARD_CHUNKS}
        if ctype in PNG_TEXT_CHUNKS:
            try:
                entry["text"] = chunk_data.decode("latin-1", errors="replace")[:200]
            except Exception:
                pass
        chunks.append(entry)

        offset += 8 + length + 4  # skip data + CRC
        if ctype == "IEND":
            break

    return chunks


# ==========================================================================
# EXTERNAL TOOLS — wrappers with graceful degradation when not installed
# ==========================================================================

def check_metadata(path):
    if not tool_available("exiftool"):
        warn("exiftool not installed — skipping metadata (sudo apt install libimage-exiftool-perl)")
        return {}
    out, err = run(["exiftool", "-j", str(path)])
    if out:
        try:
            data = json.loads(out)[0]
            data.pop("SourceFile", None)
            return data
        except (json.JSONDecodeError, IndexError):
            return {}
    return {}


def check_embedded_files(path):
    if not tool_available("binwalk"):
        warn("binwalk not installed — skipping embedded file detection (sudo apt install binwalk)")
        return []
    out, err = run(["binwalk", str(path)])
    findings = []
    if out:
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("DECIMAL") and not line.startswith("---"):
                findings.append(line)
    return findings


def check_strings(path, min_len=6, limit=40):
    data = path.read_bytes()
    results = []
    current = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= min_len:
                results.append(current.decode("ascii"))
            current = bytearray()
    if len(current) >= min_len:
        results.append(current.decode("ascii"))

    markers = ("flag{", "FLAG{", "CTF{", "http://", "https://", "ssh-rsa", "BEGIN ", "password", "PASSWORD")
    interesting = [s for s in results if any(m in s for m in markers)]
    return (interesting or results)[:limit]


def check_qr(path):
    if not PYZBAR:
        return None
    if Image is None:
        return None
    try:
        img = Image.open(path)
        results = zbar_decode(img)
    except Exception:
        return None
    if not results:
        return []
    return [{"type": r.type, "data": r.data.decode("utf-8", errors="replace")} for r in results]


def check_zsteg(path):
    if path.suffix.lower() not in (".png", ".bmp"):
        return None
    if not tool_available("zsteg"):
        warn("zsteg not installed — skipping (sudo gem install zsteg)")
        return None
    out, err = run(["zsteg", str(path)], timeout=90)
    if out:
        return [l for l in out.splitlines() if l.strip()][:30]
    return None


STEGHIDE_FORMATS = {".jpg", ".jpeg", ".bmp", ".wav", ".au"}


def try_steghide_extract(path, passphrase=""):
    if path.suffix.lower() not in STEGHIDE_FORMATS or not tool_available("steghide"):
        return None
    out, err = run(["steghide", "extract", "-sf", str(path), "-p", passphrase, "-f"])
    if err and "wrote extracted data" in err.lower():
        return err
    return None


def crack_steghide(path, wordlist):
    if path.suffix.lower() not in STEGHIDE_FORMATS:
        return None
    if not tool_available("stegseek"):
        warn("stegseek not installed — skipping brute force (sudo apt install stegseek)")
        return None
    if not wordlist or not Path(wordlist).exists():
        warn(f"Wordlist not found ({wordlist}) — skipping brute force")
        return None
    out, err = run(["stegseek", str(path), str(wordlist)], timeout=300)
    combined = f"{out}\n{err}".strip()
    return combined if combined else None


def try_outguess(path):
    if path.suffix.lower() not in (".jpg", ".jpeg") or not tool_available("outguess"):
        return None
    out_file = path.with_suffix(".outguess.out")
    out, err = run(["outguess", "-r", str(path), str(out_file)])
    if out_file.exists() and out_file.stat().st_size > 0:
        content = out_file.read_bytes()[:200]
        out_file.unlink(missing_ok=True)
        return content.hex()
    out_file.unlink(missing_ok=True)
    return None


# ==========================================================================
# CUSTOM LSB HEURISTIC + VISUAL BIT-PLANE EXTRACTION
# ==========================================================================

def check_lsb_bias(path):
    """
    Without relying on any external tool: checks whether the least
    significant bit of each color channel deviates too much from a
    ~50/50 distribution, a typical sign of naive LSB steganography
    (embedded data tends to look like random noise).
    """
    if Image is None:
        warn("Pillow not installed — skipping LSB analysis (pip install Pillow)")
        return None
    try:
        img = Image.open(path).convert("RGB")
    except Exception as e:
        warn(f"Could not open image with Pillow: {e}")
        return None

    raw = img.tobytes()
    total = len(raw) // 3
    if total == 0:
        return None

    ones = [0, 0, 0]
    for i in range(0, total * 3, 3):
        ones[0] += raw[i] & 1
        ones[1] += raw[i + 1] & 1
        ones[2] += raw[i + 2] & 1

    ratios = [o / total for o in ones]
    deviation = [abs(r - 0.5) for r in ratios]
    suspicious = all(d < 0.02 for d in deviation)

    return {
        "channel_R_ratio_1s": round(ratios[0], 4),
        "channel_G_ratio_1s": round(ratios[1], 4),
        "channel_B_ratio_1s": round(ratios[2], 4),
        "suspicious": suspicious,
    }


def extract_bitplanes(path, outdir, max_dim=512):
    """
    For each RGB channel, generates an image with all 8 bit planes
    arranged in a grid (like Stegsolve). A message hidden in the LSB
    often doesn't move the global statistics enough to trip the
    statistical heuristic, but is still visible to the naked eye as
    structured noise on bit-plane 0 (the least significant one).
    """
    if Image is None:
        return None
    try:
        img = Image.open(path).convert("RGB")
    except Exception:
        return None

    img.thumbnail((max_dim, max_dim))
    w, h = img.size
    raw = img.tobytes()

    generated = []
    channel_names = ["R", "G", "B"]
    for c in range(3):
        # 4x2 grid with the 8 bits (7=MSB ... 0=LSB), LSB at top-left
        grid = Image.new("L", (w * 4, h * 2))
        for bit in range(8):
            plane = bytearray(w * h)
            for i in range(w * h):
                plane[i] = 255 if (raw[i * 3 + c] >> bit) & 1 else 0
            plane_img = Image.frombytes("L", (w, h), bytes(plane))
            col = bit % 4
            row = bit // 4
            grid.paste(plane_img, (col * w, row * h))

        out_path = Path(outdir) / f"{path.stem}_bitplanes_{channel_names[c]}.png"
        grid.save(out_path)
        generated.append(str(out_path))

    return generated


# ==========================================================================
# SIGNAL FILTERING — separate real findings from expected tool "noise"
# ==========================================================================

BINWALK_LINE_RE = re.compile(r"^\s*\d+\s+0x[0-9a-fA-F]+\s+(.*)$")


def filter_binwalk_signal(embedded_lines):
    """
    binwalk reports two 'boilerplate' matches on virtually any PNG/JPEG:
    the file's own container signature, and a single Zlib/DEFLATE stream
    (the normal pixel data — that's the picture, not hidden data). Only
    entries beyond those count as a real signal, so a completely
    ordinary photo doesn't get flagged just for being a PNG.
    """
    meaningful = []
    seen_first_zlib = False
    for line in embedded_lines:
        m = BINWALK_LINE_RE.match(line)
        desc = m.group(1) if m else line
        if desc.startswith("PNG image") or desc.startswith("JPEG image data"):
            continue
        if desc.startswith("Zlib compressed data") and not seen_first_zlib:
            seen_first_zlib = True
            continue
        meaningful.append(line)
    return meaningful


ZSTEG_MIN_TEXT_LEN = 16
ZSTEG_MIN_LETTER_RATIO = 0.75
ZSTEG_FLAG_MARKERS = ("flag{", "FLAG{", "CTF{", "http://", "https://")


def _looks_like_real_text(s):
    """
    A flag-style marker is meaningful at any length. Otherwise, zsteg
    tries dozens of bit-plane/channel/order combinations per image, so
    with enough attempts a short run of random noise will eventually
    land in the printable ASCII range purely by chance — that's
    symbol-heavy garbage, not language. Require real text to be both
    reasonably long AND mostly letters/spaces (not symbols) before it
    counts as a signal.
    """
    if any(marker in s for marker in ZSTEG_FLAG_MARKERS):
        return True
    if len(s) < ZSTEG_MIN_TEXT_LEN:
        return False
    letters_and_spaces = sum(1 for ch in s if ch.isalpha() or ch == " ")
    return (letters_and_spaces / len(s)) >= ZSTEG_MIN_LETTER_RATIO


def filter_zsteg_signal(zsteg_lines):
    """
    zsteg tries every bit-plane / channel / byte-order combination and
    reports a 'text:' hit whenever the extracted bytes happen to land
    in the printable ASCII range — which happens by pure chance on
    almost any real photo, completely unrelated to hidden data. Only
    count it as a real signal when zsteg finds an embedded file
    signature ('file:') or a hit that actually looks like language;
    a short run of random printable symbols is expected noise, not
    evidence, however many combinations zsteg happens to try.
    """
    meaningful = []
    for line in zsteg_lines:
        if "file:" in line:
            meaningful.append(line)
            continue
        m = re.search(r'text:\s*"([^"]*)"', line)
        if m and _looks_like_real_text(m.group(1)):
            meaningful.append(line)
    return meaningful


# ==========================================================================
# REPORT AND VERDICT
# ==========================================================================

def build_report(path, wordlist=None, bitplanes=False, bitplanes_dir="."):
    path = Path(path)
    report = {"file": str(path)}

    info("Hashes...")
    report["hashes"] = compute_hashes(path)

    info("Magic signature vs. extension...")
    report["magic"] = check_magic_mismatch(path)

    info("Trailing data after EOF...")
    report["trailing"] = check_trailing_data(path)

    info("Polyglot detection (appended ZIP)...")
    report["polyglot"] = check_polyglot_zip(path)

    info("PNG chunks...")
    report["png_chunks"] = parse_png_chunks(path)

    info("Metadata (exiftool)...")
    report["metadata"] = check_metadata(path)

    info("Embedded files/signatures (binwalk)...")
    report["embedded"] = check_embedded_files(path)

    info("Printable strings...")
    report["strings"] = check_strings(path)

    info("QR / barcodes...")
    report["qr"] = check_qr(path)
    if not PYZBAR:
        warn("pyzbar not installed — skipping QR detection (pip install pyzbar; sudo apt install libzbar0)")

    info("Custom LSB heuristic...")
    report["lsb_bias"] = check_lsb_bias(path)

    info("zsteg (PNG/BMP)...")
    report["zsteg"] = check_zsteg(path)

    info("steghide extraction attempt (empty passphrase)...")
    report["steghide_empty"] = try_steghide_extract(path, "")

    info("outguess extraction attempt (JPEG)...")
    report["outguess"] = try_outguess(path)

    if wordlist:
        info(f"steghide brute force with {wordlist} (may take a while)...")
        report["steghide_crack"] = crack_steghide(path, wordlist)

    if bitplanes:
        info("Extracting visual bit planes...")
        report["bitplanes_files"] = extract_bitplanes(path, bitplanes_dir)

    report["verdict"] = build_verdict(report)
    return report


def build_verdict(report):
    signals = []

    if report.get("magic", {}).get("mismatch"):
        signals.append("File extension does not match its real format")
    if report.get("trailing", {}).get("found"):
        signals.append(f"{report['trailing']['extra_bytes']} extra bytes found after the official EOF marker")
    if report.get("polyglot", {}).get("is_zip_polyglot"):
        signals.append("The file is also a valid ZIP (polyglot)")
    if report.get("png_chunks"):
        non_std = [c for c in report["png_chunks"] if not c["standard"]]
        if non_std:
            signals.append(f"{len(non_std)} non-standard PNG chunk(s)")
        text_chunks = [c for c in report["png_chunks"] if "text" in c]
        if text_chunks:
            signals.append(f"{len(text_chunks)} PNG text chunk(s) with content")
    embedded_meaningful = filter_binwalk_signal(report.get("embedded") or [])
    if embedded_meaningful:
        signals.append(f"binwalk found {len(embedded_meaningful)} embedded signature(s) beyond the normal PNG/JPEG container")
    if report.get("qr"):
        signals.append(f"{len(report['qr'])} QR/barcode(s) detected")
    if report.get("lsb_bias", {}).get("suspicious"):
        signals.append("Suspicious LSB bias (possible LSB steganography)")
    zsteg_meaningful = filter_zsteg_signal(report.get("zsteg") or [])
    if zsteg_meaningful:
        signals.append(f"zsteg found {len(zsteg_meaningful)} pattern(s) beyond expected noise")
    if report.get("steghide_empty"):
        signals.append("steghide extracted data with an empty passphrase")
    if report.get("outguess"):
        signals.append("outguess extracted data")
    if report.get("steghide_crack") and "found" in (report["steghide_crack"] or "").lower():
        signals.append("stegseek found the passphrase")

    n = len(signals)
    if n == 0:
        level = "NO INDICATORS"
    elif n <= 2:
        level = "SLIGHTLY SUSPICIOUS"
    else:
        level = "HIGHLY SUSPICIOUS"

    return {"level": level, "signals": signals}


def print_report(report):
    if RICH:
        console.rule(f"[bold]Report — {report['file']}[/bold]")
    else:
        print(f"\n=== Report — {report['file']} ===\n")

    h = report["hashes"]
    print(f"    MD5: {h['md5']}")
    print(f"    SHA256: {h['sha256']}")

    m = report["magic"]
    if m["mismatch"]:
        warn(f"MISMATCH: extension '.{m['declared_extension']}' but real format is '{m['detected_format']}'")
    else:
        ok(f"Extension matches the format ({m['detected_format']})")

    t = report.get("trailing")
    if t and t.get("found"):
        warn(f"{t['extra_bytes']} bytes found after EOF at offset {t['offset']}")
        print(f"    ASCII preview: {t['preview_ascii']}")
    elif t is not None:
        ok("No trailing data found after EOF")

    p = report["polyglot"]
    if p["is_zip_polyglot"]:
        warn(f"This is also a valid ZIP! Contents: {p['contents']}")

    chunks = report.get("png_chunks")
    if chunks:
        non_std = [c for c in chunks if not c["standard"]]
        text_chunks = [c for c in chunks if "text" in c]
        ok(f"{len(chunks)} PNG chunks analyzed")
        if non_std:
            warn(f"Non-standard chunks: {[c['type'] for c in non_std]}")
        for c in text_chunks:
            print(f"    [{c['type']}] {c['text']}")

    if report["metadata"]:
        ok(f"{len(report['metadata'])} metadata fields")
        for k, v in list(report["metadata"].items())[:12]:
            print(f"    {k}: {v}")
    else:
        warn("No relevant metadata")

    if report["embedded"]:
        meaningful_count = len(filter_binwalk_signal(report["embedded"]))
        ok(f"{len(report['embedded'])} raw binwalk match(es) ({meaningful_count} beyond the normal PNG/JPEG container)")
        for line in report["embedded"][:10]:
            print(f"    {line}")

    if report["strings"]:
        ok(f"{len(report['strings'])} interesting string(s)")
        for s in report["strings"][:10]:
            print(f"    {s}")

    if report.get("qr"):
        ok(f"{len(report['qr'])} QR/barcode(s) found")
        for q in report["qr"]:
            print(f"    [{q['type']}] {q['data']}")

    lsb = report["lsb_bias"]
    if lsb:
        msg = f"LSB bias (R={lsb['channel_R_ratio_1s']}, G={lsb['channel_G_ratio_1s']}, B={lsb['channel_B_ratio_1s']})"
        (warn if lsb["suspicious"] else ok)(msg)

    if report.get("zsteg"):
        meaningful_count = len(filter_zsteg_signal(report["zsteg"]))
        ok(f"{len(report['zsteg'])} raw zsteg line(s) ({meaningful_count} beyond expected noise)")
        for line in report["zsteg"][:10]:
            print(f"    {line}")

    if report.get("steghide_empty"):
        ok(f"steghide (empty passphrase): {report['steghide_empty']}")

    if report.get("outguess"):
        ok(f"outguess extracted data (hex): {report['outguess'][:60]}...")

    if report.get("steghide_crack"):
        ok(f"stegseek: {report['steghide_crack']}")

    if report.get("bitplanes_files"):
        ok(f"Bit planes generated: {report['bitplanes_files']}")

    v = report["verdict"]
    print()
    if RICH:
        console.rule(f"[bold]VERDICT: {v['level']}[/bold]")
    else:
        print(f"=== VERDICT: {v['level']} ===")
    for s in v["signals"]:
        print(f"    - {s}")
    if not v["signals"]:
        print("    No signs of steganography or hidden data detected.")


def main():
    parser = argparse.ArgumentParser(
        description="Image forensics tool: format, metadata, steganography and an aggregated verdict in one pass."
    )
    parser.add_argument("image", help="Path to the image (or file) to analyze")
    parser.add_argument("-w", "--wordlist", help="Wordlist for steghide brute force (e.g. rockyou.txt)")
    parser.add_argument("-o", "--output", help="Save the full report as JSON")
    parser.add_argument("-b", "--bitplanes", action="store_true", help="Generate bit-plane images (like Stegsolve)")
    parser.add_argument("--bitplanes-dir", default=".", help="Directory to save bit planes in (default: .)")
    args = parser.parse_args()

    image_path = Path(args.image)
    if not image_path.exists():
        print(f"[!] File not found: {image_path}", file=sys.stderr)
        sys.exit(1)

    report = build_report(
        image_path,
        wordlist=args.wordlist,
        bitplanes=args.bitplanes,
        bitplanes_dir=args.bitplanes_dir,
    )
    print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        ok(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
