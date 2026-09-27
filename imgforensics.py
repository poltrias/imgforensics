#!/usr/bin/env python3
"""
imgforensics.py — eina de forense d'imatges tot-en-un per CTF/pentesting.

No es limita a encadenar exiftool/binwalk/steghide: fa comprovacions
propies (parsing de format, deteccio de polyglots, extraccio visual de
bit-planes...) que cap eina individual et dona sola, i acaba amb un
veredicte agregat perque no calgui llegir 8 blocs de sortida per decidir
si val la pena seguir investigant una imatge.

Comprovacions:
  Nivell fitxer:
    - Hashes (MD5/SHA1/SHA256)
    - Signatura magica real vs extensio declarada
    - Dades sobrants despres del marcador de fi de fitxer (EOF trailing data)
    - Deteccio de polyglot (fitxer ZIP/altres valid amagat dins la imatge)
  Nivell format:
    - Chunks de PNG (tEXt/zTXt/iTXt/eXIf i chunks no estandard)
    - Metadades EXIF/XMP/IPTC (exiftool)
    - Fitxers/signatures incrustats (binwalk)
  Nivell contingut:
    - Cadenes de text imprimibles interessants
    - Codis QR / codis de barres incrustats (pyzbar, opcional)
    - Heuristica LSB propia (biaix estadistic, sense dependencies)
    - Extraccio visual de bit-planes (com fa Stegsolve, en local)
    - zsteg (PNG/BMP)
  Esteganografia amb contrasenya:
    - steghide (JPEG/BMP/WAV/AU) — extraccio buida + forca bruta (stegseek)
    - outguess (JPEG) — extraccio buida

Autor: Pol Trias
"""

import argparse
import hashlib
import json
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


# ---------- sortida ----------

def info(msg):
    console.print(f"[bold cyan][*][/bold cyan] {msg}") if RICH else print(f"[*] {msg}")


def warn(msg):
    console.print(f"[bold yellow][!][/bold yellow] {msg}") if RICH else print(f"[!] {msg}")


def ok(msg):
    console.print(f"[bold green][+][/bold green] {msg}") if RICH else print(f"[+] {msg}")


# ---------- utilitats ----------

def tool_available(name):
    return shutil.which(name) is not None


def run(cmd, timeout=60):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return None, f"{cmd[0]} no trobat"
    except subprocess.TimeoutExpired:
        return None, f"{cmd[0]} ha superat el temps limit"


# ==========================================================================
# NIVELL FITXER — comprovacions que no depenen de cap eina externa
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

# Marcadors de fi de format coneguts, per detectar dades sobrants (trailing data)
EOF_MARKERS = {
    "jpg": b"\xff\xd9",
    "jpeg": b"\xff\xd9",
    "png": b"IEND\xaeB`\x82",
    "gif": b"\x3b",  # trailer GIF (un sol byte, menys fiable)
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
    """Compara la signatura magica real amb l'extensio declarada del fitxer."""
    with open(path, "rb") as f:
        header = f.read(16)

    detected = None
    for sig, fmt in MAGIC_SIGNATURES.items():
        if header.startswith(sig):
            detected = fmt
            break

    ext = path.suffix.lower().lstrip(".")
    mismatch = detected is not None and ext not in detected.split("/")
    return {"extensio_declarada": ext or "(cap)", "format_detectat": detected or "desconegut", "mismatch": mismatch}


def check_trailing_data(path):
    """
    Busca dades despres del marcador oficial de fi de format. Es un dels
    trucs mes classics de CTF: amagar un ZIP, un text o un altre fitxer
    just despres del EOF que els visors d'imatges ignoren.
    """
    ext = path.suffix.lower().lstrip(".")
    marker = EOF_MARKERS.get(ext)
    if not marker:
        return None

    data = path.read_bytes()
    idx = data.rfind(marker)
    if idx == -1:
        return {"trobat": False}

    end_of_official_data = idx + len(marker)
    trailing = data[end_of_official_data:]
    if not trailing:
        return {"trobat": False}

    return {
        "trobat": True,
        "bytes_sobrants": len(trailing),
        "offset": end_of_official_data,
        "preview_hex": trailing[:32].hex(),
        "preview_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in trailing[:64]),
    }


def check_polyglot_zip(path):
    """
    zipfile.is_zipfile() busca el 'end of central directory' des del final
    del fitxer cap enrere, aixi que detecta un ZIP annexat encara que el
    fitxer comenci amb dades d'imatge vàlides (el clàssic polyglot PNG+ZIP
    o JPEG+ZIP).
    """
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
            return {"es_polyglot_zip": True, "contingut": names[:30]}
    except (zipfile.BadZipFile, OSError):
        pass
    return {"es_polyglot_zip": False}


# ==========================================================================
# NIVELL FORMAT — parsing propi del contenidor
# ==========================================================================

PNG_STANDARD_CHUNKS = {
    "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP",
    "sBIT", "sRGB", "bKGD", "hIST", "pHYs", "sPLT", "tIME",
}
PNG_TEXT_CHUNKS = {"tEXt", "zTXt", "iTXt"}


def parse_png_chunks(path):
    """
    Parseja manualment l'estructura de chunks d'un PNG (sense libpng):
    length(4) + type(4) + data(length) + crc(4), repetit. Flag qualsevol
    chunk no estandard i mostra el contingut dels chunks de text, que
    sovint s'utilitzen per amagar missatges.
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

        offset += 8 + length + 4  # salta data + CRC
        if ctype == "IEND":
            break

    return chunks


# ==========================================================================
# EINES EXTERNES — wrappers amb degradacio elegant si no estan instal·lades
# ==========================================================================

def check_metadata(path):
    if not tool_available("exiftool"):
        warn("exiftool no instal·lat — salto metadades (sudo apt install libimage-exiftool-perl)")
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
        warn("binwalk no instal·lat — salto deteccio de fitxers incrustats (sudo apt install binwalk)")
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
        warn("zsteg no instal·lat — salto (sudo gem install zsteg)")
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
        warn("stegseek no instal·lat — salto forca bruta (sudo apt install stegseek)")
        return None
    if not wordlist or not Path(wordlist).exists():
        warn(f"Wordlist no trobada ({wordlist}) — salto forca bruta")
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
# HEURISTICA LSB PROPIA + EXTRACCIO VISUAL DE BIT-PLANES
# ==========================================================================

def check_lsb_bias(path):
    """
    Sense dependre de cap eina externa: comprova si el bit menys
    significatiu de cada canal de color s'allunya massa d'una
    distribucio ~50/50, senyal tipic d'esteganografia LSB ingenua
    (les dades incrustades tendeixen a semblar soroll aleatori).
    """
    if Image is None:
        warn("Pillow no instal·lat — salto analisi LSB (pip install Pillow)")
        return None
    try:
        img = Image.open(path).convert("RGB")
    except Exception as e:
        warn(f"No s'ha pogut obrir la imatge amb Pillow: {e}")
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
        "canal_R_ratio_1s": round(ratios[0], 4),
        "canal_G_ratio_1s": round(ratios[1], 4),
        "canal_B_ratio_1s": round(ratios[2], 4),
        "sospitos": suspicious,
    }


def extract_bitplanes(path, outdir, max_dim=512):
    """
    Genera, per cada canal RGB, una imatge amb els 8 bit-planes en graella
    (com fa Stegsolve). Un missatge LSB sovint es fa visible a ull nu
    al bit-plane 0 (el menys significatiu) com a soroll estructurat.
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
        # graella 4x2 amb els 8 bits (7=MSB ... 0=LSB), a dalt a l'esquerra el LSB
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
# INFORME I VEREDICTE
# ==========================================================================

def build_report(path, wordlist=None, bitplanes=False, bitplanes_dir="."):
    path = Path(path)
    report = {"file": str(path)}

    info("Hashes...")
    report["hashes"] = compute_hashes(path)

    info("Signatura magica vs extensio...")
    report["magic"] = check_magic_mismatch(path)

    info("Dades sobrants despres del EOF (trailing data)...")
    report["trailing"] = check_trailing_data(path)

    info("Deteccio de polyglot (ZIP annexat)...")
    report["polyglot"] = check_polyglot_zip(path)

    info("Chunks PNG...")
    report["png_chunks"] = parse_png_chunks(path)

    info("Metadades (exiftool)...")
    report["metadata"] = check_metadata(path)

    info("Fitxers/signatures incrustats (binwalk)...")
    report["embedded"] = check_embedded_files(path)

    info("Cadenes de text imprimibles...")
    report["strings"] = check_strings(path)

    info("Codis QR / de barres...")
    report["qr"] = check_qr(path)
    if not PYZBAR:
        warn("pyzbar no instal·lat — salto deteccio de QR (pip install pyzbar; sudo apt install libzbar0)")

    info("Heuristica LSB propia...")
    report["lsb_bias"] = check_lsb_bias(path)

    info("zsteg (PNG/BMP)...")
    report["zsteg"] = check_zsteg(path)

    info("Intent d'extraccio steghide (sense contrasenya)...")
    report["steghide_empty"] = try_steghide_extract(path, "")

    info("Intent d'extraccio outguess (JPEG)...")
    report["outguess"] = try_outguess(path)

    if wordlist:
        info(f"Forca bruta de steghide amb {wordlist} (pot trigar)...")
        report["steghide_crack"] = crack_steghide(path, wordlist)

    if bitplanes:
        info("Extraient bit-planes visuals...")
        report["bitplanes_files"] = extract_bitplanes(path, bitplanes_dir)

    report["verdict"] = build_verdict(report)
    return report


def build_verdict(report):
    signals = []

    if report.get("magic", {}).get("mismatch"):
        signals.append("L'extensio del fitxer no coincideix amb el seu format real")
    if report.get("trailing", {}).get("trobat"):
        signals.append(f"{report['trailing']['bytes_sobrants']} bytes sobrants despres del EOF oficial")
    if report.get("polyglot", {}).get("es_polyglot_zip"):
        signals.append("El fitxer tambe es un ZIP valid (polyglot)")
    if report.get("png_chunks"):
        non_std = [c for c in report["png_chunks"] if not c["standard"]]
        if non_std:
            signals.append(f"{len(non_std)} chunks PNG no estandard")
        text_chunks = [c for c in report["png_chunks"] if "text" in c]
        if text_chunks:
            signals.append(f"{len(text_chunks)} chunks de text PNG amb contingut")
    if report.get("embedded"):
        signals.append(f"binwalk ha trobat {len(report['embedded'])} signatures incrustades")
    if report.get("qr"):
        signals.append(f"{len(report['qr'])} codi(s) QR/barres detectats")
    if report.get("lsb_bias", {}).get("sospitos"):
        signals.append("Biaix LSB sospitos (possible esteganografia LSB)")
    if report.get("zsteg"):
        signals.append("zsteg ha trobat patrons")
    if report.get("steghide_empty"):
        signals.append("steghide ha extret dades amb contrasenya buida")
    if report.get("outguess"):
        signals.append("outguess ha extret dades")
    if report.get("steghide_crack") and "found" in (report["steghide_crack"] or "").lower():
        signals.append("stegseek ha trobat la contrasenya")

    n = len(signals)
    if n == 0:
        level = "SENSE INDICIS"
    elif n <= 2:
        level = "LLEUGERAMENT SOSPITOS"
    else:
        level = "ALTAMENT SOSPITOS"

    return {"nivell": level, "senyals": signals}


def print_report(report):
    if RICH:
        console.rule(f"[bold]Informe — {report['file']}[/bold]")
    else:
        print(f"\n=== Informe — {report['file']} ===\n")

    h = report["hashes"]
    print(f"    MD5: {h['md5']}")
    print(f"    SHA256: {h['sha256']}")

    m = report["magic"]
    if m["mismatch"]:
        warn(f"MISMATCH: extensio '.{m['extensio_declarada']}' pero format real es '{m['format_detectat']}'")
    else:
        ok(f"Extensio coherent amb el format ({m['format_detectat']})")

    t = report.get("trailing")
    if t and t.get("trobat"):
        warn(f"{t['bytes_sobrants']} bytes despres del EOF a l'offset {t['offset']}")
        print(f"    ASCII preview: {t['preview_ascii']}")
    elif t is not None:
        ok("Sense dades sobrants despres del EOF")

    p = report["polyglot"]
    if p["es_polyglot_zip"]:
        warn(f"Es un ZIP valid! Contingut: {p['contingut']}")

    chunks = report.get("png_chunks")
    if chunks:
        non_std = [c for c in chunks if not c["standard"]]
        text_chunks = [c for c in chunks if "text" in c]
        ok(f"{len(chunks)} chunks PNG analitzats")
        if non_std:
            warn(f"Chunks no estandard: {[c['type'] for c in non_std]}")
        for c in text_chunks:
            print(f"    [{c['type']}] {c['text']}")

    if report["metadata"]:
        ok(f"{len(report['metadata'])} camps de metadades")
        for k, v in list(report["metadata"].items())[:12]:
            print(f"    {k}: {v}")
    else:
        warn("Sense metadades rellevants")

    if report["embedded"]:
        ok(f"{len(report['embedded'])} signatures incrustades (binwalk)")
        for line in report["embedded"][:10]:
            print(f"    {line}")

    if report["strings"]:
        ok(f"{len(report['strings'])} cadenes interessants")
        for s in report["strings"][:10]:
            print(f"    {s}")

    if report.get("qr"):
        ok(f"{len(report['qr'])} codi(s) QR/barres trobats")
        for q in report["qr"]:
            print(f"    [{q['type']}] {q['data']}")

    lsb = report["lsb_bias"]
    if lsb:
        msg = f"Biaix LSB (R={lsb['canal_R_ratio_1s']}, G={lsb['canal_G_ratio_1s']}, B={lsb['canal_B_ratio_1s']})"
        (warn if lsb["sospitos"] else ok)(msg)

    if report.get("zsteg"):
        ok("zsteg ha trobat patrons")
        for line in report["zsteg"][:10]:
            print(f"    {line}")

    if report.get("steghide_empty"):
        ok(f"steghide (contrasenya buida): {report['steghide_empty']}")

    if report.get("outguess"):
        ok(f"outguess ha extret dades (hex): {report['outguess'][:60]}...")

    if report.get("steghide_crack"):
        ok(f"stegseek: {report['steghide_crack']}")

    if report.get("bitplanes_files"):
        ok(f"Bit-planes generats: {report['bitplanes_files']}")

    v = report["verdict"]
    print()
    if RICH:
        console.rule(f"[bold]VEREDICTE: {v['nivell']}[/bold]")
    else:
        print(f"=== VEREDICTE: {v['nivell']} ===")
    for s in v["senyals"]:
        print(f"    - {s}")
    if not v["senyals"]:
        print("    Cap senyal d'esteganografia o dades amagades detectat.")


def main():
    parser = argparse.ArgumentParser(
        description="Eina de forense d'imatges: format, metadades, esteganografia i veredicte agregat en un sol pas."
    )
    parser.add_argument("image", help="Ruta a la imatge (o fitxer) a analitzar")
    parser.add_argument("-w", "--wordlist", help="Wordlist per forca bruta de steghide (ex: rockyou.txt)")
    parser.add_argument("-o", "--output", help="Desa l'informe complet en JSON")
    parser.add_argument("-b", "--bitplanes", action="store_true", help="Genera imatges de bit-planes (com Stegsolve)")
    parser.add_argument("--bitplanes-dir", default=".", help="Directori on desar els bit-planes (per defecte: .)")
    args = parser.parse_args()

    image_path = Path(args.image)
    if not image_path.exists():
        print(f"[!] Fitxer no trobat: {image_path}", file=sys.stderr)
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
        ok(f"Informe desat a {args.output}")


if __name__ == "__main__":
    main()
