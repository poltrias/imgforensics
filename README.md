# imgforensics

All-in-one image forensics tool for CTF and pentesting. It doesn't just
chain `exiftool`, `binwalk` and `steghide`: it adds its own file-format
and container-structure checks that no single existing tool gives you
on its own, and ends with an **aggregated verdict** so you don't have
to read through 8 separate blocks of output to decide whether an
image is worth investigating further.

## What it checks

**File level** (own implementation, no external dependencies)
- MD5/SHA1/SHA256 hashes
- Real magic signature vs. declared file extension (catches renamed files)
- Trailing data after the official end-of-file marker (*trailing
  data* — one of the most classic CTF tricks)
- **Polyglot detection**: a valid ZIP (or other format) appended
  inside the image, even if the viewer only ever sees the image part

**Format level**
- Manual **PNG chunk** parsing — flags non-standard chunks and shows
  the content of `tEXt`/`zTXt`/`iTXt` chunks, where messages are often
  hidden directly in the container
- EXIF/XMP/IPTC metadata (`exiftool`)
- Embedded files/signatures (`binwalk`)

**Content level**
- Interesting printable strings (flags, URLs, SSH keys...)
- Embedded QR codes / barcodes (`pyzbar`, optional)
- **Custom LSB heuristic**: statistical bias of the least significant
  bit of each color channel, with no external tool dependency
- **Visual bit-plane extraction** (Stegsolve-style): generates one
  image per channel with all 8 bit planes in a grid — a hidden LSB
  message that doesn't skew the image enough to trip the statistical
  heuristic is often **visible to the naked eye** as structured noise
  on plane 0
- `zsteg` (PNG/BMP-specific LSB analysis)

**Passphrase-based steganography**
- `steghide` (JPEG/BMP/WAV/AU) — empty-passphrase extraction
- `outguess` (JPEG) — empty-passphrase extraction
- `stegseek` — steghide passphrase brute force with a wordlist

Every check is independent: if a tool isn't installed, it warns you
and keeps going with the rest instead of crashing.

## Why this isn't just a wrapper

`exiftool`, `binwalk` and `steghide` each do one thing. This tool adds
the part none of them does alone:

- PNG chunk parsing and polyglot detection are original implementations
  working directly on the binary structure of the format, not calls to
  another tool.
- Trailing-data detection and the magic-signature mismatch check cover
  a case — very common in CTF — that `exiftool` and `binwalk` alone
  don't always make obvious: a renamed file, or one with data appended
  after it.
- The **final verdict** combines every signal (mismatch, trailing
  data, polyglot, non-standard chunks, LSB bias, QR found...) into a
  single suspicion level, instead of leaving you to interpret 8
  separate outputs.

## Installation (Kali Linux)

```bash
# System tools
sudo apt update
sudo apt install -y libimage-exiftool-perl binwalk steghide stegseek \
    ruby ruby-dev libzbar0

# zsteg (Ruby gem)
sudo gem install zsteg

# Python dependencies
pip install -r requirements.txt --break-system-packages
```

`outguess` has been dropped from recent Kali/Debian repos. It's
optional — the tool already skips it gracefully if it's missing. If
you want it anyway, build it from source:

```bash
git clone https://github.com/crorvick/outguess.git
cd outguess && ./configure && make && sudo make install
```

If `stegseek` isn't in your repos either, build it from
[github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek).

## Usage

```bash
# Full analysis
python3 imgforensics.py image.png

# With visual bit-plane extraction
python3 imgforensics.py image.png -b

# With steghide brute force and a JSON report
python3 imgforensics.py image.jpg -w /usr/share/wordlists/rockyou.txt -o report.json
```

## Example verdict
