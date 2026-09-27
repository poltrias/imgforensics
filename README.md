# imgforensics

Eina de forense d'imatges tot-en-un per CTF i pentesting. No es limita a
encadenar `exiftool`, `binwalk` i `steghide`: fa comprovacions pròpies de
format i estructura de fitxer que cap eina individual dona per separat, i
acaba amb un **veredicte agregat** perquè no calgui llegir 8 blocs de
sortida per decidir si val la pena seguir investigant una imatge.

## Què comprova

**Nivell fitxer** (implementació pròpia, sense dependències externes)
- Hashes MD5/SHA1/SHA256
- Signatura màgica real vs. extensió declarada (detecta fitxers renombrats)
- Dades sobrants després del marcador oficial de fi de fitxer (*trailing
  data* — un dels trucs més clàssics de CTF)
- Detecció de **polyglots**: un ZIP (o un altre format) vàlid annexat
  dins la imatge, encara que el visor només vegi la part d'imatge

**Nivell format**
- Parsing manual dels **chunks de PNG** — detecta chunks no estàndard i
  mostra el contingut de `tEXt`/`zTXt`/`iTXt`, on sovint s'amaguen
  missatges directament al contenidor
- Metadades EXIF/XMP/IPTC (`exiftool`)
- Fitxers/signatures incrustats (`binwalk`)

**Nivell contingut**
- Cadenes de text imprimibles interessants (flags, URLs, claus SSH...)
- Codis QR / de barres incrustats (`pyzbar`, opcional)
- **Heurística LSB pròpia**: biaix estadístic del bit menys significatiu
  de cada canal de color, sense dependre de cap eina externa
- **Extracció visual de bit-planes** (a l'estil Stegsolve): genera una
  imatge per canal amb els 8 plans de bits en graella — un missatge LSB
  que no altera prou la imatge per disparar l'heurística estadística
  sovint **es veu a ull nu** com a soroll estructurat al pla 0
- `zsteg` (LSB específic per PNG/BMP)

**Esteganografia amb contrasenya**
- `steghide` (JPEG/BMP/WAV/AU) — extracció amb contrasenya buida
- `outguess` (JPEG) — extracció amb contrasenya buida
- `stegseek` — força bruta de la contrasenya de steghide amb wordlist

Cada comprovació és independent: si no tens una eina instal·lada,
l'eina t'ho avisa i continua amb la resta en lloc de petar.

## Per què no és només un wrapper

`exiftool`, `binwalk` i `steghide` fan una cosa cadascun. Aquesta eina
afegeix la part que no fa cap d'ells sol:

- El parsing de chunks PNG i la detecció de polyglots són implementació
  pròpia sobre l'estructura binària del format, no una crida a una altra
  eina.
- La detecció de *trailing data* i el mismatch de signatura màgica
  cobreixen el cas — molt habitual en CTF — d'un fitxer renombrat o amb
  dades annexades que `exiftool` i `binwalk` per si sols no sempre
  deixen clar.
- El **veredicte final** combina tots els senyals (mismatch, trailing
  data, polyglot, chunks no estàndard, biaix LSB, QR trobat...) en un
  sol nivell de sospita, en lloc de deixar-te interpretar 8 sortides
  soltes.

## Instal·lació (Kali Linux)

```bash
# Eines de sistema
sudo apt update
sudo apt install -y libimage-exiftool-perl binwalk steghide stegseek \
    outguess ruby ruby-dev libzbar0

# zsteg (gem de Ruby)
sudo gem install zsteg

# Dependències de Python
pip install -r requirements.txt --break-system-packages
```

Si `stegseek` no està als repositoris, es pot compilar des de
[github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek).

## Ús

```bash
# Analisi completa
python3 imgforensics.py imatge.png

# Amb extraccio de bit-planes visuals
python3 imgforensics.py imatge.png -b

# Amb forca bruta de steghide i informe JSON
python3 imgforensics.py imatge.jpg -w /usr/share/wordlists/rockyou.txt -o informe.json
```

## Exemple de veredicte

```
=== VEREDICTE: ALTAMENT SOSPITOS ===
    - 151 bytes sobrants despres del EOF oficial
    - El fitxer tambe es un ZIP valid (polyglot)
    - 1 chunks de text PNG amb contingut
```

## Per fer

- [ ] Extracció automàtica dels fitxers que detecta `binwalk` (`-e`)
- [ ] Mode `--batch` per analitzar un directori sencer
- [ ] Suport per GIF animat (LSB distribuït entre frames)
