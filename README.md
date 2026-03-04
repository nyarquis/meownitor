# Meownitor

A static analysis toolkit for detecting malicious indicators in PDF files. Meownitor performs metadata inspection, keyword scanning, JavaScript analysis, IOC extraction, exploit signature detection, VirusTotal hash lookup, and weighted risk scoring — all without executing the file.

---

## Features

- **File Hashing** — MD5, SHA1, and SHA256 digests
- **VirusTotal Lookup** — queries the VirusTotal API v3 by SHA256 hash and reports engine detections
- **Metadata Extraction** — reads author, creation date, producer, and creator fields via `pikepdf`, with `pdfminer` as a fallback; flags anomalies such as blank authors or automated-tool producer strings
- **Object Enumeration** — counts total objects, streams, embedded files, and suspicious objects
- **Keyword Scanning** — checks for 25 suspicious PDF keywords across three severity tiers (High, Medium, Low)
- **JavaScript Analysis** — extracts embedded `/JS` streams and scans for 12 obfuscation patterns including `eval()`, `unescape()`, `String.fromCharCode`, hex encoding, and Base64
- **IOC Extraction** — regex-based extraction of URLs, IP addresses, email addresses, and domains
- **Exploit Detection** — matches against 5 known CVE signatures and 2 binary signatures (NOP sled shellcode, PE header)
- **Risk Scoring** — weighted scoring system producing a 0–100 score with a CLEAN / LOW / MEDIUM / HIGH / CRITICAL verdict
- **Report Generation** — structured plain-text report saved as a `.txt` file alongside the input PDF

---

## Requirements

Python 3.10 or newer.

```
pip install pikepdf pdfminer.six
```

All other dependencies (`hashlib`, `re`, `urllib`, `json`, `argparse`, `pathlib`) are part of the Python standard library.

---

## VirusTotal API Key

Meownitor uses the [VirusTotal Public API v3](https://developers.virustotal.com/reference/overview). A free API key is available at [virustotal.com](https://www.virustotal.com).

Replace the placeholder on line 17 of `main.py` with your key:

```python
VIRUSTOTAL_API_KEY = "your_api_key_here"
```

If the key is missing, invalid, or the request fails for any reason, Meownitor prints a warning and continues — the rest of the analysis is unaffected.

---

## Usage

```
python main.py <path_to_pdf>
```

The report is printed to stdout and saved as a `.txt` file in the same directory.

### Example

```
python main.py suspicious.pdf
```

Output file: `suspicious.txt`

---

## Report Structure

```
================================
   MALWARE REPORT
================================

   FILE NAME       : suspicious.pdf
   TIME STAMP      : 2026-03-04 11:30:00
   SIZE (IN BYTES) : 1,449

-- FILE HASHES -----------------
-- VIRUSTOTAL ------------------
-- RISK SCORE ------------------
-- METADATA --------------------
-- OBJECT ENUMERATION ----------
-- SUSPICIOUS KEYWORDS ---------
-- JAVASCRIPT ANALYSIS ---------
-- INDICATORS OF COMPROMISE ----
-- EXPLOIT DETECTION -----------
-- MITIGATION RECOMMENDATIONS --
```

---

## Risk Scoring

Each detected indicator contributes a weighted score, capped at 100.

| Indicator | Weight |
|---|---|
| Shell Code or PE Header | 40 |
| Known Exploit (CVE match) | 30 |
| High Severity Keyword | 20 |
| `/OpenAction` keyword | 18 |
| JavaScript Obfuscation Pattern | 15 |
| Encrypted Stream | 12 |
| Indicator of Compromise URL | 10 |
| Medium Severity Keyword | 8 |
| Indicator of Compromise IP | 8 |
| Suspicious Metadata | 5 |
| Low Severity Keyword | 2 |

| Score | Verdict |
|---|---|
| 75 – 100 | CRITICAL |
| 50 – 74 | HIGH |
| 25 – 49 | MEDIUM |
| 1 – 24 | LOW |
| 0 | CLEAN |

---

## Keyword Reference

**High** — `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA`, `/Encrypt`, `/AcroForm`

**Medium** — `/URI`, `/SubmitForm`, `/GoToR`, `/Sound`, `/Movie`, `/ImportData`, `/Hide`, `/ObjStm`, `/JBIG2Decode`, `/ASCIIHexDecode`

**Low** — `/Author`, `/Producer`, `/Creator`, `/FlateDecode`, `/LZWDecode`

---

## CVE Signatures

| CVE | Pattern |
|---|---|
| CVE-2010-0188 | TIFF Image Exploit (LibTIFF) |
| CVE-2008-2992 | `util.printf()` Heap Spray |
| CVE-2007-5659 | `collectEmailInfo()` Buffer Overflow |
| CVE-2009-0927 | `getIcon()` Stack Overflow |
| CVE-2010-1240 | `app.openDoc()` Launch Action |

---

## Disclaimer

Meownitor is intended for educational and defensive security purposes only. Only analyse files you own or have explicit permission to analyse. Never execute suspicious PDFs on a production system — use an isolated environment.