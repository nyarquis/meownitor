#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import pdfminer.high_level
import pdfminer.pdfdocument
import pdfminer.pdfparser
import pikepdf
import re
import sys
import urllib.request

VIRUSTOTAL_API_KEY   = "PLACEHOLDER"
WEIGHTS              = {
    "High Severity Keyword"       : 20,
    "Medium Severity Keyword"     : 8, 
    "Low Severity Keyword"        : 2, 
    "JavaScript Obfuscation"      : 15, 
    "Known Exploit"               : 30, 
    "Shell Code or PE"            : 40, 
    "Indicator of Compromise URL" : 10, 
    "Indicator of Compromise IP"  : 8, 
    "Encrypted Stream"            : 12, 
    "Suspicious Metadata"         : 5, 
    "OpenAction"                  : 18,
}
SUSPICIOUS_KEYWORDS  = {
    "High"   : [
        "/JavaScript",
        "/JS",
        "/OpenAction",
        "/AA",
        "/Launch",
        "/EmbeddedFile",
        "/RichMedia",
        "/XFA",
        "/Encrypt",
        "/AcroForm",
    ],
    "Medium" : [
        "/URI",
        "/SubmitForm",
        "/GoToR",
        "/Sound",
        "/Movie",
        "/ImportData",
        "/Hide",
        "/ObjStm",
        "/JBIG2Decode",
        "/ASCIIHexDecode",
    ],
    "Low"    : [
        "/Author",
        "/Producer",
        "/Creator",
        "/FlateDecode",
        "/LZWDecode",
    ],
}
COMPROMISE_PATTERNS  = {
    "URL"     : r'https?://[^\s\'"<>]{4,}',
    "IP ADDR" : r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "EMAIL"   : r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "DOMAIN"  : r'(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|xyz|top|tk|cc|ru|cn|pw)\b',
}
KNOWN_EXPLOITS       = {
    "CVE-2010-0188" : re.compile(r'TIFF|tiff.*image', re.IGNORECASE),
    "CVE-2008-2992" : re.compile(r'util\.printf\s*\(', re.IGNORECASE),
    "CVE-2007-5659" : re.compile(r'collectEmailInfo\s*\(', re.IGNORECASE),
    "CVE-2009-0927" : re.compile(r'getIcon\s*\(', re.IGNORECASE),
    "CVE-2010-1240" : re.compile(r'app\.openDoc\s*\(', re.IGNORECASE),
    "Shell Code"    : re.compile(rb'\x90{10,}'),
    "PE Header"     : re.compile(rb'MZ\x90\x00'),
}
OBFUSCATION_PATTERNS = [
    (r'\beval\s*\(',                  "'eval()' [ Dynamic Code Execution ]"),
    (r'\bunescape\s*\(',              "'unescape()' [ String Decoding ]"),
    (r'String\.fromCharCode',         "'String.fromCharCode' [ Character Encoding ]"),
    (r'\\x[0-9a-fA-F]{2}',            "Hex-Encoded String [ Data Masking ]"),
    (r'\\u[0-9a-fA-F]{4}',            "Unicode Escape Sequence [ Data Masking ]"),
    (r'(?:atob|btoa)\s*\(',           "Base64 [ Data Encoding ]"),
    (r'document\s*\.\s*write\s*\(',   "'document.write()' [ DOM Manipulation / Injection ]"),
    (r'app\s*\.\s*openDoc',           "'app.openDoc()' [ File Access ]"),
    (r'this\s*\.\s*exportDataObject', "'exportDataObject()' [ Payload Drop ]"),
    (r'util\s*\.\s*printf\s*\(',      "'util.printf()' [ Heap Spray / Exploit ]"),
    (r'app\.response\s*\(',           "'app.response()' [ Phishing Dialog ]"),
    (r'getAnnots\s*\(',               "'getAnnots()' [ Exploit Vector ]"),
]

def ComputeHashes(file_path: str) -> dict:

    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    
    with open(file_path, "rb") as file_handle:

        for chunk in iter(lambda: file_handle.read(8192), b""):

            hash_md5.update(chunk)
            hash_sha1.update(chunk)
            hash_sha256.update(chunk)

    return {
        "MD5"    : hash_md5.hexdigest(),
        "SHA1"   : hash_sha1.hexdigest(),
        "SHA256" : hash_sha256.hexdigest(),
    }

def SafeString(value) -> str:

    if value is None:

        return "N/A"

    return str(value).strip()

def ExtractMetadata(file_path: str) -> dict:

    metadata = {"source": "unavailable", "fields": {}, "anomalies": []}

    try:

        with pikepdf.open(file_path) as portable_document:

            metadata["source"] = "pikepdf"
            metadata["fields"]["page_count"] = len(portable_document.pages)

            if portable_document.docinfo:

                for key, value in portable_document.docinfo.items():

                    metadata["fields"][str(key)] = SafeString(value)

            creation_date_string = metadata["fields"].get("/CreationDate", "")

            if creation_date_string and len(creation_date_string) >= 6:

                year_string = creation_date_string[2:6] if creation_date_string.startswith("D:") else creation_date_string[:4]

                try:

                    creation_year = int(year_string)

                    if creation_year < 2000:

                        metadata["anomalies"].append(f"Suspicious Creation Year: {creation_year}")

                    if creation_year > datetime.datetime.now().year + 1:

                        metadata["anomalies"].append(f"Future Creation Date: {creation_year}")

                except ValueError:

                    pass

            author_value = metadata["fields"].get("/Author", "").strip()

            producer_value = metadata["fields"].get("/Producer", "").strip()

            if not author_value and producer_value:

                metadata["anomalies"].append("Possibly Generated Automatically")

    except Exception:

        try:

            with open(file_path, "rb") as file_handle:

                parser             = pdfminer.pdfparser.PDFParser(file_handle)
                document           = pdfminer.pdfdocument.PDFDocument(parser)
                metadata["source"] = "pdfminer"

                if document.info:

                    for info_dictionary in document.info:

                        for key, value in info_dictionary.items():

                            metadata["fields"][key] = SafeString(value)

        except Exception as fallback_exception:

            metadata["error"] = str(fallback_exception)

    return metadata

def ScanKeywords(file_path: str) -> dict:

    keyword_findings = {"High": [], "Medium": [], "Low": []}

    try:

        with open(file_path, "rb") as file_handle:

            raw_bytes = file_handle.read()

        raw_text = raw_bytes.decode("latin-1", errors="replace")

        for severity_level, keyword_list in SUSPICIOUS_KEYWORDS.items():

            for keyword in keyword_list:

                occurrence_count = raw_text.count(keyword)

                if occurrence_count:

                    keyword_findings[severity_level].append({"Keyword": keyword, "Count": occurrence_count})

    except Exception as exception:

        keyword_findings["error"] = str(exception)

    return keyword_findings

def ExtractJavaScript(file_path: str) -> dict:

    javascript_result = {"scripts": [], "obfuscation_hits": [], "error": None}

    try:

        with pikepdf.open(file_path) as portable_document:

            for object_identifier, pdf_object in portable_document.objects.items():

                try:

                    if isinstance(pdf_object, pikepdf.Dictionary):

                        if "/JS" in pdf_object:

                            javascript_value = pdf_object["/JS"]

                            if isinstance(javascript_value, pikepdf.Stream):

                                javascript_text = javascript_value.read_bytes().decode("latin-1", errors="replace")

                            else:

                                javascript_text = str(javascript_value)

                            javascript_result["scripts"].append({"object_identifier": str(object_identifier), "content": javascript_text[:2000]})

                except Exception:

                    continue

    except Exception as exception:

        javascript_result["error"] = str(exception)

    try:

        with open(file_path, "rb") as file_handle:

            raw_text = file_handle.read().decode("latin-1", errors="replace")

        for pattern, description in OBFUSCATION_PATTERNS:

            pattern_matches = re.findall(pattern, raw_text)

            if pattern_matches:

                javascript_result["obfuscation_hits"].append({"description": description, "occurrences": len(pattern_matches), "sample": pattern_matches[0][:100] if pattern_matches else ""})

    except Exception as exception:

        javascript_result["error"] = (javascript_result.get("error") or "") + " | " + str(exception)

    return javascript_result

def ExtractIndicatorsOfCompromise(file_path: str) -> dict:

    indicators = {key: [] for key in COMPROMISE_PATTERNS}

    try:

        with open(file_path, "rb") as file_handle:

            raw_text = file_handle.read().decode("latin-1", errors="replace")

        for indicator_type, pattern in COMPROMISE_PATTERNS.items():

            all_matches = list(set(re.findall(pattern, raw_text)))

            if indicator_type == "IP Address":

                all_matches = [match for match in all_matches if not match.startswith("0.") and not match.startswith("255.")]

            indicators[indicator_type] = all_matches[:50]

    except Exception as exception:

        indicators["error"] = str(exception)

    return indicators

def DetectExploits(file_path: str) -> dict:

    exploit_hits = {"cve_matches": [], "binary_signatures": []}

    try:

        with open(file_path, "rb") as file_handle:

            raw_bytes = file_handle.read()

        raw_text = raw_bytes.decode("latin-1", errors="replace")

        for signature_name, compiled_pattern in KNOWN_EXPLOITS.items():

            if isinstance(compiled_pattern.pattern, bytes):

                regex_match = compiled_pattern.search(raw_bytes)

            else:

                regex_match = compiled_pattern.search(raw_text)

            if regex_match:

                match_entry = {"name": signature_name, "offset": regex_match.start()}

                if signature_name.startswith("CVE"):

                    exploit_hits["cve_matches"].append(match_entry)

                else:

                    exploit_hits["binary_signatures"].append(match_entry)

    except Exception as exception:

        exploit_hits["error"] = str(exception)

    return exploit_hits

def EnumerateObjects(file_path: str) -> dict:

    enumeration_result = {"total_objects": 0, "streams": 0, "embedded_files": 0, "suspicious_objects": [], "error": None}

    try:

        with pikepdf.open(file_path) as portable_document:

            enumeration_result["total_objects"] = len(list(portable_document.objects.items()))

            for object_identifier, pdf_object in portable_document.objects.items():

                try:

                    if isinstance(pdf_object, pikepdf.Stream):

                        enumeration_result["streams"] += 1

                    if isinstance(pdf_object, pikepdf.Dictionary):

                        type_value    = str(pdf_object.get("/Type", ""))
                        subtype_value = str(pdf_object.get("/Subtype", ""))

                        if "EmbeddedFile" in subtype_value or "EmbeddedFile" in type_value:

                            enumeration_result["embedded_files"] += 1

                        if any(key in pdf_object for key in ["/JavaScript", "/JS", "/OpenAction", "/Launch"]):

                            enumeration_result["suspicious_objects"].append(str(object_identifier))

                except Exception:

                    continue

    except Exception as exception:

        enumeration_result["error"] = str(exception)

    return enumeration_result

def QueryVirusTotal(file_hashes: dict) -> dict:

    virustotal_result = {"sha256": file_hashes["SHA256"], "found": False, "malicious": None, "suspicious": None, "undetected": None, "total_engines": None, "link": None, "error": None}
    sha256_hash       = file_hashes["SHA256"]
    endpoint_url      = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    request           = urllib.request.Request(endpoint_url)
    request.add_header("x-apikey", VIRUSTOTAL_API_KEY)
    request.add_header("Accept", "application/json")

    try:

        with urllib.request.urlopen(request, timeout=15) as response:

            response_body                       = json.loads(response.read().decode())
            stats                               = response_body["data"]["attributes"]["last_analysis_stats"]
            virustotal_result["found"]          = True
            virustotal_result["malicious"]      = stats.get("malicious", 0)
            virustotal_result["suspicious"]     = stats.get("suspicious", 0)
            virustotal_result["undetected"]     = stats.get("undetected", 0)
            virustotal_result["total_engines"]  = sum(stats.values())
            virustotal_result["link"]           = f"https://www.virustotal.com/gui/file/{sha256_hash}"

    except urllib.error.HTTPError as http_error:

        if http_error.code == 404:

            virustotal_result["error"] = "Hash Not Found in VirusTotal Database."

        elif http_error.code == 401:

            virustotal_result["error"] = "VirusTotal API Key Invalid or Missing."

        elif http_error.code == 429:

            virustotal_result["error"] = "VirusTotal API Rate Limit Exceeded."

        else:

            virustotal_result["error"] = f"VirusTotal HTTP Error: {http_error.code}"

        print(f"   [!] VirusTotal Warning: {virustotal_result['error']}")

    except Exception as exception:

        virustotal_result["error"] = str(exception)
        print(f"   [!] VirusTotal Warning: {virustotal_result['error']}")

    return virustotal_result

def ComputeRiskScore(keyword_findings, javascript_result, indicators_of_compromise, exploit_hits) -> dict:
    total_score     = 0
    score_breakdown = []

    for keyword_item in keyword_findings.get("High", []):

        points = WEIGHTS["High Severity Keyword"]

        if keyword_item["Keyword"] == "/OpenAction":

            points = WEIGHTS["OpenAction"]

        total_score += points
        score_breakdown.append(f"+{points}  High Severity Keyword: {keyword_item['Keyword']} (x{keyword_item['Count']})")

    for keyword_item in keyword_findings.get("Medium", []):

        points       = WEIGHTS["Medium Severity Keyword"]
        total_score += points
        score_breakdown.append(f"+{points}  Medium Severity Keyword: {keyword_item['Keyword']}")

    for obfuscation_hit in javascript_result.get("obfuscation_hits", []):

        points       = WEIGHTS["JavaScript Obfuscation"]
        total_score += points
        score_breakdown.append(f"+{points}  JavaScript Obfuscation: {obfuscation_hit['description']}")

    for cve_match in exploit_hits.get("cve_matches", []):

        points       = WEIGHTS["Known Exploit"]
        total_score += points
        score_breakdown.append(f"+{points}  Exploit signature: {cve_match['name']}")

    for binary_signature in exploit_hits.get("binary_signatures", []):

        points = WEIGHTS["Shell Code or PE"]
        total_score += points
        score_breakdown.append(f"+{points}  Binary signature: {binary_signature['name']}")

    for url in indicators_of_compromise.get("URL", []):

        total_score += WEIGHTS["Indicator of Compromise URL"]
        score_breakdown.append(f"+{WEIGHTS['Indicator of Compromise URL']}  Indicator of Compromise URL: {url[:60]}")

        break

    for ip_address in indicators_of_compromise.get("IP ADDR", []):

        total_score += WEIGHTS["Indicator of Compromise IP"]
        score_breakdown.append(f"+{WEIGHTS['Indicator of Compromise IP']}  Indicator of Compromise IP: {ip_address}")

        break

    total_score = min(total_score, 100)

    if total_score >= 75:

        severity_level = "CRITICAL"

    elif total_score >= 50:

        severity_level = "HIGH"

    elif total_score >= 25:

        severity_level = "MEDIUM"

    elif total_score > 0:

        severity_level = "LOW"

    else:

        severity_level = "CLEAN"

    return {"score": total_score, "level": severity_level, "breakdown": score_breakdown}

def GenerateReport(file_path: str, analysis_results: dict) -> str:

    output_lines = []
    separator = "=" * 32
    output_lines.append(separator)
    output_lines.append("   MEOWNITOR — MALWARE REPORT")
    output_lines.append(separator)
    output_lines.append("")
    output_lines.append(f"   FILE NAME       : {file_path}")
    output_lines.append(f"   TIME STAMP      : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    output_lines.append(f"   SIZE (IN BYTES) : {os.path.getsize(file_path):,}")
    output_lines.append("")
    output_lines.append("-- FILE HASHES -----------------")
    output_lines.append("")

    for hash_name, hash_value in analysis_results["hashes"].items():

        output_lines.append(f"   {hash_name:8}: {hash_value}")

    output_lines.append("")
    output_lines.append("-- VIRUSTOTAL ------------------")
    output_lines.append("")
    virustotal_result = analysis_results["virustotal"]

    if virustotal_result.get("error"):

        output_lines.append(f"   Status  : {virustotal_result['error']}")

    elif virustotal_result.get("found"):

        output_lines.append(f"   Malicious   : {virustotal_result['malicious']} / {virustotal_result['total_engines']} engines")
        output_lines.append(f"   Suspicious  : {virustotal_result['suspicious']}")
        output_lines.append(f"   Undetected  : {virustotal_result['undetected']}")
        output_lines.append(f"   Link        : {virustotal_result['link']}")

    else:

        output_lines.append("   Status  : Not submitted / no result.")

    output_lines.append("")
    output_lines.append("-- RISK SCORE ------------------")
    output_lines.append("")
    risk_result = analysis_results["risk"]
    output_lines.append(f"   Score : {risk_result['score']}   [{risk_result['level']}]")
    output_lines.append("   Score Breakdown:")
    output_lines.append("")

    for breakdown_item in risk_result["breakdown"]:

        output_lines.append(f"   {breakdown_item}")

    output_lines.append("")
    output_lines.append("-- METADATA --------------------")
    output_lines.append("")
    metadata_result = analysis_results["metadata"]

    for field_key, field_value in metadata_result.get("fields", {}).items():

        output_lines.append(f"   {field_key:20}: {field_value}")

    output_lines.append("")
    for anomaly_description in metadata_result.get("anomalies", []):

        output_lines.append(f"   [!] ANOMALY: {anomaly_description}")

    output_lines.append("")
    output_lines.append("-- OBJECT ENUMERATION ----------")
    output_lines.append("")
    object_result = analysis_results["objects"]
    output_lines.append(f"   Total Objects   : {object_result.get('total_objects', 'N/A')}")
    output_lines.append(f"   Streams         : {object_result.get('streams', 'N/A')}")
    output_lines.append(f"   Embedded Files  : {object_result.get('embedded_files', 'N/A')}")

    output_lines.append("")
    if object_result.get("suspicious_objects"):

        output_lines.append(f"   Suspicious Objects : {', '.join(object_result['suspicious_objects'][:10])}")

    output_lines.append("")
    output_lines.append("-- SUSPICIOUS KEYWORDS ---------")
    output_lines.append("")
    keyword_results = analysis_results["keywords"]

    for severity_level in ("High", "Medium", "Low"):

        for keyword_item in keyword_results.get(severity_level, []):

            output_lines.append(f"   [ {severity_level:6} ] {keyword_item['Keyword']:24} Count = {keyword_item['Count']}")

    output_lines.append("")
    output_lines.append("-- JAVASCRIPT ANALYSIS ---------")
    output_lines.append("")
    javascript_result = analysis_results["javascript"]

    if javascript_result.get("scripts"):

        output_lines.append(f"   Embedded JavaScript Scripts Found: {len(javascript_result['scripts'])}")
        output_lines.append("")

        for script_entry in javascript_result["scripts"][:3]:

            output_lines.append(f"   Object {script_entry['object_identifier']}: {script_entry['content'][:150].strip()} ...")

    else:

        output_lines.append("   No Embedded JavaScript Streams Found.")

    output_lines.append("")
    if javascript_result.get("obfuscation_hits"):

        output_lines.append("   Obfuscation Patterns Detected:")
        output_lines.append("")

        for obfuscation_hit in javascript_result["obfuscation_hits"]:

            output_lines.append(f"   [!] {obfuscation_hit['description']}  (x{obfuscation_hit['occurrences']})")

    output_lines.append("")
    output_lines.append("-- INDICATORS OF COMPROMISE ----")
    output_lines.append("")

    for indicator_type, indicator_values in analysis_results["indicators_of_compromise"].items():

        if indicator_type == "error" or not indicator_values:

            continue

        output_lines.append(f"  {indicator_type}:")
        output_lines.append("")

        for indicator_value in indicator_values[:10]:

            output_lines.append(f"    - {indicator_value}")
            output_lines.append("")

    output_lines.append("-- EXPLOIT DETECTION -----------")
    output_lines.append("")
    exploit_result = analysis_results["exploits"]

    if exploit_result.get("cve_matches"):

        for cve_match in exploit_result["cve_matches"]:

            output_lines.append(f"   [!] CVE Match: {cve_match['name']}  at offset {cve_match['offset']}")

    else:

        output_lines.append("   No Known CVE Signatures Matched.")

    if exploit_result.get("binary_signatures"):

        for binary_signature in exploit_result["binary_signatures"]:

            output_lines.append(f"  [!] Binary Signature: {binary_signature['name']} at offset {binary_signature['offset']}")

    output_lines.append("")
    output_lines.append("-- MITIGATION RECOMMENDATIONS --")
    output_lines.append("")
    recommendations = []

    if keyword_results.get("High"):

        recommendations.append("Block or Quarantine (High Severity Keywords)")
        recommendations.append("Disable JavaScript Execution")

    if javascript_result.get("obfuscation_hits"):

        recommendations.append("De-Obfuscate and Manually Review")

    if analysis_results["indicators_of_compromise"].get("URL") or analysis_results["indicators_of_compromise"].get("IP Address"):

        recommendations.append("Block Compromised URLs / IPs at Network Perimeter")
        recommendations.append("Submit URLs to VirusTotal")

    if exploit_result.get("cve_matches"):

        recommendations.append("Ensure PDF Reader is Up-to-Date (Exploit Signatures)")
        recommendations.append("Sandbox PDF Rendering for Untrusted Documents")

    if object_result.get("embedded_files", 0) > 0:

        recommendations.append("Extract and Separately Scan Embedded File Objects")

    recommendations.append("Never Open Unknown PDFs on Production Systems")
    recommendations.append("Train Users to Recognise Phishing Attachments")
    
    for recommendation_index, recommendation_text in enumerate(recommendations, 1):

        output_lines.append(f"   {recommendation_index}. {recommendation_text}")

    output_lines.append("")
    output_lines.append(separator)
    output_lines.append("   END OF REPORT")
    output_lines.append(separator)

    return "\n".join(output_lines)

def Analyze(file_path: str, output_directory: str = ".") -> dict:

    if not os.path.isfile(file_path):

        print(f"[ERROR] File not found: {file_path}")
        sys.exit(1)

    file_hashes              = ComputeHashes(file_path)
    virustotal_result        = QueryVirusTotal(file_hashes)
    file_metadata            = ExtractMetadata(file_path)
    object_enumeration       = EnumerateObjects(file_path)
    keyword_scan_results     = ScanKeywords(file_path)
    javascript_analysis      = ExtractJavaScript(file_path)
    indicators_of_compromise = ExtractIndicatorsOfCompromise(file_path)
    exploit_detection        = DetectExploits(file_path)
    risk_score               = ComputeRiskScore(keyword_scan_results, javascript_analysis, indicators_of_compromise, exploit_detection)
    analysis_results         = {
        "file"                     : file_path,
        "timestamp"                : datetime.datetime.now().isoformat(),
        "hashes"                   : file_hashes,
        "virustotal"               : virustotal_result,
        "metadata"                 : file_metadata,
        "objects"                  : object_enumeration,
        "keywords"                 : keyword_scan_results,
        "javascript"               : javascript_analysis,
        "indicators_of_compromise" : indicators_of_compromise,
        "exploits"                 : exploit_detection,
        "risk"                     : risk_score,
    }
    report_text      = GenerateReport(file_path, analysis_results)
    output_base      = pathlib.Path(output_directory) / pathlib.Path(file_path).stem
    report_file_path = str(output_base) + ".txt"
    print("\n" + report_text)

    with open(report_file_path, "w") as report_file_handle:

        report_file_handle.write(report_text)

    print(f"\n   REPORT SAVED @ {report_file_path}")

    return analysis_results

if __name__ == "__main__":

    if len(sys.argv) < 2:

        sys.exit(1)

    filename = sys.argv[1]
    Analyze(filename, output_directory=".")