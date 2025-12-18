# Vuln_info/csv_handler/uploader.py

import pandas as pd
import logging
import datetime
import hashlib
import os
import json
from pymongo import UpdateOne, MongoClient
import certifi

from vulnerability_pipeline.core.mongo_client import MongoManager
from vulnerability_pipeline.core.config import Config

# -------------------------------------------------------------------
# Logger
# -------------------------------------------------------------------
logger = logging.getLogger("CSVProcessor")
logging.basicConfig(level=logging.INFO)

# Mapping: scanner name → unified-field → source column name
SCANNER_COLUMN_MAP = {
    "Nessus": {
        "Scanner plugin ID": "Plugin ID",
        "Vulnerability name": "Name",
        "Scanner Reported Severity": "Risk",
        "Scanner Severity": "CVSS",
        "Description": "Description",
        "Status": "Status",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Plugin Output",
        "Possible Solutions": "Solution",
        "Possible patches": "See Also",
        "IPAddress": "Host"
    },
    "HCL AppScan": {
        "Scanner plugin ID": "Issue ID",
        "Vulnerability name": "Issue Type / Title",
        "Scanner Reported Severity": "Severity (raw text)",
        "Scanner Severity": "CVSS Score (if available)",
        "Description": "Description",
        "Status": "Issue Status (Open/Fixed)",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Evidence / HTTP request-response",
        "Possible Solutions": "Fix Recommendation",
        "Possible patches": "CVE / Patch Reference (if available)",
        "IPAddress": "Hostname / IP"
    },
    "Acunetix / Invicti": {
        "Scanner plugin ID": "Vulnerability ID",
        "Vulnerability name": "Vulnerability Title",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "CVSS Base",
        "Description": "Description",
        "Status": "Status / Confirmed",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Proof / Payload / Evidence",
        "Possible Solutions": "Recommendation",
        "Possible patches": "CVE \u2192 Patch Reference",
        "IPAddress": "Target / Host"
    },
    "OWASP ZAP": {
        "Scanner plugin ID": "Alert ID",
        "Vulnerability name": "Alert Name",
        "Scanner Reported Severity": "Risk",
        "Scanner Severity": "CVSS (if mapped)",
        "Description": "Description",
        "Status": "Status (Confirmed / False Positive)",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Evidence",
        "Possible Solutions": "Solution",
        "Possible patches": "N/A",
        "IPAddress": "Host / URL"
    },
    "Netsparker / Invicti": {
        "Scanner plugin ID": "Vulnerability ID",
        "Vulnerability name": "Vulnerability Title",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "CVSS Score",
        "Description": "Description",
        "Status": "Status",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Proof / Payload",
        "Possible Solutions": "Recommendation",
        "Possible patches": "Fix Version / Patch Link",
        "IPAddress": "Target / Host"
    },
    "w3af": {
        "Scanner plugin ID": "Vulnerability ID",
        "Vulnerability name": "Name",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "N/A",
        "Description": "Description",
        "Status": "Active / Verified",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "HTTP Request/Response",
        "Possible Solutions": "Fix Guidance",
        "Possible patches": "N/A",
        "IPAddress": "Host / URL"
    },
    "OpenVAS / Greenbone (GVM)": {
        "Scanner plugin ID": "NVT OID / Vulnerability ID",
        "Vulnerability name": "Name",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "CVSS Score",
        "Description": "Summary / Description",
        "Status": "Threat / QoD / Result",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Detection Output / Details",
        "Possible Solutions": "Solution",
        "Possible patches": "Patch / CVE Ref",
        "IPAddress": "Host"
    },
    "Qualys VMDR": {
        "Scanner plugin ID": "QID",
        "Vulnerability name": "Title",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "CVSS Base",
        "Description": "Diagnosis",
        "Status": "Vuln Status (Active, Fixed, Reopened)",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Results",
        "Possible Solutions": "Solution",
        "Possible patches": "Patchable / Fix Version",
        "IPAddress": "Host"
    },
    "Masscan / RustScan": {
        "Scanner plugin ID": "N/A",
        "Vulnerability name": "N/A",
        "Scanner Reported Severity": "Severity (1-5)",
        "Scanner Severity": "N/A",
        "Description": "Scan Output / Banner",
        "Status": "N/A",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Scan Output / Banner",
        "Possible Solutions": "N/A",
        "Possible patches": "N/A",
        "IPAddress": "Host"
    },
    "Nmap": {
        "Scanner plugin ID": "Script ID / Script Name",
        "Vulnerability name": "Script Title / Service Name",
        "Scanner Reported Severity": "Script risk output",
        "Scanner Severity": "CVSS (if script reports)",
        "Description": "Script Output Summary",
        "Status": "Host Up / Down",
        "Port": "Port",
        "Protocol": "TCP/UDP",
        "Plugin Output": "Script Output",
        "Possible Solutions": "N/A",
        "Possible patches": "N/A",
        "IPAddress": "Host"
    },
    "Angry IP Scanner": {
        "Scanner plugin ID": "N/A",
        "Vulnerability name": "N/A",
        "Scanner Reported Severity": "N/A",
        "Scanner Severity": "N/A",
        "Description": "N/A",
        "Status": "Alive / Dead",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "N/A",
        "Possible Solutions": "N/A",
        "Possible patches": "N/A",
        "IPAddress": "Host"
    },
    "Nuclei": {
        "Scanner plugin ID": "Template ID",
        "Vulnerability name": "Template Name",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "CVSS (if tagged in template)",
        "Description": "Description",
        "Status": "Matched / Not matched",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Matched Data / Extracted Results",
        "Possible Solutions": "N/A",
        "Possible patches": "Fix Version / Patch Tag (if any)",
        "IPAddress": "Target / Host"
    },
    "EyeWitness": {
        "Scanner plugin ID": "N/A",
        "Vulnerability name": "Screenshot / Page Title",
        "Scanner Reported Severity": "N/A",
        "Scanner Severity": "N/A",
        "Description": "Screenshot Context / Page Title",
        "Status": "Captured / Skipped",
        "Port": "Port (if applicable)",
        "Protocol": "HTTP/HTTPS",
        "Plugin Output": "Screenshot / HTML Title",
        "Possible Solutions": "N/A",
        "Possible patches": "Reference (Exploit / Patch link)",
        "IPAddress": "Target / Domain"
    },
    "Sn1per / Recon-ng": {
        "Scanner plugin ID": "Finding ID / Module ID",
        "Vulnerability name": "Finding Title",
        "Scanner Reported Severity": "Severity / Confidence",
        "Scanner Severity": "N/A",
        "Description": "Reference / Patch URL",
        "Status": "Found / Not Found",
        "Port": "Port",
        "Protocol": "HTTP/HTTPS",
        "Plugin Output": "Command Output / Evidence",
        "Possible Solutions": "Recommendation / Next Steps",
        "Possible patches": "Reference / Patch URL",
        "IPAddress": "Target"
    },
    "Burp Suite": {
        "Scanner plugin ID": "Issue Type",
        "Vulnerability name": "Issue Name",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "N/A",
        "Description": "Issue Detail",
        "Status": "Issue Status (Certain / Tentative)",
        "Port": "N/A",
        "Protocol": "HTTP/HTTPS",
        "Plugin Output": "Evidence",
        "Possible Solutions": "Remediation Background",
        "Possible patches": "Reference / Patch URL",
        "IPAddress": "Host"
    }
}

# -------------------------------------------------------------------
class CSVProcessor:
    def __init__(self, mongo_uri: str = None):
        # 1. Target Database (where data goes)
        if mongo_uri:
            logger.info(f"Target: Custom MongoDB {mongo_uri[:15]}...")
            is_local = "localhost" in mongo_uri or "127.0.0.1" in mongo_uri
            if is_local:
                self.client = MongoClient(mongo_uri, serverSelectionTimeoutMS=10000)
            else:
                self.client = MongoClient(mongo_uri, tls=True, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=10000)
            self.db = self.client[Config.DB_GOLD]
        else:
            logger.info("Target: Default System MongoDB")
            self.client = MongoManager.get_client()
            self.db = self.client[Config.DB_GOLD]

        # 2. Intel Database (where Risk Intel comes from)
        # ALWAYS use system default for Intel lookup to ensure we find the 322k records
        self.intel_client = MongoManager.get_client()
        self.intel_db = self.intel_client[Config.DB_GOLD]
        
        self.collection = self.db["vrr_risk_report"]
        self.raw_collection = self.db["host_findings"]

    # -------------------------------------------------------------------
    # Utilities
    # -------------------------------------------------------------------
    def _generate_id(self, host, plugin_id):
        raw = f"{host}-{plugin_id}"
        return hashlib.md5(raw.encode()).hexdigest()

    @staticmethod
    def _normalize_cves(cve_str):
        if not cve_str or pd.isna(cve_str):
            return []
        import re
        # Find anything that looks like CVE-YYYY-NNNN
        found = re.findall(r'CVE-\d{4}-\d+', str(cve_str).upper())
        return sorted(list(set(found)))

    def _detect_scanner(self, df: pd.DataFrame) -> str:
        cols_lower = {str(c).lower() for c in df.columns}
        best_match = None
        best_score = 0

        for scanner, mapping in SCANNER_COLUMN_MAP.items():
            # Check how many mapped columns exist in the input DF
            score = sum(1 for src_col in mapping.values() if src_col and str(src_col).lower() in cols_lower)
            if score > best_score:
                best_match = scanner
                best_score = score

        return best_match or "Generic Scanner"

    # -------------------------------------------------------------------
    # Generic Ingestion & Transformation
    # -------------------------------------------------------------------
    def _transform_generic(self, df: pd.DataFrame) -> pd.DataFrame:
        scanner = self._detect_scanner(df)
        mapping = SCANNER_COLUMN_MAP.get(scanner, {})
        logger.info(f"Detected scanner: {scanner}")

        out = pd.DataFrame(index=df.index)

        def pick_col(*candidates):
            for c in candidates:
                if c and c in df.columns:
                    return df[c]
            return pd.Series([""] * len(df), index=df.index)

        # 1. Generate HostFindingsID (using mapped IP and Plugin ID)
        ip_col = mapping.get("IPAddress", "Host")
        plugin_col = mapping.get("Scanner plugin ID", "Plugin ID")
        
        out["HostFindingsID"] = df.apply(
            lambda r: self._generate_id(
                str(r.get(ip_col, "UnknownHost")),
                str(r.get(plugin_col, "0"))
            ),
            axis=1
        )

        # 2. Map Core Columns
        out["ScannerName"] = scanner
        out["ScannerPluginID"] = pick_col(mapping.get("Scanner plugin ID"), "Plugin ID")
        out["VulnerabilityName"] = pick_col(mapping.get("Vulnerability name"), "Name")
        out["ScannerReportedSeverity"] = pick_col(mapping.get("Scanner Reported Severity"), "Risk")
        out["ScannerSeverity"] = pick_col(mapping.get("Scanner Severity"), "CVSS")
        
        # Smart Description (Synopsis + Description)
        desc_col = mapping.get("Description", "Description")
        synops_col = "Synopsis"
        out["Description"] = (
            pick_col(desc_col).fillna("") + 
            " " + 
            pick_col(synops_col).fillna("")
        ).str.strip()

        out["Status"] = pick_col(mapping.get("Status"), "Status").replace("", "Open")
        out["Port"] = pick_col(mapping.get("Port"), "Port")
        out["Protocol"] = pick_col(mapping.get("Protocol"), "Protocol")
        out["PluginOutput"] = pick_col(mapping.get("Plugin Output"), "Plugin Output")
        out["PossibleSolutions"] = pick_col(mapping.get("Possible Solutions"), "Solution")
        out["PossiblePatches"] = pick_col(mapping.get("Possible patches"), "See Also")
        out["IPAddress"] = pick_col(ip_col, "Host")
        out["Date"] = datetime.datetime.now().strftime("%Y-%m-%d")

        # 3. CVE Extraction & Enrichment
        # We need to find CVEs in the original DF (often in a 'CVE' column)
        cve_candidates = ["CVE", "cve", "Vulnerability ID", "Advisory", "References"]
        cve_col_name = None
        for c in cve_candidates:
            if c in df.columns:
                cve_col_name = c
                break
        
        cve_data = df[cve_col_name].fillna("") if cve_col_name else pd.Series([""] * len(df))
        
        # Collect unique CVEs for bulk lookup
        unique_cves = set()
        row_cve_lists = []
        for val in cve_data:
            cves = self._normalize_cves(val)
            row_cve_lists.append(cves)
            unique_cves.update(cves)

        # Fetch Intel
        intel_map = {}
        if unique_cves:
            coll = self.intel_db["fct_final"]
            cursor = coll.find({"cve_id": {"$in": list(unique_cves)}}, {"_id": 0})
            for doc in cursor:
                intel_map[doc["cve_id"]] = doc
        
        # Apply Enrichment
        vrr_scores = []
        vulnerabilities = []
        weaknesses = []
        threats = []

        for cves in row_cve_lists:
            if not cves:
                vrr_scores.append(0.0); vulnerabilities.append([]); weaknesses.append([]); threats.append({})
                continue

            row_scores = []
            row_found_cves = set()
            row_cwes = set()
            row_threats = {}

            for cve in cves:
                intel = intel_map.get(cve)
                if intel:
                    row_scores.append(intel.get("vrr_score", 0.0))
                    row_found_cves.add(cve)
                    
                    # Merge Threats
                    t_data = intel.get("threats", {})
                    for k, v in t_data.items():
                        if k not in row_threats: row_threats[k] = set()
                        items = v if isinstance(v, list) else [v]
                        row_threats[k].update(items)
                        # Extract CWEs
                        for x in items:
                            if isinstance(x, str) and "CWE-" in x: row_cwes.add(x)

            # Finalize Row Data
            final_threats = {}
            for k, v in row_threats.items():
                list_v = sorted(list(v))
                final_threats[k] = list_v[0] if len(list_v) == 1 else list_v

            vrr_scores.append(max(row_scores) if row_scores else 0.0)
            vulnerabilities.append(sorted(list(row_found_cves)))
            weaknesses.append(sorted(list(row_cwes)))
            threats.append(final_threats)

        out["vrr_score"] = vrr_scores
        out["vulnerabilities"] = vulnerabilities
        out["weaknesses"] = weaknesses
        out["threats"] = threats

        # 4. Junk Removal (Exclude VRR == 0)
        total_rows = len(out)
        out_clean = out[out["vrr_score"] > 0].copy()
        removed = total_rows - len(out_clean)
        logger.info(f"Junk Removal: Filtered {removed} rows with 0 risk. {len(out_clean)} remaining.")

        # 5. Standardized 19-Column Schema Mapping
        # Map internal names to the user's requested "Master Schema" names
        master_schema = pd.DataFrame(index=out_clean.index)
        master_schema["Host Findings ID"] = out_clean["HostFindingsID"]
        master_schema["VRR Score"] = out_clean["vrr_score"]
        master_schema["Scanner Name"] = out_clean["ScannerName"]
        master_schema["Scanner plugin ID"] = out_clean["ScannerPluginID"]
        master_schema["Vulnerability name"] = out_clean["VulnerabilityName"]
        master_schema["Scanner Reported Severity"] = out_clean["ScannerReportedSeverity"]
        master_schema["Scanner Severity"] = out_clean["ScannerSeverity"]
        master_schema["Description"] = out_clean["Description"]
        master_schema["Status"] = out_clean["Status"]
        master_schema["Port"] = out_clean["Port"]
        master_schema["Protocol"] = out_clean["Protocol"]
        master_schema["Plugin Output"] = out_clean["PluginOutput"]
        master_schema["Possible Solutions"] = out_clean["PossibleSolutions"]
        master_schema["Possible patches"] = out_clean["PossiblePatches"]
        master_schema["IPAddress"] = out_clean["IPAddress"]
        master_schema["Vulnerabilities"] = out_clean["vulnerabilities"]
        master_schema["Weaknesses"] = out_clean["weaknesses"]
        master_schema["Threat"] = out_clean["threats"]
        master_schema["Date"] = out_clean["Date"]

        # Save Reports
        os.makedirs("data", exist_ok=True)
        csv_path = os.path.join(os.getcwd(), "data", "final_risk_report.csv")
        json_path = os.path.join(os.getcwd(), "data", "final_risk_report.json")
        
        master_schema.to_csv(csv_path, index=False)
        master_schema.to_json(json_path, orient="records", indent=4)
        
        # Optional Excel Export
        try:
            excel_path = csv_path.replace(".csv", ".xlsx")
            master_schema.to_excel(excel_path, index=False, engine="openpyxl")
            logger.info(f"Excel saved -> {excel_path}")
        except Exception:
            pass # openpyxl might not be installed
        
        # Summary Display
        if not master_schema.empty:
            print("\n" + "="*80 + "\nENRICHED VULNERABILITY REPORT SUMMARY\n" + "="*80)
            print(master_schema[["Scanner plugin ID", "VRR Score", "Vulnerabilities", "IPAddress"]].head(10).to_string(index=False))
            if len(master_schema) > 10: print(f"... and {len(master_schema)-10} more rows.")
            print("="*80 + "\n")

        self.last_report_metadata = {
            "csv_path": csv_path,
            "json_path": json_path,
            "total_rows": total_rows,
            "clean_rows": len(master_schema)
        }

        return master_schema

    # -------------------------------------------------------------------
    # Main CSV Processor
    # -------------------------------------------------------------------
    def process_csv(self, file_path: str):
        try:
            df_raw = pd.read_csv(file_path)
            
            # Use the new generic transformation (detects, maps, enriches, filters)
            df = self._transform_generic(df_raw)

            if df.empty:
                logger.warning("No actionable vulnerabilities (VRR > 0) found in CSV.")
                return {
                    "status": "success", 
                    "processed": 0, 
                    "collection": "vrr_risk_report",
                    "metadata": getattr(self, "last_report_metadata", {}),
                    "data": []
                }

            # Map "Master Schema" names back to internal DB keys for MongoDB storage
            # to maintain consistency with existing records if needed, OR just store as is.
            # Given the previous logic used "HostFindingsID", I'll ensure that's available.
            records = []
            for _, row in df.iterrows():
                record = row.to_dict()
                # Ensure internal ID key is available for the filter
                record["HostFindingsID"] = row["Host Findings ID"]
                records.append(record)

            ops = []
            for record in records:
                # Clean up null values safely (handles lists/dicts from enrichment)
                clean = {}
                for k, v in record.items():
                    if isinstance(v, (list, dict)):
                        clean[k] = v
                    elif pd.notna(v):
                        clean[k] = v
                
                clean["last_updated"] = datetime.datetime.utcnow()

                ops.append(
                    UpdateOne(
                        {"HostFindingsID": clean["HostFindingsID"]},
                        {
                            "$set": clean,
                            "$unset": {
                                "vrr_score": "", 
                                "threats": "", 
                                "vulnerabilities": "", 
                                "weaknesses": ""
                            }
                        },
                        upsert=True
                    )
                )

            if ops:
                result = self.collection.bulk_write(ops)
                logger.info(
                    f"🚀 CLEAN DATA LOADED TO MONGODB (collection: 'vrr_risk_report') | "
                    f"Count: {len(ops)}"
                )

            # Convert to JSON-safe dicts for API response (handles datetimes, NaNs, etc)
            json_safe_records = json.loads(df.to_json(orient="records", date_format="iso"))

            return {
                "status": "success", 
                "processed": len(ops), 
                "collection": "vrr_risk_report",
                "metadata": getattr(self, "last_report_metadata", {}),
                "data": json_safe_records
            }

        except Exception as e:
            logger.error(f"CSV processing failed: {e}")
            raise

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 -m csv_handler.uploader <csv_file> [mongo_uri]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    custom_uri = sys.argv[2] if len(sys.argv) > 2 else None
    
    processor = CSVProcessor(mongo_uri=custom_uri)
    try:
        processor.process_csv(file_path)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
