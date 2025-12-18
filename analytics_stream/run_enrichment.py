# Vuln_info/analytics_stream/run_enrichment.py
import sys
import os
import argparse
from csv_handler.enricher import CSVEnricher

def main():
    parser = argparse.ArgumentParser(description="Enrich Vulnerability CSV with Risk Intel (VRR & Threats)")
    parser.add_argument("input", help="Path to input CSV file")
    parser.add_argument("--output", help="Path to save enriched CSV", default=None)
    parser.add_argument("--upload", help="Collection name to upload to MongoDB", default=None)
    parser.add_argument("--cve-col", help="Name of the CVE column in input file", default="CVE")
    parser.add_argument("--uri", help="Optional custom MongoDB URI", default=None)

    args = parser.parse_args()

    # Move to project root to find config/env
    os.chdir(os.path.dirname(os.path.abspath(__file__)) + "/..")

    enricher = CSVEnricher(mongo_uri=args.uri)
    
    # Run Enrichment
    logger = enricher.enrich_csv(args.input, args.output, cve_column=args.cve_col)
    
    # Upload if requested
    if args.upload and logger is not None:
        enricher.upload_to_collection(logger, args.upload)

if __name__ == "__main__":
    main()
