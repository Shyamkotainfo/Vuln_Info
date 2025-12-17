import sys
import os
# Add root to path to ensure imports work
sys.path.append(os.getcwd())

from vulnerability_pipeline.core.mongo_client import MongoManager
import logging

logging.basicConfig(level=logging.INFO)

def verify_mongo_data():
    db = MongoManager.get_gold_db()
    
    print("\n=== DimVRR (2 Expected) ===")
    for doc in db.dim_vrr.find():
        print(f"CVE: {doc.get('vuln_id')} | UUID: {doc.get('unique_id')}")
        
    print("\n=== DimWeakness (3 Expected) ===")
    for doc in db.dim_weakness.find():
        print(f"CVE: {doc.get('vuln_id')} | Weakness: {doc.get('weakness_name')} | UUID: {doc.get('unique_id')}")
        
    print("\n=== FctFinal (3 Expected Rows: 1 for CVE-1, 2 for CVE-2) ===")
    # Note: Logic was "explode weaknesses", so CVE with 2 CWEs should get 2 Fact rows
    for doc in db.fct_final.find():
        print(f"CVE: {doc.get('cve_id')} | Score: {doc.get('vrr_score')} | WeaknessFK: {doc.get('weakness_id')}")

if __name__ == "__main__":
    verify_mongo_data()
