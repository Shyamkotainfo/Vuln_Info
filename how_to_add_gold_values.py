"""
How to Add Values to Gold Dimensional Tables

The Gold Layer uses a configuration-driven approach. To add new factors/columns:
"""

from vulnerability_pipeline.core.mongo_client import MongoManager

# === STEP 1: View Current Data ===
db = MongoManager.get_gold_db()

print("=== Sample VRR Dimensional Rows ===")
for doc in db["gold_vrr"].find().limit(5):
    print(f"CVE: {doc['cve_id']}")
    print(f"  Factor: {doc['factor_name']}")
    print(f"  Value: {doc['value']}")
    print(f"  Category: {doc['category']}")
    print(f"  Type: {doc['static_or_dynamic']}")
    print(f"  Source: {doc['source']}")
    print()

print("\n=== Counts ===")
print(f"VRR Rows: {db['gold_vrr'].count_documents({})}")
print(f"Threats Rows: {db['gold_threats'].count_documents({})}")
print(f"Vulnerabilities Rows: {db['gold_vulnerabilities'].count_documents({})}")
print(f"Weaknesses Rows: {db['gold_weaknesses'].count_documents({})}")

# === STEP 2: How to Add New Factors ===
print("\n\n=== HOW TO ADD NEW FACTORS ===")
print("""
1. Edit: vulnerability_pipeline/gold/mapping_config.py

2. Add to the appropriate FACTORS dict. Example for VRR:

VRR_FACTORS = {
    "exploit": {
        "exploit_verified": {"path": "verified", "category": "Exploitation Status", "type": "Dynamic"},
        # ADD NEW FACTOR HERE:
        "exploit_count": {"path": "TRUE", "category": "Exploit Availability", "type": "Static"}
    }
}

3. Re-run the Gold pipeline:
   python3 -m vulnerability_pipeline.pipeline_orchestrator --layer gold

4. The new factor will automatically appear as rows in gold_vrr!
""")

# === STEP 3: Manual Insertion (Advanced) ===
print("\n=== MANUAL INSERTION (For Custom/Static Values) ===")
print("""
If you want to manually insert a factor not from sources:

import hashlib
from datetime import datetime

# Example: Add a manual "criticality_override" factor
cve_id = "CVE-2021-44228"
factor_name = "criticality_override"
value = "CRITICAL"

row_id = hashlib.md5(f"{cve_id}_{factor_name}_gold_vrr".encode()).hexdigest()

doc = {
    "_id": row_id,
    "s_no": row_id,
    "cve_id": cve_id,
    "factor_name": factor_name,
    "value": value,
    "category": "Manual Override",
    "static_or_dynamic": "Static",
    "source": "manual",
    "gold_created_at": datetime.utcnow(),
    "gold_updated_at": datetime.utcnow()
}

db["gold_vrr"].update_one({"_id": row_id}, {"$set": doc}, upsert=True)
print(f"Inserted manual factor for {cve_id}")
""")
