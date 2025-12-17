import logging
import time
from vulnerability_pipeline.core.mongo_client import MongoManager

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verify_gold_cleanup")

def verify_cleanup():
    try:
        db = MongoManager.get_gold_db()
        logger.info(f"Connected to Gold DB: {db.name}")
        
        collections = db.list_collection_names()
        logger.info(f"Current Gold Collections: {collections}")
        
        # Check CISA for full fields
        cisa_doc = db['gold_cisa'].find_one({"cveID": "CVE-2022-37055"})
        if cisa_doc:
            print("\n=== CISA Document Check (CVE-2022-37055) ===")
            required_keys = ["vulnerabilityName", "shortDescription", "cwes", "dateAdded"]
            for key in required_keys:
                status = "✅ Found" if key in cisa_doc else "❌ MISSING"
                print(f"{key}: {status}")
        else:
            print("\n❌ Could not find test document CVE-2022-37055")
            
    except Exception as e:
        logger.error(f"Failed to check: {e}")

if __name__ == "__main__":
    verify_cleanup()
