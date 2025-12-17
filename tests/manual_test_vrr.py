import sys
import os
import logging
import pandas as pd
import tempfile
from dotenv import load_dotenv

# Load env vars
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analytics_stream.dimension_builder import DimensionBuilder
from analytics_stream.client_processor import ClientProcessor
from vulnerability_pipeline.core.mongo_client import MongoManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("manual_test")

def test_pipeline():
    # 1. Connect and find a sample CVE
    db = MongoManager.get_gold_db()
    sample_cve_doc = db["gold_nvd"].find_one({}, {"cve_id": 1})
    
    if not sample_cve_doc:
        logger.error("❌ No data found in gold_nvd! Cannot test pipeline.")
        return

    cve_id = sample_cve_doc.get("cve_id")
    logger.info(f"🔎 Testing with CVE: {cve_id}")

    # 2. Test Dimension Builder
    logger.info("--- Testing Dimension Builder ---")
    builder = DimensionBuilder()
    vrr, threat = builder.build_for_cve(cve_id)
    
    print("\n[DimVRR Data]")
    print(vrr)
    print("\n[DimThreat Data]")
    print(threat)
    
    # Verify Dimensions in DB
    saved_vrr = db["dim_vrr"].find_one({"cve_id": cve_id})
    saved_threat = db["dim_threat"].find_one({"cve_id": cve_id})
    
    if saved_vrr and saved_threat:
        logger.info("✅ Dimensions successfully saved to MongoDB.")
    else:
        logger.error("❌ Dimensions NOT saved to MongoDB.")

    # 3. Test Client Processor
    logger.info("\n--- Testing Client Processor ---")
    
    # Create dummy CSV
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
        tmp.write(f"Host,Plugin Output,CVE\n192.168.1.1,Vulnerable Java,{cve_id}\n")
        tmp_path = tmp.name
        
    try:
        processor = ClientProcessor() # Uses default/gold db for output for testing
        col_name = processor.process_csv(tmp_path, client_id="test_run_001")
        
        # Verify Output
        if col_name:
            data = db[col_name].find_one()
            logger.info(f"✅ Client Data processed into collection: {col_name}")
            print("\n[Final Table Record]")
            print(data)
        else:
            logger.error("❌ Client Processor returned no collection name.")
            
    finally:
        os.remove(tmp_path)

if __name__ == "__main__":
    test_pipeline()
