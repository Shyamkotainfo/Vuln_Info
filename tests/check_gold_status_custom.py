import logging
from vulnerability_pipeline.core.mongo_client import MongoManager

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("check_gold_counts")

def check_gold_counts():
    try:
        db = MongoManager.get_gold_db()
        logger.info(f"Connected to Gold DB: {db.name}")
        
        collections = db.list_collection_names()
        logger.info(f"Gold Collections: {collections}")
        
        print("\n=== Gold Collection Counts ===")
        for col_name in sorted(collections):
            count = db[col_name].count_documents({})
            print(f"{col_name}: {count}")
            
    except Exception as e:
        logger.error(f"Failed to check counts: {e}")

if __name__ == "__main__":
    check_gold_counts()
