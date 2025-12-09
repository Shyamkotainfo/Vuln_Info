from vulnerability_pipeline.core.config import Config
from vulnerability_pipeline.core.mongo_client import MongoManager

def verify_nvd_data():
    try:
        # Get client and database using existing logic
        db = MongoManager.get_bronze_db()
        collection = db[Config.COLLECTION_NVD]
        
        # Count documents
        count = collection.count_documents({})
        print(f"Connected to MongoDB: {Config.MONGO_URI}")
        print(f"Database: {Config.DB_BRONZE}")
        print(f"Collection: {Config.COLLECTION_NVD}")
        print(f"Current NVD Record Count: {count}")
        
        # Sample one document to check structure
        if count > 0:
            print("\nSample Document (ID only):")
            sample = collection.find_one({}, {"id": 1, "ingested_at": 1})
            print(sample)
            
    except Exception as e:
        print(f"Error checking MongoDB: {e}")

if __name__ == "__main__":
    verify_nvd_data()
