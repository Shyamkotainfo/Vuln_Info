import os
from pymongo import MongoClient
import json
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

def verify():
    uri = os.getenv("MONGO_URI") or "mongodb://localhost:27017/"
    is_local = "localhost" in uri or "127.0.0.1" in uri
    
    if is_local:
        client = MongoClient(uri)
    else:
        import certifi
        client = MongoClient(uri, tls=True, tlsCAFile=certifi.where())
    try:
        db = client.get_database()
        if db.name == "test": db = client["vulnerability_gold"]
    except:
        db = client["vulnerability_gold"]

    print("\n--- Verifying Counts ---")
    rows_threats = db.dim_threats.count_documents({})
    rows_vrr = db.dim_vrr.count_documents({})
    print(f"Dim Threats: {rows_threats}")
    print(f"Dim VRR:     {rows_vrr}")

    print("\n--- Verifying fct_final ---")
    data = list(db.fct_final.find({}, {"_id": 0, "date_added": 0}).limit(2)) # Limit to 2 for brevity
    print(json.dumps(data, indent=2))
    
    if len(data) > 0 and rows_threats > 0:
        print("✅ SUCCESS: Data found in all tables.")
    else:
        print("❌ FAILURE: Missing data.")

if __name__ == "__main__":
    verify()
