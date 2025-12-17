import os
import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

def get_db():
    uri = os.getenv("MONGO_URI") or "mongodb://localhost:27017/"
    client = MongoClient(uri)
    try:
        return client.get_database()
    except:
        return client["vulnerability_gold"] # Match local DB name

def create_mock_data():
    db = get_db()
    
    # 1. Gold NVD
    cve1 = "CVE-2023-9999"
    cve2 = "CVE-2023-8888"
    
    db.gold_nvd.drop()
    db.gold_nvd.insert_many([
        {
            "cve_id": cve1,
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
            },
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-123"}]}],
            "references": [{"url": "http://example.com/mock"}]
        },
        {
            "cve_id": cve2,
             "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]
            }
        }
    ])
    
    # 2. Gold CISA
    db.gold_cisa.drop()
    db.gold_cisa.insert_one({
        "cveID": cve1,
        "knownRansomwareCampaignUse": "Known",
        "product": "MockServer",
        "vendorProject": "MockCorp",
        "requiredAction": "Apply patch now"
    })
    
    # 3. Gold EPSS
    db.gold_epss.drop()
    db.gold_epss.insert_one({
        "cve": cve1,
        "epss": 0.95,
        "percentile": 0.99
    })
    
    print("✅ Mock Gold Data Inserted.")

if __name__ == "__main__":
    create_mock_data()
