from vulnerability_pipeline.bronze.nvd.load import NVDLoader
from datetime import datetime

def test_upload_5_records():
    print("Preparing 5 dummy records...")
    dummy_data = []
    for i in range(1, 6):
        # Construct data structure matching what extract_from_api usually returns
        # i.e. a list of items, where each item has a 'cve' key
        dummy_data.append({
            "cve": {
                "id": f"CVE-TEST-2024-000{i}",
                "sourceIdentifier": "manual_test",
                "published": datetime.utcnow().isoformat(),
                "lastModified": datetime.utcnow().isoformat(),
                "vulnStatus": "Test_Record",
                "descriptions": [{"lang": "en", "value": "This is a test record."}]
            }
        })
    
    print("Loading records to MongoDB...")
    loader = NVDLoader()
    loader.load_bulk(dummy_data)
    print("Done.")

if __name__ == "__main__":
    test_upload_5_records()
