import sys
import unittest
from unittest.mock import MagicMock
from datetime import datetime

# Import classes to test
from vulnerability_pipeline.datasources.external_feeds.nvd.extract import NVDExtractor
from vulnerability_pipeline.datasources.external_feeds.nvd.load import NVDLoader
from vulnerability_pipeline.datasources.external_feeds.cisa.extract import CISAExtractor
from vulnerability_pipeline.datasources.external_feeds.cisa.load import CISALoader
from vulnerability_pipeline.datasources.external_feeds.epss.extract import EPSSExtractor
from vulnerability_pipeline.datasources.external_feeds.epss.load import EPSSLoader
from vulnerability_pipeline.datasources.external_feeds.exploit.extract import ExploitDBExtractor
from vulnerability_pipeline.datasources.external_feeds.exploit.load import ExploitDBLoader
from vulnerability_pipeline.datasources.external_feeds.metasploit.extract import MetasploitExtractor
from vulnerability_pipeline.datasources.external_feeds.metasploit.load import MetasploitLoader

from vulnerability_pipeline.pipeline_orchestrator import PipelineOrchestrator

class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.orchestrator = PipelineOrchestrator()
    
    def test_nvd_load_5(self):
        print("\nTesting NVD Load (5 records)...")
        # Mock Extractor to yield 5 dummy records
        dummy_data = [{
            "cve": {
                "id": f"CVE-TEST-NVD-{i}",
                "sourceIdentifier": "test",
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-01T00:00:00.000",
                "vulnStatus": "Test",
                "descriptions": [{"lang": "en", "value": "Test desc"}]
            }
        } for i in range(5)]
        
        self.orchestrator.sources['nvd']['extractor'].extract = MagicMock(return_value=dummy_data)
        self.orchestrator.run_pipeline(source_keys=['nvd'], mode='full')
        
    def test_cisa_load_5(self):
        print("\nTesting CISA Load (5 records)...")
        dummy_data = [{
            "cveID": f"CVE-TEST-CISA-{i}",
            "vendorProject": "TestVendor",
            "product": "TestProduct",
            "vulnerabilityName": "TestVuln",
            "dateAdded": "2024-01-01",
            "shortDescription": "Test Desc",
            "requiredAction": "None",
            "dueDate": "2024-02-01",
            # Enriched fields
            "catalogVersion": "1.0",
            "dateReleased": "2024-01-01"
        } for i in range(5)]

        self.orchestrator.sources['cisa']['extractor'].extract = MagicMock(return_value=dummy_data)
        self.orchestrator.run_pipeline(source_keys=['cisa'], mode='full')

    def test_epss_load_5(self):
        print("\nTesting EPSS Load (5 records)...")
        dummy_data = [{
            "cve": f"CVE-TEST-EPSS-{i}",
            "epss": "0.5",
            "percentile": "0.9",
            "date": "2024-01-01"
        } for i in range(5)]

        self.orchestrator.sources['epss']['extractor'].extract = MagicMock(return_value=dummy_data)
        self.orchestrator.run_pipeline(source_keys=['epss'], mode='full')

    def test_exploit_load_5(self):
        print("\nTesting ExploitDB Load (5 records)...")
        dummy_data = [{
            "id": f"EDB-TEST-{i}",
            "file": "test.txt",
            "description": "Test Exploit",
            "date_published": "2024-01-01",
            "author": "Tester",
            "type": "web",
            "platform": "php",
            "port": "80"
        } for i in range(5)]

        self.orchestrator.sources['exploit']['extractor'].extract = MagicMock(return_value=dummy_data)
        self.orchestrator.run_pipeline(source_keys=['exploit'], mode='full')
    
    def test_metasploit_load_5(self):
        print("\nTesting Metasploit Load (5 records)...")
        dummy_data = [{
            "fullname": f"exploit/test/module_{i}",
            "name": f"Test Module {i}",
            "title": f"Test Metasploit {i}",
            "mod_time": "2024-01-01",
            "type": "exploit"
        } for i in range(5)]

        self.orchestrator.sources['metasploit']['extractor'].extract = MagicMock(return_value=dummy_data)
        self.orchestrator.run_pipeline(source_keys=['metasploit'], mode='full')

if __name__ == "__main__":
    unittest.main()
