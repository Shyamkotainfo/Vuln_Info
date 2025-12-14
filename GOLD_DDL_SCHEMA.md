# Gold Layer - Database Schema (DDL)

This document provides MongoDB collection schemas for the Gold Layer.
**Note**: These tables are created as empty structures. You populate them manually.

## 1. Source Mirrors (5 Collections)

### gold_nvd
```javascript
{
  "_id": "CVE-2021-44228",
  "id": "CVE-2021-44228",
  "published": "2021-12-10T10:15:09.067",
  "lastModified": "2023-11-07T03:44:03.267",
  "descriptions": [{value: "Apache Log4j2 2.0-beta9..."}],
  "metrics_cvssMetricV31": [{cvssData: {baseScore: 10.0, ...}}],
  "weaknesses": [{description: [{value: "CWE-502"}]}],
  "references": [...],
  "gold_created_at": ISODate("2025-12-12T..."),
  "gold_updated_at": ISODate("2025-12-12T...")
}
```

### gold_cisa
```javascript
{
  "_id": "CVE-2021-44228",
  "cve_id": "CVE-2021-44228",
  "vendor_project": "Apache",
  "product": "Log4j2",
  "vulnerability_name": "Apache Log4j2 Remote Code Execution",
  "date_added": "2021-12-10",
  "short_description": "Apache Log4j2 contains...",
  "required_action": "Apply updates per vendor instructions.",
  "due_date": "2021-12-24",
  "known_ransomware_campaign_use": "Known",
  "notes": "",
  "gold_created_at": ISODate("2025-12-12T..."),
  "gold_updated_at": ISODate("2025-12-12T...")
}
```

### gold_epss
```javascript
{
  "_id": "CVE-2021-44228",
  "cve": "CVE-2021-44228",
  "epss": 0.97536,
  "percentile": 0.99999,
  "date": "2025-12-12",
  "gold_created_at": ISODate("2025-12-12T..."),
  "gold_updated_at": ISODate("2025-12-12T...")
}
```

### gold_exploit
```javascript
{
  "_id": "50592",
  "id": "50592",
  "file": "exploits/multiple/remote/50592.py",
  "description": "Apache Log4j2 - Remote Code Execution (RCE)",
  "date_published": "2022-12-13",
  "author": "kozmer",
  "type": "remote",
  "platform": "multiple",
  "verified": true,
  "codes": ["CVE-2021-44228"],
  "tags": ["java", "log4j", "rce"],
  "screenshot_url": null,
  "application_url": null,
  "source_url": "https://www.exploit-db.com/exploits/50592",
  "gold_created_at": ISODate("2025-12-12T..."),
  "gold_updated_at": ISODate("2025-12-12T...")
}
```

### gold_metasploit
```javascript
{
  "_id": "exploit/multi/http/log4shell_header_injection",
  "fullname": "exploit/multi/http/log4shell_header_injection",
  "name": "Log4Shell HTTP Header Injection",
  "type": "exploit",
  "rank": "excellent",
  "description": "This module exploits...",
  "references": ["CVE-2021-44228", "URL-https://..."],
  "platform": "java",
  "arch": "",
  "rport": "8080",
  "mod_time": "2023-01-01 00:00:00 UTC",
  "gold_created_at": ISODate("2025-12-12T..."),
  "gold_updated_at": ISODate("2025-12-12T...")
}
```

## 2. Dimensional Aggregates (4 Collections)

### gold_vrr (Risk Factors)
**Purpose**: Stores all risk factors for VRR calculation in long format.

```javascript
{
  "_id": "a1b2c3d4e5f6...",  // MD5 hash of cve_id + factor_name + table
  "s_no": "a1b2c3d4e5f6...",  // Same as _id
  "cve_id": "CVE-2021-44228",
  "factor_name": "cvss_v3_score",
  "value": 10.0,  // Can be number, boolean, or string
  "category": "Base Severity",
  "static_or_dynamic": "Dynamic",  // "Dynamic" from sources, "Static" for manual
  "source": "nvd",  // Source collection name
  "gold_created_at": ISODate("2025-12-12T..."),
  "gold_updated_at": ISODate("2025-12-12T...")
}
```

**Indexes**:
```javascript
db.gold_vrr.createIndex({cve_id: 1})
db.gold_vrr.createIndex({factor_name: 1})
db.gold_vrr.createIndex({cve_id: 1, factor_name: 1})
```

### gold_threats (Threat Intelligence)
**Purpose**: Active exploitation indicators.

```javascript
{
  "_id": "b2c3d4e5f6g7...",
  "s_no": "b2c3d4e5f6g7...",
  "cve_id": "CVE-2021-44228",
  "factor_name": "kev_listed",
  "value": true,
  "category": "Active Exploitation",
  "static_or_dynamic": "Dynamic",
  "source": "cisa",
  "gold_created_at": ISODate("2025-12-12T..."),
  "gold_updated_at": ISODate("2025-12-12T...")
}
```

**Indexes**:
```javascript
db.gold_threats.createIndex({cve_id: 1})
db.gold_threats.createIndex({factor_name: 1})
```

### gold_vulnerabilities (Metadata)
**Purpose**: Descriptive information about the vulnerability.

```javascript
{
  "_id": "c3d4e5f6g7h8...",
  "s_no": "c3d4e5f6g7h8...",
  "cve_id": "CVE-2021-44228",
  "factor_name": "description",
  "value": "Apache Log4j2 2.0-beta9 through 2.15.0...",
  "category": "Metadata",
  "static_or_dynamic": "Dynamic",
  "source": "nvd",
  "gold_created_at": ISODate("2025-12-12T..."),
  "gold_updated_at": ISODate("2025-12-12T...")
}
```

**Indexes**:
```javascript
db.gold_vulnerabilities.createIndex({cve_id: 1})
```

### gold_weaknesses (CWE Mappings)
**Purpose**: Root cause classification.

```javascript
{
  "_id": "d4e5f6g7h8i9...",
  "s_no": "d4e5f6g7h8i9...",
  "cve_id": "CVE-2021-44228",
  "factor_name": "primary_cwe",
  "value": "CWE-502",
  "category": "CWE",
  "static_or_dynamic": "Dynamic",
  "source": "nvd",
  "gold_created_at": ISODate("2025-12-12T..."),
  "gold_updated_at": ISODate("2025-12-12T...")
}
```

**Indexes**:
```javascript
db.gold_weaknesses.createIndex({cve_id: 1})
db.gold_weaknesses.createIndex({value: 1})  // For CWE lookups
```

## 3. Master/Final Table

### gold_master
**Purpose**: Consolidated view joining all dimensions by CVE.

```javascript
{
  "_id": "CVE-2021-44228",
  "cve_id": "CVE-2021-44228",
  
  // VRR Calculation Results
  "vrr_score": 95.5,
  "vrr_category": "CRITICAL",
  
  // Aggregated Threat Indicators
  "threat_level": "HIGH",
  "in_kev": true,
  "epss_score": 0.97536,
  "exploit_count": 5,
  "metasploit_modules": 2,
  
  // Metadata Summary
  "title": "Apache Log4j2 Remote Code Execution",
  "published_date": "2021-12-10",
  "cvss_v3_score": 10.0,
  "primary_cwe": "CWE-502",
  
  // Timestamps
  "gold_created_at": ISODate("2025-12-12T..."),
  "gold_updated_at": ISODate("2025-12-12T...")
}
```

**Indexes**:
```javascript
db.gold_master.createIndex({cve_id: 1}, {unique: true})
db.gold_master.createIndex({vrr_score: -1})
db.gold_master.createIndex({threat_level: 1})
db.gold_master.createIndex({in_kev: 1})
```

## How to Create Collections

Run the Gold layer once to create empty collections with indexes:
```bash
python3 -m vulnerability_pipeline.pipeline_orchestrator --layer gold
```

This will:
1. Create all 10 Gold collections
2. Set up indexes
3. **NOT** populate data (manual mode enabled)

## How to Populate Data

See `how_to_add_gold_values.py` for examples of manual insertion.
