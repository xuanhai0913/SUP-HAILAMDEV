# SUP API Documentation

## Overview
REST API for SUP Supply Chain Attack Detection Framework

## Base URL
```
http://localhost:8080/api/v1
```

## Authentication
Bearer token required for all endpoints:
```
Authorization: Bearer <token>
```

## Endpoints

### Health
```
GET /health
```
Response: `{"status": "ok", "version": "1.0.0"}`

### Scans

#### Start Registry Scan
```
POST /scans/registry
```
Body:
```json
{
  "ecosystem": "npm",
  "package": "lodash",
  "version": "4.17.21",
  "all_versions": false
}
```

#### Start Dependency Scan
```
POST /scans/dependencies
```
Body:
```json
{
  "file": "package-lock.json",
  "sbom": "",
  "recursive": true,
  "include_dev": false
}
```

#### Start Container Scan
```
POST /scans/container
```
Body:
```json
{
  "image": "nginx:latest",
  "tarball": "",
  "layers": true,
  "base_image": true
}
```

#### Start Repository Scan
```
POST /scans/repository
```
Body:
```json
{
  "path": "/path/to/repo",
  "submodules": true,
  "workflows": true,
  "signing": true
}
```

#### Get Scan Status
```
GET /scans/{id}
```

#### List Scans
```
GET /scans?status=completed&limit=50
```

#### Get Scan Results
```
GET /scans/{id}/results?format=json
```

### Analysis

#### Analyze Pipeline
```
POST /analyze/pipeline
```
Body:
```json
{
  "file": ".github/workflows/ci.yml",
  "platform": "github",
  "check_secrets": true,
  "check_actions": true,
  "check_injection": true
}
```

#### Analyze Build
```
POST /analyze/build
```
Body:
```json
{
  "file": "package.json",
  "type": "npm"
}
```

#### Analyze Config
```
POST /analyze/config
```
Body:
```json
{
  "file": "Dockerfile",
  "type": "dockerfile"
}
```

#### Analyze Script
```
POST /analyze/script
```
Body:
```json
{
  "file": "package.json",
  "ecosystem": "npm"
}
```

### Verification

#### Verify Build Reproducibility
```
POST /verify/build
```
Body:
```json
{
  "source": "/path/to/source",
  "build_cmd": "npm run build",
  "output": "dist/",
  "iterations": 2
}
```

#### Verify Artifact
```
POST /verify/artifact
```
Body:
```json
{
  "file": "artifact.tar.gz",
  "checksum": "sha256:...",
  "algorithm": "sha256"
}
```

#### Verify Signature
```
POST /verify/signature
```
Body:
```json
{
  "file": "artifact.tar.gz",
  "signature": "artifact.tar.gz.sig",
  "key": "public.key",
  "type": "cosign"
}
```

#### Verify SBOM
```
POST /verify/sbom
```
Body:
```json
{
  "artifact": "artifact.tar.gz",
  "sbom": "sbom.json",
  "format": "spdx"
}
```

### Diff

#### Diff SBOMs
```
POST /diff/sbom
```
Body:
```json
{
  "old": "sbom-v1.json",
  "new": "sbom-v2.json",
  "format": "spdx",
  "show_unchanged": false
}
```

#### Diff Configs
```
POST /diff/config
```
Body:
```json
{
  "old": "config-v1.yaml",
  "new": "config-v2.yaml",
  "type": "yaml"
}
```

#### Diff Artifacts
```
POST /diff/artifact
```
Body:
```json
{
  "old": "artifact-v1.tar.gz",
  "new": "artifact-v2.tar.gz",
  "algorithm": "sha256"
}
```

#### Diff Lockfiles
```
POST /diff/lockfile
```
Body:
```json
{
  "old": "package-lock.json",
  "new": "package-lock.json",
  "ecosystem": "npm"
}
```

### Hunt

#### Hunt Scan
```
POST /hunt/scan
```
Body:
```json
{
  "target": "/path/to/scan",
  "signatures": "./signatures",
  "rules": "",
  "recursive": true,
  "exclude": ["node_modules", ".git"],
  "threads": 4
}
```

#### Hunt Behavioral
```
POST /hunt/behavioral
```
Body:
```json
{
  "package": "lodash@4.17.21",
  "ecosystem": "npm",
  "sandbox": "docker",
  "timeout": 60,
  "network": false
}
```

#### Hunt Correlate
```
POST /hunt/correlate
```
Body:
```json
{
  "input": "./scan-results",
  "output": "./correlation",
  "threshold": 0.7
}
```

### Signatures

#### List Signatures
```
GET /signatures?category=malware&severity=critical
```

#### Validate Signature
```
POST /signatures/validate
```
Body:
```json
{
  "file": "rule.yar"
}
```

#### Create Signature
```
POST /signatures
```
Body:
```json
{
  "name": "Custom_Rule",
  "category": "suspicious",
  "severity": "high",
  "author": "analyst",
  "description": "Custom detection rule",
  "content": "rule Custom_Rule { ... }"
}
```

#### Update Signatures
```
POST /signatures/update
```
Body:
```json
{
  "feeds": ["https://feed.example.com/rules.yar"],
  "force": false
}
```

### Reports

#### Generate Report
```
POST /reports
```
Body:
```json
{
  "input": "./scan-results",
  "template": "executive",
  "format": "html",
  "title": "Monthly Supply Chain Report"
}
```

#### List Reports
```
GET /reports?format=html
```

#### Get Report
```
GET /reports/{id}
```

#### Download Report
```
GET /reports/{id}/download
```

### Configuration

#### Get Config
```
GET /config
```

#### Update Config
```
PUT /config
```

## WebSocket

### Real-time Scan Updates
```
WS /ws/scans/{id}
```
Messages:
```json
{"type": "progress", "scan_id": "uuid", "progress": 0.5, "message": "Scanning dependencies..."}
{"type": "finding", "scan_id": "uuid", "finding": {...}}
{"type": "complete", "scan_id": "uuid", "summary": {...}}
```

### Real-time Hunt Updates
```
WS /ws/hunt/{id}
```

## Error Responses
```json
{
  "error": "description",
  "code": "ERROR_CODE",
  "details": {}
}
```

HTTP Status Codes:
- 200 - Success
- 201 - Created
- 202 - Accepted (async operation)
- 400 - Bad Request
- 401 - Unauthorized
- 404 - Not Found
- 500 - Internal Server Error