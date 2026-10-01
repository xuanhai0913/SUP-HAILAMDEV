# SUP Usage Guide

## Quick Reference

```bash
# Scan package registry
sup scan registry --ecosystem npm --package lodash --version 4.17.21

# Scan all versions of a package
sup scan registry --ecosystem pypi --package requests --all-versions

# Scan project dependencies
sup scan deps --file package-lock.json --recursive

# Scan with SBOM
sup scan deps --sbom sbom.json --recursive

# Scan container image
sup scan container --image nginx:latest --layers

# Scan repository
sup scan repo --path . --workflows --submodules

# Analyze CI/CD pipeline
sup analyze pipeline --file .github/workflows/ci.yml --platform github

# Analyze build config
sup analyze build --dir . --type npm

# Analyze Dockerfile
sup analyze config --file Dockerfile --type dockerfile

# Analyze install scripts
sup analyze script --dir . --ecosystem npm

# Verify build reproducibility
sup verify build --source . --build-cmd "npm run build" --output dist/

# Verify artifact checksum
sup verify artifact --file artifact.tar.gz --checksum sha256:abc123...

# Verify signature
sup verify signature --file artifact.tar.gz --signature artifact.sig --key pub.key --type cosign

# Verify SBOM
sup verify sbom --artifact artifact.tar.gz --sbom sbom.json

# Diff SBOMs
sup diff sbom --old sbom-v1.json --new sbom-v2.json

# Diff configs
sup diff config --old config-v1.yaml --new config-v2.yaml

# Diff lockfiles
sup diff lockfile --old package-lock.json --new package-lock.json

# Hunt with YARA
sup hunt scan --target . --signatures ./signatures --recursive

# Behavioral analysis
sup hunt behavioral --package lodash@4.17.21 --ecosystem npm --timeout 60

# Correlate findings
sup hunt correlate --input ./results --output ./correlation

# Manage signatures
sup signature list --dir ./signatures --category malware
sup signature validate --dir ./signatures
sup signature create --name "My_Rule" --category suspicious --severity high

# Generate report
sup report generate --input ./results --template executive --format html
```

## Detailed Examples

### 1. NPM Package Registry Scan

```bash
# Scan specific version
sup scan registry --ecosystem npm --package lodash --version 4.17.21 --output json

# Scan all versions for typosquatting
sup scan registry --ecosystem npm --package express --all-versions --output sarif

# Output to file
sup scan registry --ecosystem npm --package axios --version 1.6.0 --output json > axios-scan.json
```

**Findings include:**
- Typosquatting variants (expres, axois, etc.)
- Dependency confusion risks
- Malicious code patterns in package
- Known vulnerable versions
- Maintainer reputation

### 2. Dependency Scanning

```bash
# package-lock.json (npm)
sup scan deps --file package-lock.json --recursive --include-dev

# requirements.txt (PyPI)
sup scan deps --file requirements.txt --recursive

# go.mod / go.sum (Go)
sup scan deps --file go.mod --recursive

# Cargo.lock (Rust)
sup scan deps --file Cargo.lock --recursive

# pom.xml (Maven)
sup scan deps --file pom.xml --recursive

# With SBOM
syft packages dir:. -o json > sbom.json
sup scan deps --sbom sbom.json --recursive
```

**Findings include:**
- Known vulnerabilities (CVE, GHSA)
- Malicious packages (event-stream, ua-parser-js, etc.)
- License compliance issues
- Outdated dependencies
- Transitive dependency risks

### 3. Container Scanning

```bash
# Scan image from registry
sup scan container --image nginx:1.25-alpine --layers --base-image

# Scan local tarball
docker save nginx:latest | gzip > nginx.tar.gz
sup scan container --tarball nginx.tar.gz --layers

# Scan with base image drift detection
sup scan container --image myapp:latest --base-image
```

**Findings include:**
- Base image vulnerabilities
- Malicious layers
- Suspicious runtime configs (USER root, privileged)
- Exposed secrets in layers
- Non-reproducible builds

### 4. Repository Scanning

```bash
# Full repo scan
sup scan repo --path . --workflows --submodules --signing

# Scan only workflows
sup scan repo --path . --workflows --no-submodules --no-signing

# Scan since specific date
sup scan repo --path . --since 2024-01-01T00:00:00Z
```

**Findings include:**
- Submodule hijacking risks
- Unpinned GitHub Actions
- Script injection in workflows
- Secret leakage
- Commit signing bypass
- Repo jacking indicators

### 5. CI/CD Pipeline Analysis

```bash
# GitHub Actions
sup analyze pipeline --file .github/workflows/ci.yml --platform github --check-secrets --check-actions

# GitLab CI
sup analyze pipeline --file .gitlab-ci.yml --platform gitlab

# Jenkins
sup analyze pipeline --file Jenkinsfile --platform jenkins

# Azure DevOps
sup analyze pipeline --file azure-pipelines.yml --platform azure
```

**Findings include:**
- Unpinned actions (uses: actions/checkout@main)
- Script injection via ${{ github.event... }}
- Hardcoded secrets
- Excessive permissions
- Untrusted reusable workflows

### 6. Build Analysis

```bash
# npm scripts
sup analyze build --file package.json --type npm

# Makefile
sup analyze build --file Makefile --type make

# Gradle
sup analyze build --file build.gradle --type gradle

# Maven
sup analyze build --file pom.xml --type maven
```

**Findings include:**
- Suspicious install scripts
- Arbitrary code execution in build
- Unverified downloads
- Timestamp injection
- Path manipulation

### 7. Config Analysis

```bash
# Dockerfile
sup analyze config --file Dockerfile --type dockerfile

# Kubernetes
sup analyze config --dir k8s/ --type k8s

# Helm
sup analyze config --dir helm/ --type helm

# Docker Compose
sup analyze config --file docker-compose.yml --type compose
```

**Findings include:**
- Base image drift (latest tags)
- Privileged containers
- Host path mounts
- Exposed secrets
- Insecure capabilities

### 8. Script Analysis

```bash
# npm package.json scripts
sup analyze script --file package.json --ecosystem npm

# Python setup.py
sup analyze script --file setup.py --ecosystem pypi

# Rust Cargo.toml
sup analyze script --file Cargo.toml --ecosystem cargo
```

**Findings include:**
- Malicious install/postinstall scripts
- Credential exfiltration
- Process execution
- Network callbacks
- Persistence mechanisms

### 9. Build Verification

```bash
# Reproducible build check
sup verify build --source . --build-cmd "npm run build" --output "dist/*" --iterations 3 --clean

# With custom environment
sup verify build --source . --build-cmd "docker build -t test ." --output "test:latest" --iterations 2
```

**Checks:**
- Bit-for-bit reproducibility
- Timestamp injection
- Path dependencies
- Non-deterministic outputs

### 10. Artifact Verification

```bash
# Checksum verification
sup verify artifact --file app.tar.gz --checksum sha256:a1b2c3... --algorithm sha256

# From checksum file
sup verify artifact --file app.tar.gz --checksum-file SHA256SUMS
```

### 11. Signature Verification

```bash
# cosign
sup verify signature --file app.tar.gz --signature app.tar.gz.sig --key cosign.pub --type cosign

# GPG
sup verify signature --file app.tar.gz --signature app.tar.gz.asc --key public.gpg --type gpg
```

### 12. SBOM Verification

```bash
# Generate SBOM
syft packages dir:. -o spdx-json > sbom.json

# Verify against artifact
sup verify sbom --artifact app.tar.gz --sbom sbom.json --format spdx
```

### 13. Diff Operations

```bash
# SBOM diff (dependency changes)
sup diff sbom --old sbom-v1.json --new sbom-v2.json --show-unchanged

# Config drift
sup diff config --old prod-config.yaml --new staging-config.yaml

# Lockfile changes
sup diff lockfile --old package-lock.json --new package-lock.json --ecosystem npm
```

**Output shows:**
- Added dependencies
- Removed dependencies
- Version changes (with severity)
- License changes
- New vulnerabilities introduced

### 14. Threat Hunting

```bash
# YARA scan
sup hunt scan --target ./project --signatures ./signatures --recursive --threads 8

# Specific rule set
sup hunt scan --target ./project --rules ./signatures/malware/cryptominers.yar

# Behavioral (requires sandbox)
sup hunt behavioral --package suspicious-pkg@1.0.0 --ecosystem npm --sandbox docker --timeout 120

# Correlation
sup hunt correlate --input ./scan-results --output ./campaigns --threshold 0.8
```

### 15. Signature Management

```bash
# List all
sup signature list --dir ./signatures

# Filter
sup signature list --category exploit --severity critical

# Validate
sup signature validate --dir ./signatures

# Create new
sup signature create --name "Detect_X" --category suspicious --severity high --author "analyst" --description "Detects X"

# Update from feeds
sup signature update --dir ./signatures --force
```

### 16. Reporting

```bash
# Executive summary
sup report generate --input ./results --template executive --format html --title "Q1 Supply Chain Report"

# Technical detail
sup report generate --input ./results --template technical --format pdf

# Compliance (SLSA, NIST SSDF)
sup report generate --input ./results --template compliance --format html

# List reports
sup report list --dir ./reports --format html
```

## Output Formats

| Format | Use Case |
|--------|----------|
| `json` | Automation, SIEM ingestion |
| `sarif` | GitHub Code Scanning, IDE integration |
| `html` | Human review, sharing |
| `cyclonedx` | SBOM compliance |
| `table` | Quick CLI review |

## Configuration

### Config File (config/sup.yaml)
```yaml
registries:
  npm:
    endpoint: "https://registry.npmjs.org"
    rate_limit: 100

detectors:
  typosquatting:
    threshold: 0.85
  malicious_code:
    entropy_threshold: 7.5

reporting:
  formats: ["json", "sarif", "html"]
  output_dir: "./reports"
```

### Environment Variables
```bash
export SUP_CONFIG=/custom/path/sup.yaml
export GITHUB_TOKEN=ghp_xxxxxxxx
export SLACK_WEBHOOK=https://hooks.slack.com/xxx
```

## Integration Examples

### GitHub Actions
```yaml
# .github/workflows/supply-chain.yml
name: Supply Chain Scan
on: [push, pull_request, schedule]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run SUP
        run: |
          curl -sL https://github.com/hailamdev/sup/releases/latest/download/sup-linux -o sup
          chmod +x sup
          ./sup scan deps --file package-lock.json --output sarif > results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI
```yaml
# .gitlab-ci.yml
supply_chain_scan:
  image: sup-cli:latest
  script:
    - sup scan deps --file requirements.txt --output json > results.json
  artifacts:
    reports:
      sast: results.json
```

### Pre-commit Hook
```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: sup-scan
      name: SUP Supply Chain Scan
      entry: sup scan deps --file package-lock.json
      language: system
      types: [file]
      args: [--output, json]
```

## Troubleshooting

### No Findings but Suspicious Package
- Lower entropy threshold: `--entropy-threshold 7.0`
- Enable dynamic analysis: `--dynamic-analysis`
- Check custom signatures

### False Positives
- Add exceptions to policy file
- Adjust severity thresholds
- Update signatures

### Performance Issues
- Increase workers: `--threads 8`
- Disable recursive: `--no-recursive`
- Use exclude patterns: `--exclude node_modules,.git`

### Sandbox Errors
- Ensure Docker is running
- Check sandbox image: `docker pull sup-sandbox:latest`
- Increase timeout: `--timeout 120`

## SentinelFlow Engagement Notes

- Reports auto-formatted for Palantir audit format
- Dr. Reyes reviews all critical findings
- Thursday handoff includes correlation clusters
- $50k penalty if Q4 deadline missed
- Strand requires behavioral analysis for all npm packages