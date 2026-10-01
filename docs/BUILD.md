# SUP Build Instructions

## Prerequisites
- Go 1.21+
- Docker (for container scanning, sandboxing)
- YARA 4.2+ (libyara-dev)
- Git
- Make

## Quick Start

### 1. Install Dependencies
```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y libyara-dev docker.io

# macOS
brew install yara docker

# Go dependencies
go mod download
go mod verify
```

### 2. Build
```bash
# Standard build
make build

# Cross-platform build
make build-all

# With symbols stripped
make build LDFLAGS="-s -w"

# Obfuscated build (requires garble)
make obfuscate
```

### 3. Generate Certificates (for API server)
```bash
make certs
```

### 4. Run
```bash
# CLI
./bin/sup scan registry --ecosystem npm --package lodash

# API Server
./bin/sup-api
```

## Build Targets

| Target | Description |
|--------|-------------|
| `build` | Build CLI for current platform |
| `build-all` | Build for Linux, Windows, macOS (Intel + ARM) |
| `build-linux` | Linux amd64 |
| `build-windows` | Windows amd64 |
| `build-macos` | macOS amd64 + arm64 |
| `obfuscate` | Garble-obfuscated build |
| `certs` | Generate TLS certificates |
| `docker` | Build Docker images |
| `test` | Run unit tests |
| `lint` | Run golangci-lint |
| `clean` | Remove build artifacts |

## Cross-Compilation

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o bin/sup-linux ./src

# Windows
GOOS=windows GOARCH=amd64 go build -o bin/sup.exe ./src

# macOS Intel
GOOS=darwin GOARCH=amd64 go build -o bin/sup-macos ./src

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o bin/sup-macos-arm ./src
```

## Docker Builds

### CLI Image
```dockerfile
FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git make libyara-dev
WORKDIR /app
COPY . .
RUN make build

FROM alpine:3.18
RUN apk add --no-cache libyara docker-cli
WORKDIR /app
COPY --from=builder /app/bin/sup .
COPY --from=builder /app/signatures ./signatures
COPY --from=builder /app/config ./config
ENTRYPOINT ["./sup"]
```

```bash
docker build -f Dockerfile.cli -t sup-cli:latest .
docker run -v $(pwd):/workspace sup-cli scan deps --file /workspace/package-lock.json
```

### API Server Image
```dockerfile
FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git make libyara-dev
WORKDIR /app
COPY . .
RUN make build-api

FROM alpine:3.18
RUN apk add --no-cache libyara ca-certificates
WORKDIR /app
COPY --from=builder /app/bin/sup-api .
COPY --from=builder /app/config ./config
COPY --from=builder /app/signatures ./signatures
EXPOSE 8080
ENTRYPOINT ["./sup-api"]
```

```bash
docker build -f Dockerfile.api -t sup-api:latest .
docker run -p 8080:8080 -v $(pwd)/config:/app/config sup-api
```

## Obfuscation

### Garble (Recommended)
```bash
go install mvdan.cc/garble@latest
garble -literals -tiny -seed=random build -o bin/sup-obf ./src
```

### UPX Compression
```bash
upx --best --lzma bin/sup
```

## Development

### Run Tests
```bash
# Unit tests
go test ./... -v

# Integration tests
go test ./tests/... -v -tags=integration

# With coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Linting
```bash
golangci-lint run ./...
```

### Formatting
```bash
go fmt ./...
goimports -w ./src
```

## Configuration

### Environment Variables
```bash
export SUP_CONFIG=/path/to/sup.yaml
export GITHUB_TOKEN=ghp_xxx
export GITLAB_TOKEN=glpat_xxx
export SLACK_WEBHOOK=https://hooks.slack.com/xxx
```

### Config File Locations (priority order)
1. `-c/--config` flag
2. `./config/sup.yaml`
3. `~/config/sup.yaml`
4. `~/.sup/sup.yaml`
5. `/etc/sup/sup.yaml`

## Troubleshooting

### YARA Compilation Errors
```bash
# Check YARA version
yara --version

# Reinstall libyara
sudo apt-get install --reinstall libyara-dev
```

### Docker Permission Issues
```bash
sudo usermod -aG docker $USER
newgrp docker
```

### Module Download Failures
```bash
go mod download -x
GOPROXY=https://proxy.golang.org go mod download
```

### Cross-Compilation CGO Issues
```bash
# For YARA, CGO is required
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o bin/sup-linux ./src
```

## Release Process

```bash
# Tag version
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# GitHub Actions will build and release binaries
# See .github/workflows/release.yml
```

## SentinelFlow Integration

```bash
# Build for SentinelFlow audit
make build-all SENTINEL=1

# Output includes:
# - Binaries for all platforms
# - SBOM (CycloneDX)
# - Provenance attestation
# - Signature verification
```