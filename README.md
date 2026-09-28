# SUP-HAILAMDEV

**SUP (Supply-chain Security Utility)** là khung dòng lệnh viết bằng Go nhằm hỗ trợ rà soát rủi ro trong chuỗi cung ứng phần mềm: package, dependency, SBOM, CI/CD, build artifact, container và Git repository.

> **Disclaimer — authorized lab/research only:** Chỉ sử dụng dự án trong phòng lab hoặc cho nghiên cứu được ủy quyền. Chỉ quét, phân tích hoặc kiểm tra hệ thống, repository, package và artifact mà bạn sở hữu hoặc có sự cho phép bằng văn bản. Không sử dụng cho truy cập trái phép, phát tán mã độc, né kiểm soát hoặc thu thập dữ liệu của bên thứ ba.

## Tổng quan

SUP cung cấp một bộ lệnh CLI để:

- Quét dependency, lockfile và SBOM.
- Rà soát package registry cho các dấu hiệu như typosquatting hoặc dependency confusion.
- Phân tích cấu hình CI/CD, build script, Docker/Kubernetes/Helm và install script.
- Kiểm tra container image hoặc tarball.
- Kiểm tra repository Git, submodule, workflow và commit signing.
- So sánh SBOM, lockfile, cấu hình và artifact giữa hai phiên bản.
- Tạo, kiểm tra và nạp rule YARA để threat hunting.
- Kiểm tra checksum SHA-256 của artifact và sinh kết quả JSON/SARIF/HTML/table.

## Trạng thái hiện tại

Repository hiện ở mức **prototype/skeleton**. Phần CLI, kiểu dữ liệu và luồng xử lý chính đã được dựng, nhưng nhiều engine phân tích chưa triển khai đầy đủ:

| Khu vực | Trạng thái |
|---|---|
| CLI Cobra, cấu hình YAML và logging | Có khung xử lý |
| Tạo/list/validate rule YARA | Có một phần, cần thư viện YARA |
| Kiểm tra checksum SHA-256 | Có triển khai |
| Quét registry, dependency, container và repository | Khung API; backend hiện trả về kết quả rỗng |
| Phân tích CI/CD, build, config và script | Khung API; chưa có detector thực tế |
| Diff SBOM, config, artifact và lockfile | Khung API; chưa có logic so sánh hoàn chỉnh |
| Build reproducibility, chữ ký và đối chiếu SBOM | Chưa hoàn thiện; còn placeholder |
| Behavioral hunting, correlation và threat-intel update | Chưa hoàn thiện |
| CycloneDX, hunt SARIF/HTML, report merge/generate | Chưa hoàn thiện |

Vì vậy, không nên dùng kết quả hiện tại làm bằng chứng duy nhất cho quyết định bảo mật hoặc phát hành phần mềm.

## Kiến trúc repository

```text
.
├── config/
│   └── sup.yaml          # Cấu hình mẫu
├── src/
│   ├── main.go           # Entry point
│   └── cmd/
│       ├── root.go       # CLI root, config và logging
│       ├── scan.go       # Quét registry/dependency/container/repository
│       ├── analyze.go    # Phân tích CI/CD, build, config, script
│       ├── verify.go     # Verify artifact, build, signature, SBOM
│       ├── diff.go       # So sánh SBOM/config/artifact/lockfile
│       ├── hunt.go       # YARA hunting và correlation
│       ├── signature.go  # Quản lý rule YARA
│       └── report.go     # Sinh và quản lý report
└── go.mod
```

## Yêu cầu

- Go 1.21 trở lên.
- C compiler và thư viện native YARA nếu sử dụng các lệnh liên quan đến YARA.
- Quyền đọc đối với target cần phân tích.
- Kết nối mạng và token tương ứng nếu bật threat-intelligence feed hoặc integration.

## Build

Sau khi các lỗi build hiện tại được xử lý, có thể build theo hướng dẫn:

```bash
go mod download
mkdir -p bin
go build -o bin/sup ./src
```

Kiểm tra thông tin phiên bản:

```bash
./bin/sup version
```

## Cấu trúc lệnh

```text
sup
├── scan
│   ├── registry
│   ├── deps
│   ├── container
│   └── repo
├── analyze
│   ├── pipeline
│   ├── build
│   ├── config
│   └── script
├── verify
│   ├── build
│   ├── artifact
│   ├── signature
│   └── sbom
├── diff
│   ├── sbom
│   ├── config
│   ├── artifact
│   └── lockfile
├── hunt
│   ├── scan
│   ├── behavioral
│   └── correlate
├── signature
│   ├── list
│   ├── validate
│   ├── create
│   ├── update
│   ├── test
│   └── export
├── report
└── version
```

Một số tùy chọn cấp root:

```text
--config       Đường dẫn file cấu hình
--output       Định dạng output: json, sarif, html, cyclonedx hoặc table
--output-dir   Thư mục output, mặc định ./reports
--verbose      Bật log chi tiết
--no-color     Tắt màu trong output
```

## Ví dụ sử dụng

Các ví dụ dưới đây mô tả giao diện CLI dự kiến:

```bash
# Quét một repository trong phạm vi được ủy quyền
./bin/sup scan repo --path ./project --output table

# Quét lockfile hoặc manifest
./bin/sup scan deps --file ./go.mod --output json

# Phân tích workflow CI/CD
./bin/sup analyze pipeline --file .github/workflows/ci.yml --output table

# Kiểm tra SHA-256 của artifact
./bin/sup verify artifact \
  --file ./dist/app.tar.gz \
  --checksum sha256:<expected-sha256> \
  --output table

# Tạo rule YARA mẫu
./bin/sup signature create \
  --name suspicious_rule \
  --category suspicious \
  --severity medium

# Liệt kê và kiểm tra rule YARA
./bin/sup signature list --dir ./signatures
./bin/sup signature validate --dir ./signatures

# Threat hunting trên thư mục được phép kiểm tra
./bin/sup hunt scan \
  --target ./project \
  --rules ./signatures \
  --output table
```

## Cấu hình

File mẫu nằm tại [`config/sup.yaml`](config/sup.yaml). Có thể truyền file khác bằng `--config`:

```bash
./bin/sup --config ./config/sup.yaml scan repo --path ./project
```

Các nhóm cấu hình chính:

- `registries`: endpoint và cache cho npm, PyPI, Maven, Go, Cargo, NuGet.
- `detectors`: bật/tắt nhóm detector và ngưỡng phát hiện.
- `analysis`: giới hạn phân tích tĩnh, động và sandbox.
- `signatures`: đường dẫn rule YARA và lịch cập nhật.
- `reporting`: định dạng, thư mục output và thời gian lưu report.
- `integrations`: GitHub, GitLab, Jenkins, Slack và Jira.
- `threat_intel`: feed Sonatype, GitHub Advisory, OSV, NVD và Snyk.

Không ghi token, webhook hoặc credential trực tiếp vào repository. Cấu hình dùng biến môi trường như `GITHUB_TOKEN`, `SLACK_WEBHOOK`, `JENKINS_TOKEN` và các biến tương ứng.

## Output và giới hạn

Kết quả scan có thể được biểu diễn dưới dạng JSON, SARIF, HTML hoặc bảng terminal. Một số lệnh hiện in kết quả trực tiếp ra stdout; tùy chọn `--output-dir` chưa được áp dụng thống nhất cho mọi backend.

Các giới hạn đáng chú ý:

- `sha512` và `blake3` chưa được triển khai trong verifier.
- Kiểm tra checksum file, chữ ký cosign/GPG/Sigstore và so sánh SBOM chưa hoàn chỉnh.
- Một số lệnh update/export/test/merge chỉ mới có giao diện và thông báo placeholder.
- Các detector chính chưa phân tích thực tế nên kết quả rỗng không đồng nghĩa target an toàn.
- Cần bổ sung test tự động, fixture mẫu và cơ chế sandbox trước khi dùng trong pipeline thật.

## Định hướng phát triển

1. Sửa lỗi build và bổ sung test cho từng command.
2. Tách các scanner/analyzer thành package riêng thay vì để chung trong `src/cmd`.
3. Triển khai parser cho từng hệ sinh thái và detector theo từng loại rủi ro.
4. Hoàn thiện output SARIF/CycloneDX/HTML và chuẩn hóa exit code theo severity.
5. Bổ sung sandbox thật, kiểm soát network và cơ chế lưu evidence an toàn.
6. Bổ sung CI kiểm tra dependency, lint, test và reproducible build.

## Tác giả

**Nguyễn Xuân Hải**

- LinkedIn: [linkedin.com/in/xuanhai0913](https://www.linkedin.com/in/xuanhai0913/)
- Facebook: [facebook.com/nguyenhai0913](https://www.facebook.com/nguyenhai0913)

## License

Internal use only — SentinelFlow engagement.
