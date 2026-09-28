package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan targets for supply chain threats",
	Long:  `Scan package registries, dependencies, containers, and repositories for supply chain attacks.`,
}

var scanRegistryCmd = &cobra.Command{
	Use:   "registry",
	Short: "Scan package registry for malicious packages",
	Long:  `Scan npm, PyPI, Maven, Go, Cargo, NuGet registries for typosquatting, dependency confusion, and malicious publishes.`,
	RunE:  runScanRegistry,
}

var scanDepsCmd = &cobra.Command{
	Use:   "deps",
	Short: "Scan project dependencies for vulnerabilities and threats",
	Long:  `Analyze lockfiles, manifests, and SBOMs for known vulnerabilities, malicious packages, and supply chain risks.`,
	RunE:  runScanDeps,
}

var scanContainerCmd = &cobra.Command{
	Use:   "container",
	Short: "Scan container images for supply chain compromises",
	Long:  `Analyze container layers, base images, and runtime configs for malicious modifications.`,
	RunE:  runScanContainer,
}

var scanRepoCmd = &cobra.Command{
	Use:   "repo",
	Short: "Scan git repository for supply chain risks",
	Long:  `Check for submodule hijacking, commit signing bypass, malicious workflow files, and repo jacking.`,
	RunE:  runScanRepo,
}

func init() {
	scanCmd.AddCommand(scanRegistryCmd)
	scanCmd.AddCommand(scanDepsCmd)
	scanCmd.AddCommand(scanContainerCmd)
	scanCmd.AddCommand(scanRepoCmd)
	
	scanRegistryCmd.Flags().String("ecosystem", "", "Package ecosystem (npm|pypi|maven|go|cargo|nuget)")
	scanRegistryCmd.Flags().String("package", "", "Package name to scan")
	scanRegistryCmd.Flags().String("version", "", "Specific version to scan (default: latest)")
	scanRegistryCmd.Flags().Bool("all-versions", false, "Scan all published versions")
	scanRegistryCmd.Flags().String("output", "json", "Output format")
	
	scanDepsCmd.Flags().String("file", "", "Lockfile/manifest path (package-lock.json, requirements.txt, go.mod, Cargo.lock, pom.xml)")
	scanDepsCmd.Flags().String("sbom", "", "SBOM file path (SPDX, CycloneDX, Syft JSON)")
	scanDepsCmd.Flags().Bool("recursive", true, "Scan transitive dependencies")
	scanDepsCmd.Flags().Bool("include-dev", false, "Include dev dependencies")
	scanDepsCmd.Flags().String("policy", "", "Policy file for fail thresholds")
	
	scanContainerCmd.Flags().String("image", "", "Container image reference (name:tag or digest)")
	scanContainerCmd.Flags().String("tarball", "", "Container image tarball path")
	scanContainerCmd.Flags().Bool("layers", true, "Analyze individual layers")
	scanContainerCmd.Flags().Bool("base-image", true, "Check base image drift")
	
	scanRepoCmd.Flags().String("path", ".", "Repository path")
	scanRepoCmd.Flags().Bool("submodules", true, "Check submodules")
	scanRepoCmd.Flags().Bool("workflows", true, "Check CI/CD workflows")
	scanRepoCmd.Flags().Bool("signing", true, "Verify commit signing")
	scanRepoCmd.Flags().String("since", "", "Scan commits since date (RFC3339)")
}

func runScanRegistry(cmd *cobra.Command, args []string) error {
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	pkg, _ := cmd.Flags().GetString("package")
	version, _ := cmd.Flags().GetString("version")
	allVersions, _ := cmd.Flags().GetBool("all-versions")
	
	if ecosystem == "" || pkg == "" {
		return fmt.Errorf("ecosystem and package are required")
	}
	
	logger := Logger()
	logger.Info("Starting registry scan",
		zap.String("ecosystem", ecosystem),
		zap.String("package", pkg),
		zap.String("version", version),
		zap.Bool("all_versions", allVersions))
	
	scanner := NewRegistryScanner(ecosystem)
	ctx := context.Background()
	
	var results []ScanResult
	var err error
	
	if allVersions {
		results, err = scanner.ScanAllVersions(ctx, pkg)
	} else {
		result, err := scanner.ScanPackage(ctx, pkg, version)
		if err != nil {
			return err
		}
		results = []ScanResult{result}
	}
	
	if err != nil {
		return err
	}
	
	return outputResults(results, cmd)
}

func runScanDeps(cmd *cobra.Command, args []string) error {
	file, _ := cmd.Flags().GetString("file")
	sbomFile, _ := cmd.Flags().GetString("sbom")
	recursive, _ := cmd.Flags().GetBool("recursive")
	includeDev, _ := cmd.Flags().GetBool("include-dev")
	policyFile, _ := cmd.Flags().GetString("policy")
	
	if file == "" && sbomFile == "" {
		return fmt.Errorf("file or sbom is required")
	}
	
	logger := Logger()
	logger.Info("Starting dependency scan",
		zap.String("file", file),
		zap.String("sbom", sbomFile),
		zap.Bool("recursive", recursive))
	
	scanner := NewDependencyScanner()
	ctx := context.Background()
	
	var results []ScanResult
	var err error
	
	if sbomFile != "" {
		results, err = scanner.ScanSBOM(ctx, sbomFile, recursive)
	} else {
		results, err = scanner.ScanLockfile(ctx, file, recursive, includeDev)
	}
	
	if err != nil {
		return err
	}
	
	if policyFile != "" {
		violations := checkPolicy(results, policyFile)
		if len(violations) > 0 {
			fmt.Fprintf(os.Stderr, "Policy violations: %d\n", len(violations))
			for _, v := range violations {
				fmt.Fprintf(os.Stderr, "  - %s\n", v)
			}
			os.Exit(1)
		}
	}
	
	return outputResults(results, cmd)
}

func runScanContainer(cmd *cobra.Command, args []string) error {
	image, _ := cmd.Flags().GetString("image")
	tarball, _ := cmd.Flags().GetString("tarball")
	layers, _ := cmd.Flags().GetBool("layers")
	baseImage, _ := cmd.Flags().GetBool("base-image")
	
	if image == "" && tarball == "" {
		return fmt.Errorf("image or tarball is required")
	}
	
	logger := Logger()
	logger.Info("Starting container scan",
		zap.String("image", image),
		zap.String("tarball", tarball),
		zap.Bool("layers", layers))
	
	scanner := NewContainerScanner()
	ctx := context.Background()
	
	var results []ScanResult
	var err error
	
	if tarball != "" {
		results, err = scanner.ScanTarball(ctx, tarball, layers, baseImage)
	} else {
		results, err = scanner.ScanImage(ctx, image, layers, baseImage)
	}
	
	if err != nil {
		return err
	}
	
	return outputResults(results, cmd)
}

func runScanRepo(cmd *cobra.Command, args []string) error {
	path, _ := cmd.Flags().GetString("path")
	submodules, _ := cmd.Flags().GetBool("submodules")
	workflows, _ := cmd.Flags().GetBool("workflows")
	signing, _ := cmd.Flags().GetBool("signing")
	since, _ := cmd.Flags().GetString("since")
	
	logger := Logger()
	logger.Info("Starting repository scan",
		zap.String("path", path),
		zap.Bool("submodules", submodules),
		zap.Bool("workflows", workflows))
	
	scanner := NewRepoScanner()
	ctx := context.Background()
	
	results, err := scanner.ScanRepo(ctx, path, ScanRepoOptions{
		CheckSubmodules: submodules,
		CheckWorkflows:  workflows,
		CheckSigning:    signing,
		Since:           since,
	})
	
	if err != nil {
		return err
	}
	
	return outputResults(results, cmd)
}

type ScanResult struct {
	Target      string                 `json:"target"`
	Type        string                 `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	Findings    []Finding              `json:"findings"`
	Summary     ScanSummary            `json:"summary"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type Finding struct {
	ID          string                 `json:"id"`
	RuleID      string                 `json:"rule_id"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Location    string                 `json:"location"`
	Evidence    map[string]interface{} `json:"evidence,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	References  []string               `json:"references,omitempty"`
	CWE         []string               `json:"cwe,omitempty"`
	CVSS        float64                `json:"cvss,omitempty"`
}

type ScanSummary struct {
	Total       int `json:"total"`
	Critical    int `json:"critical"`
	High        int `json:"high"`
	Medium      int `json:"medium"`
	Low         int `json:"low"`
	Informational int `json:"informational"`
}

func outputResults(results []ScanResult, cmd *cobra.Command) error {
	outputFormat, _ := cmd.Flags().GetString("output")
	outputDir, _ := cmd.Flags().GetString("output-dir")
	
	switch outputFormat {
	case "json":
		return outputJSON(results, outputDir)
	case "sarif":
		return outputSARIF(results, outputDir)
	case "html":
		return outputHTML(results, outputDir)
	case "cyclonedx":
		return outputCycloneDX(results, outputDir)
	case "table":
		return outputTable(results)
	default:
		return fmt.Errorf("unknown output format: %s", outputFormat)
	}
}

func outputJSON(results []ScanResult, outputDir string) error {
	for _, r := range results {
		data, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(data))
	}
	return nil
}

func outputSARIF(results []ScanResult, outputDir string) error {
	// SARIF 2.1.0 format
	sarif := map[string]interface{}{
		"$schema":  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
		"version":  "2.1.0",
		"runs":     []interface{}{},
	}
	
	for _, r := range results {
		run := map[string]interface{}{
			"tool": map[string]interface{}{
				"driver": map[string]interface{}{
					"name":    "SUP",
					"version": Version,
					"informationUri": "https://github.com/hailamdev/sup",
					"rules":   []interface{}{},
				},
			},
			"results": []interface{}{},
		}
		
		ruleMap := make(map[string]map[string]interface{})
		
		for _, f := range r.Findings {
			if _, exists := ruleMap[f.RuleID]; !exists {
				ruleMap[f.RuleID] = map[string]interface{}{
					"id":   f.RuleID,
					"name": f.Title,
					"shortDescription": map[string]string{"text": f.Description},
					"fullDescription":  map[string]string{"text": f.Description},
					"defaultConfiguration": map[string]interface{}{
						"level": severityToSARIFLevel(f.Severity),
					},
					"properties": map[string]interface{}{
						"category": f.Category,
						"cwe":      f.CWE,
						"cvss":     f.CVSS,
					},
				}
			}
			
			run["results"] = append(run["results"].([]interface{}), map[string]interface{}{
				"ruleId":    f.RuleID,
				"level":     severityToSARIFLevel(f.Severity),
				"message":   map[string]string{"text": f.Description},
				"locations": []interface{}{
					map[string]interface{}{
						"physicalLocation": map[string]interface{}{
							"artifactLocation": map[string]string{"uri": f.Location},
						},
					},
				},
				"properties": map[string]interface{}{
					"evidence":    f.Evidence,
					"remediation": f.Remediation,
				},
			})
		}
		
		for _, rule := range ruleMap {
			run["tool"].(map[string]interface{})["driver"].(map[string]interface{})["rules"] = 
				append(run["tool"].(map[string]interface{})["driver"].(map[string]interface{})["rules"].([]interface{}), rule)
		}
		
		sarif["runs"] = append(sarif["runs"].([]interface{}), run)
	}
	
	data, _ := json.MarshalIndent(sarif, "", "  ")
	fmt.Println(string(data))
	return nil
}

func outputHTML(results []ScanResult, outputDir string) error {
	html := `<!DOCTYPE html>
<html><head><title>SUP Scan Report</title>
<style>
body { font-family: monospace; margin: 20px; }
.critical { color: #dc3545; } .high { color: #fd7e14; } 
.medium { color: #ffc107; } .low { color: #28a745; } .info { color: #6c757d; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
</style></head><body>
<h1>SUP Supply Chain Scan Report</h1>
<p>Generated: ` + time.Now().Format(time.RFC3339) + `</p>`
	
	for _, r := range results {
		html += fmt.Sprintf(`<h2>Target: %s (%s)</h2>`, r.Target, r.Type)
		html += fmt.Sprintf(`<p>Scan Time: %s | Findings: %d (C:%d H:%d M:%d L:%d I:%d)</p>`,
			r.Timestamp.Format(time.RFC3339), r.Summary.Total, r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Informational)
		
		html += `<table><tr><th>Severity</th><th>Category</th><th>Title</th><th>Location</th><th>Description</th></tr>`
		for _, f := range r.Findings {
			html += fmt.Sprintf(`<tr><td class="%s">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				strings.ToLower(f.Severity), f.Severity, f.Category, f.Title, f.Location, f.Description)
		}
		html += `</table>`
	}
	
	html += `</body></html>`
	fmt.Println(html)
	return nil
}

func outputCycloneDX(results []ScanResult, outputDir string) error {
	// Simplified CycloneDX output
	fmt.Println("CycloneDX output not fully implemented")
	return nil
}

func outputTable(results []ScanResult) error {
	for _, r := range results {
		tbl := table.New("SEVERITY", "CATEGORY", "TITLE", "LOCATION")
		for _, f := range r.Findings {
			tbl.AddRow(f.Severity, f.Category, f.Title, f.Location)
		}
		tbl.Print()
	}
	return nil
}

func severityToSARIFLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical": return "error"
	case "high": return "error"
	case "medium": return "warning"
	case "low": return "note"
	default: return "none"
	}
}

func checkPolicy(results []ScanResult, policyFile string) []string {
	// Policy checking logic
	return []string{}
}

// Scanner implementations (stubs for structure)

type RegistryScanner struct {
	ecosystem string
}

func NewRegistryScanner(ecosystem string) *RegistryScanner {
	return &RegistryScanner{ecosystem: ecosystem}
}

func (s *RegistryScanner) ScanPackage(ctx context.Context, pkg, version string) (ScanResult, error) {
	return ScanResult{
		Target:    fmt.Sprintf("%s/%s@%s", s.ecosystem, pkg, version),
		Type:      "registry",
		Timestamp: time.Now(),
		Findings:  []Finding{},
		Summary:   ScanSummary{},
	}, nil
}

func (s *RegistryScanner) ScanAllVersions(ctx context.Context, pkg string) ([]ScanResult, error) {
	return []ScanResult{}, nil
}

type DependencyScanner struct{}

func NewDependencyScanner() *DependencyScanner {
	return &DependencyScanner{}
}

func (s *DependencyScanner) ScanLockfile(ctx context.Context, file string, recursive, includeDev bool) ([]ScanResult, error) {
	return []ScanResult{}, nil
}

func (s *DependencyScanner) ScanSBOM(ctx context.Context, file string, recursive bool) ([]ScanResult, error) {
	return []ScanResult{}, nil
}

type ContainerScanner struct{}

func NewContainerScanner() *ContainerScanner {
	return &ContainerScanner{}
}

func (s *ContainerScanner) ScanImage(ctx context.Context, image string, layers, baseImage bool) ([]ScanResult, error) {
	return []ScanResult{}, nil
}

func (s *ContainerScanner) ScanTarball(ctx context.Context, tarball string, layers, baseImage bool) ([]ScanResult, error) {
	return []ScanResult{}, nil
}

type ScanRepoOptions struct {
	CheckSubmodules bool
	CheckWorkflows  bool
	CheckSigning    bool
	Since           string
}

type RepoScanner struct{}

func NewRepoScanner() *RepoScanner {
	return &RepoScanner{}
}

func (s *RepoScanner) ScanRepo(ctx context.Context, path string, opts ScanRepoOptions) ([]ScanResult, error) {
	return []ScanResult{}, nil
}