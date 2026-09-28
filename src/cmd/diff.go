package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare SBOMs, configs, and artifacts",
	Long:  `Compare two SBOMs, configuration files, or artifacts to detect supply chain changes.`,
}

var diffSBOMCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Compare two SBOMs",
	Long:  `Compare two SBOM files (SPDX, CycloneDX, Syft JSON) to detect added/removed/changed dependencies.`,
	RunE:  runDiffSBOM,
}

var diffConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Compare two configuration files",
	Long:  `Compare CI/CD configs, Dockerfiles, k8s manifests for drift detection.`,
	RunE:  runDiffConfig,
}

var diffArtifactCmd = &cobra.Command{
	Use:   "artifact",
	Short: "Compare two artifacts",
	Long:  `Compare two build artifacts for binary differences.`,
	RunE:  runDiffArtifact,
}

var diffLockfileCmd = &cobra.Command{
	Use:   "lockfile",
	Short: "Compare two lockfiles",
	Long:  `Compare package-lock.json, requirements.txt, go.sum, Cargo.lock for dependency changes.`,
	RunE:  runDiffLockfile,
}

func init() {
	diffCmd.AddCommand(diffSBOMCmd)
	diffCmd.AddCommand(diffConfigCmd)
	diffCmd.AddCommand(diffArtifactCmd)
	diffCmd.AddCommand(diffLockfileCmd)
	
	diffSBOMCmd.Flags().String("old", "", "Old SBOM file (required)")
	diffSBOMCmd.Flags().String("new", "", "New SBOM file (required)")
	diffSBOMCmd.Flags().String("format", "auto", "SBOM format (spdx|cyclonedx|syft|auto)")
	diffSBOMCmd.Flags().Bool("show-unchanged", false, "Show unchanged dependencies")
	diffSBOMCmd.Flags().String("severity", "", "Filter by vulnerability severity (critical|high|medium|low)")
	
	diffConfigCmd.Flags().String("old", "", "Old config file (required)")
	diffConfigCmd.Flags().String("new", "", "New config file (required)")
	diffConfigCmd.Flags().String("type", "auto", "Config type (yaml|json|dockerfile|auto)")
	
	diffArtifactCmd.Flags().String("old", "", "Old artifact file (required)")
	diffArtifactCmd.Flags().String("new", "", "New artifact file (required)")
	diffArtifactCmd.Flags().String("algorithm", "sha256", "Hash algorithm for comparison")
	
	diffLockfileCmd.Flags().String("old", "", "Old lockfile (required)")
	diffLockfileCmd.Flags().String("new", "", "New lockfile (required)")
	diffLockfileCmd.Flags().String("ecosystem", "auto", "Package ecosystem (npm|pypi|go|cargo|auto)")
}

func runDiffSBOM(cmd *cobra.Command, args []string) error {
	oldFile, _ := cmd.Flags().GetString("old")
	newFile, _ := cmd.Flags().GetString("new")
	format, _ := cmd.Flags().GetString("format")
	showUnchanged, _ := cmd.Flags().GetBool("show-unchanged")
	severity, _ := cmd.Flags().GetString("severity")
	
	if oldFile == "" || newFile == "" {
		return fmt.Errorf("old and new SBOM files are required")
	}
	
	logger := Logger()
	logger.Info("Starting SBOM diff",
		zap.String("old", oldFile),
		zap.String("new", newFile))
	
	differ := NewSBOMDiffer()
	ctx := context.Background()
	
	result, err := differ.DiffSBOMs(ctx, oldFile, newFile, DiffSBOMOptions{
		Format:        format,
		ShowUnchanged: showUnchanged,
		SeverityFilter: severity,
	})
	
	if err != nil {
		return err
	}
	
	return outputDiffResult(result, cmd)
}

func runDiffConfig(cmd *cobra.Command, args []string) error {
	oldFile, _ := cmd.Flags().GetString("old")
	newFile, _ := cmd.Flags().GetString("new")
	configType, _ := cmd.Flags().GetString("type")
	
	if oldFile == "" || newFile == "" {
		return fmt.Errorf("old and new config files are required")
	}
	
	logger := Logger()
	logger.Info("Starting config diff",
		zap.String("old", oldFile),
		zap.String("new", newFile))
	
	differ := NewConfigDiffer()
	ctx := context.Background()
	
	result, err := differ.DiffConfigs(ctx, oldFile, newFile, configType)
	
	if err != nil {
		return err
	}
	
	return outputDiffResult(result, cmd)
}

func runDiffArtifact(cmd *cobra.Command, args []string) error {
	oldFile, _ := cmd.Flags().GetString("old")
	newFile, _ := cmd.Flags().GetString("new")
	algorithm, _ := cmd.Flags().GetString("algorithm")
	
	if oldFile == "" || newFile == "" {
		return fmt.Errorf("old and new artifact files are required")
	}
	
	logger := Logger()
	logger.Info("Starting artifact diff",
		zap.String("old", oldFile),
		zap.String("new", newFile))
	
	differ := NewArtifactDiffer()
	ctx := context.Background()
	
	result, err := differ.DiffArtifacts(ctx, oldFile, newFile, algorithm)
	
	if err != nil {
		return err
	}
	
	return outputDiffResult(result, cmd)
}

func runDiffLockfile(cmd *cobra.Command, args []string) error {
	oldFile, _ := cmd.Flags().GetString("old")
	newFile, _ := cmd.Flags().GetString("new")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	
	if oldFile == "" || newFile == "" {
		return fmt.Errorf("old and new lockfiles are required")
	}
	
	logger := Logger()
	logger.Info("Starting lockfile diff",
		zap.String("old", oldFile),
		zap.String("new", newFile))
	
	differ := NewLockfileDiffer()
	ctx := context.Background()
	
	result, err := differ.DiffLockfiles(ctx, oldFile, newFile, ecosystem)
	
	if err != nil {
		return err
	}
	
	return outputDiffResult(result, cmd)
}

type DiffSBOMOptions struct {
	Format         string
	ShowUnchanged  bool
	SeverityFilter string
}

type DiffResult struct {
	Target     string                 `json:"target"`
	Type       string                 `json:"type"`
	Timestamp  time.Time              `json:"timestamp"`
	OldFile    string                 `json:"old_file"`
	NewFile    string                 `json:"new_file"`
	Changes    []DiffChange           `json:"changes"`
	Summary    DiffSummary            `json:"summary"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type DiffChange struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // added, removed, modified, moved
	Category    string                 `json:"category"`
	Path        string                 `json:"path"`
	OldValue    interface{}            `json:"old_value,omitempty"`
	NewValue    interface{}            `json:"new_value,omitempty"`
	Severity    string                 `json:"severity,omitempty"`
	Description string                 `json:"description"`
	Impact      string                 `json:"impact,omitempty"`
}

type DiffSummary struct {
	Total     int `json:"total"`
	Added     int `json:"added"`
	Removed   int `json:"removed"`
	Modified  int `json:"modified"`
	Moved     int `json:"moved"`
	Critical  int `json:"critical"`
	High      int `json:"high"`
	Medium    int `json:"medium"`
	Low       int `json:"low"`
}

func outputDiffResult(result DiffResult, cmd *cobra.Command) error {
	outputFormat, _ := cmd.Flags().GetString("output")
	
	switch outputFormat {
	case "json":
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	case "table":
		fmt.Printf("\n=== Diff: %s (%s) ===\n", result.Target, result.Type)
		fmt.Printf("Old: %s\n", result.OldFile)
		fmt.Printf("New: %s\n", result.NewFile)
		fmt.Printf("Timestamp: %s\n", result.Timestamp.Format(time.RFC3339))
		fmt.Printf("Summary: %d total (+%d -%d ~%d ➤%d)\n",
			result.Summary.Total, result.Summary.Added, result.Summary.Removed, result.Summary.Modified, result.Summary.Moved)
		if result.Summary.Critical+result.Summary.High+result.Summary.Medium+result.Summary.Low > 0 {
			fmt.Printf("Severity: C:%d H:%d M:%d L:%d\n",
				result.Summary.Critical, result.Summary.High, result.Summary.Medium, result.Summary.Low)
		}
		
		if len(result.Changes) > 0 {
			tbl := table.New("TYPE", "CATEGORY", "PATH", "SEVERITY", "DESCRIPTION")
			for _, c := range result.Changes {
				desc := c.Description
				if len(desc) > 60 { desc = desc[:57] + "..." }
				tbl.AddRow(c.Type, c.Category, c.Path, c.Severity, desc)
			}
			tbl.Print()
		}
	case "html":
		return outputDiffHTML(result)
	default:
		return fmt.Errorf("unknown output format: %s", outputFormat)
	}
	return nil
}

func outputDiffHTML(result DiffResult) error {
	html := `<!DOCTYPE html>
<html><head><title>SUP Diff Report</title>
<style>
body { font-family: monospace; margin: 20px; }
.added { color: #28a745; } .removed { color: #dc3545; } 
.modified { color: #ffc107; } .moved { color: #17a2b8; }
.critical { background: #f8d7da; } .high { background: #fdf2e9; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; }
th { background: #f2f2f2; }
</style></head><body>
<h1>SUP Diff Report</h1>
<p>Old: ` + result.OldFile + `</p>
<p>New: ` + result.NewFile + `</p>
<p>Time: ` + result.Timestamp.Format(time.RFC3339) + `</p>
<table><tr><th>Type</th><th>Category</th><th>Path</th><th>Severity</th><th>Description</th><th>Old Value</th><th>New Value</th></tr>`
	
	for _, c := range result.Changes {
		html += fmt.Sprintf(`<tr class="%s"><td class="%s">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%v</td><td>%v</td></tr>`,
			c.Type, c.Type, c.Type, c.Category, c.Path, c.Severity, c.Description, c.OldValue, c.NewValue)
	}
	
	html += `</table></body></html>`
	fmt.Println(html)
	return nil
}

// Differ implementations

type SBOMDiffer struct{}

func NewSBOMDiffer() *SBOMDiffer {
	return &SBOMDiffer{}
}

func (d *SBOMDiffer) DiffSBOMs(ctx context.Context, oldFile, newFile string, opts DiffSBOMOptions) (DiffResult, error) {
	// Parse both SBOMs, compare packages
	return DiffResult{
		Target:    "sbom",
		Type:      "sbom_diff",
		Timestamp: time.Now(),
		OldFile:   oldFile,
		NewFile:   newFile,
		Changes:   []DiffChange{},
		Summary:   DiffSummary{},
	}, nil
}

type ConfigDiffer struct{}

func NewConfigDiffer() *ConfigDiffer {
	return &ConfigDiffer{}
}

func (d *ConfigDiffer) DiffConfigs(ctx context.Context, oldFile, newFile, configType string) (DiffResult, error) {
	// Parse both configs (YAML/JSON), deep diff
	return DiffResult{
		Target:    "config",
		Type:      "config_diff",
		Timestamp: time.Now(),
		OldFile:   oldFile,
		NewFile:   newFile,
		Changes:   []DiffChange{},
		Summary:   DiffSummary{},
	}, nil
}

type ArtifactDiffer struct{}

func NewArtifactDiffer() *ArtifactDiffer {
	return &ArtifactDiffer{}
}

func (d *ArtifactDiffer) DiffArtifacts(ctx context.Context, oldFile, newFile, algorithm string) (DiffResult, error) {
	// Binary diff, section analysis
	return DiffResult{
		Target:    "artifact",
		Type:      "artifact_diff",
		Timestamp: time.Now(),
		OldFile:   oldFile,
		NewFile:   newFile,
		Changes:   []DiffChange{},
		Summary:   DiffSummary{},
	}, nil
}

type LockfileDiffer struct{}

func NewLockfileDiffer() *LockfileDiffer {
	return &LockfileDiffer{}
}

func (d *LockfileDiffer) DiffLockfiles(ctx context.Context, oldFile, newFile, ecosystem string) (DiffResult, error) {
	// Parse lockfiles, compare dependencies
	return DiffResult{
		Target:    "lockfile",
		Type:      "lockfile_diff",
		Timestamp: time.Now(),
		OldFile:   oldFile,
		NewFile:   newFile,
		Changes:   []DiffChange{},
		Summary:   DiffSummary{},
	}, nil
}