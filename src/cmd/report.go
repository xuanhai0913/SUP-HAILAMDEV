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

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate and manage reports",
	Long:  `Generate comprehensive reports from scan, analysis, and hunt results.`,
}

var reportGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate report from results",
	RunE:  runReportGenerate,
}

var reportListCmd = &cobra.Command{
	Use:   "list",
	Short: "List generated reports",
	RunE:  runReportList,
}

var reportMergeCmd = &cobra.Command{
	Use:   "merge",
	Short: "Merge multiple reports",
	RunE:  runReportMerge,
}

var reportTemplateCmd = &cobra.Command{
	Use:   "template",
	Short: "Manage report templates",
	RunE:  runReportTemplate,
}

func init() {
	reportCmd.AddCommand(reportGenerateCmd)
	reportCmd.AddCommand(reportListCmd)
	reportCmd.AddCommand(reportMergeCmd)
	reportCmd.AddCommand(reportTemplateCmd)
	
	reportGenerateCmd.Flags().String("input", "", "Input results file or directory (required)")
	reportGenerateCmd.Flags().String("template", "default", "Template name (default|executive|technical|compliance)")
	reportGenerateCmd.Flags().String("format", "html", "Output format (html|pdf|json|sarif)")
	reportGenerateCmd.Flags().String("output", "", "Output file path")
	reportGenerateCmd.Flags().Bool("include-evidence", true, "Include evidence in report")
	reportGenerateCmd.Flags().String("title", "SUP Supply Chain Security Report", "Report title")
	
	reportListCmd.Flags().String("dir", "./reports", "Reports directory")
	reportListCmd.Flags().String("format", "", "Filter by format")
	
	reportMergeCmd.Flags().String("inputs", "", "Comma-separated input files")
	reportMergeCmd.Flags().String("output", "", "Output file (required)")
	reportMergeCmd.Flags().String("format", "html", "Output format")
	
	reportTemplateCmd.Flags().String("action", "list", "Action (list|create|edit|delete)")
	reportTemplateCmd.Flags().String("name", "", "Template name")
	reportTemplateCmd.Flags().String("file", "", "Template file")
}

func runReportGenerate(cmd *cobra.Command, args []string) error {
	input, _ := cmd.Flags().GetString("input")
	template, _ := cmd.Flags().GetString("template")
	format, _ := cmd.Flags().GetString("format")
	output, _ := cmd.Flags().GetString("output")
	includeEvidence, _ := cmd.Flags().GetBool("include-evidence")
	title, _ := cmd.Flags().GetString("title")
	
	if input == "" {
		return fmt.Errorf("input is required")
	}
	
	if output == "" {
		output = fmt.Sprintf("./reports/sup-report-%s.%s", time.Now().Format("20060102-150405"), format)
	}
	
	logger := Logger()
	logger.Info("Generating report",
		zap.String("input", input),
		zap.String("template", template),
		zap.String("format", format))
	
	generator := NewReportGenerator()
	ctx := context.Background()
	
	err := generator.Generate(ctx, ReportOptions{
		Input:           input,
		Template:        template,
		Format:          format,
		Output:          output,
		IncludeEvidence: includeEvidence,
		Title:           title,
	})
	
	if err != nil {
		return err
	}
	
	fmt.Printf("Report generated: %s\n", output)
	return nil
}

func runReportList(cmd *cobra.Command, args []string) error {
	dir, _ := cmd.Flags().GetString("dir")
	formatFilter, _ := cmd.Flags().GetString("format")
	
	logger := Logger()
	logger.Info("Listing reports", zap.String("dir", dir))
	
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	
	tbl := table.New("FILE", "SIZE", "MODIFIED", "FORMAT")
	for _, f := range files {
		if f.IsDir() { continue }
		info, _ := f.Info()
		ext := filepath.Ext(f.Name())
		if formatFilter != "" && ext != "."+formatFilter {
			continue
		}
		tbl.AddRow(f.Name(), formatBytes(info.Size()), info.ModTime().Format("2006-01-02 15:04"), ext[1:])
	}
	tbl.Print()
	
	return nil
}

func runReportMerge(cmd *cobra.Command, args []string) error {
	inputs, _ := cmd.Flags().GetString("inputs")
	output, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	
	if inputs == "" || output == "" {
		return fmt.Errorf("inputs and output are required")
	}
	
	logger := Logger()
	logger.Info("Merging reports", zap.String("inputs", inputs))
	
	// Load and merge reports
	
	fmt.Println("Report merge not fully implemented")
	return nil
}

func runReportTemplate(cmd *cobra.Command, args []string) error {
	action, _ := cmd.Flags().GetString("action")
	name, _ := cmd.Flags().GetString("name")
	file, _ := cmd.Flags().GetString("file")
	
	switch action {
	case "list":
		fmt.Println("Available templates: default, executive, technical, compliance")
	case "create":
		if name == "" || file == "" {
			return fmt.Errorf("name and file required for create")
		}
		fmt.Printf("Creating template: %s\n", name)
	case "edit":
		fmt.Printf("Editing template: %s\n", name)
	case "delete":
		fmt.Printf("Deleting template: %s\n", name)
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
	
	return nil
}

type ReportOptions struct {
	Input           string
	Template        string
	Format          string
	Output          string
	IncludeEvidence bool
	Title           string
}

type ReportGenerator struct{}

func NewReportGenerator() *ReportGenerator {
	return &ReportGenerator{}
}

func (g *ReportGenerator) Generate(ctx context.Context, opts ReportOptions) error {
	// Load input results
	// Apply template
	// Render to format
	// Write output
	return nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
	 exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}