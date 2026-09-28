package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/hillu/go-yara/v4"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var signatureCmd = &cobra.Command{
	Use:   "signature",
	Short: "Manage YARA signatures and IOCs",
	Long:  `Create, validate, update, and manage YARA rules and threat intelligence signatures.`,
}

var signatureListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available signatures",
	RunE:  runSignatureList,
}

var signatureValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate YARA rule syntax",
	RunE:  runSignatureValidate,
}

var signatureCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create new YARA rule from template",
	RunE:  runSignatureCreate,
}

var signatureUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update signatures from threat intel feeds",
	RunE:  runSignatureUpdate,
}

var signatureTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test signatures against sample files",
	RunE:  runSignatureTest,
}

var signatureExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export signatures to different formats",
	RunE:  runSignatureExport,
}

func init() {
	signatureCmd.AddCommand(signatureListCmd)
	signatureCmd.AddCommand(signatureValidateCmd)
	signatureCmd.AddCommand(signatureCreateCmd)
	signatureCmd.AddCommand(signatureUpdateCmd)
	signatureCmd.AddCommand(signatureTestCmd)
	signatureCmd.AddCommand(signatureExportCmd)
	
	signatureListCmd.Flags().String("dir", "./signatures", "Signatures directory")
	signatureListCmd.Flags().String("category", "", "Filter by category")
	signatureListCmd.Flags().String("severity", "", "Filter by severity")
	signatureListCmd.Flags().Bool("show-meta", false, "Show rule metadata")
	
	signatureValidateCmd.Flags().String("file", "", "YARA rule file to validate")
	signatureValidateCmd.Flags().String("dir", "", "Directory of rules to validate")
	
	signatureCreateCmd.Flags().String("name", "", "Rule name (required)")
	signatureCreateCmd.Flags().String("category", "malware", "Category (malware|exploit|suspicious|ioc)")
	signatureCreateCmd.Flags().String("severity", "medium", "Severity (critical|high|medium|low|info)")
	signatureCreateCmd.Flags().String("author", "", "Rule author")
	signatureCreateCmd.Flags().String("description", "", "Rule description")
	signatureCreateCmd.Flags().String("output", "", "Output file path")
	
	signatureUpdateCmd.Flags().String("dir", "./signatures", "Signatures directory")
	signatureUpdateCmd.Flags().String("feeds", "", "Comma-separated feed URLs")
	signatureUpdateCmd.Flags().Bool("force", false, "Force update even if recent")
	
	signatureTestCmd.Flags().String("rules", "", "Rules file or directory")
	signatureTestCmd.Flags().String("samples", "", "Sample files directory")
	signatureTestCmd.Flags().Bool("verbose", false, "Verbose output")
	
	signatureExportCmd.Flags().String("dir", "./signatures", "Signatures directory")
	signatureExportCmd.Flags().String("format", "stix", "Export format (stix|misp|openioc|json)")
	signatureExportCmd.Flags().String("output", "", "Output file")
}

func runSignatureList(cmd *cobra.Command, args []string) error {
	dir, _ := cmd.Flags().GetString("dir")
	category, _ := cmd.Flags().GetString("category")
	severity, _ := cmd.Flags().GetString("severity")
	showMeta, _ := cmd.Flags().GetBool("show-meta")
	
	logger := Logger()
	logger.Info("Listing signatures", zap.String("dir", dir))
	
	rules, err := loadRulesFromDir(dir)
	if err != nil {
		return err
	}
	
	var filtered []*yara.Rule
	for _, r := range rules {
		meta := r.Metas
		if category != "" && meta["category"] != category {
			continue
		}
		if severity != "" && meta["severity"] != severity {
			continue
		}
		filtered = append(filtered, r)
	}
	
	if showMeta {
		for _, r := range filtered {
			fmt.Printf("\n=== %s ===\n", r.Identifier)
			fmt.Printf("  Namespace: %s\n", r.Namespace)
			fmt.Printf("  Tags: %v\n", r.Tags)
			for k, v := range r.Metas {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}
	} else {
		tbl := table.New("RULE", "NAMESPACE", "CATEGORY", "SEVERITY", "TAGS")
		for _, r := range filtered {
			cat := r.Metas["category"]
			sev := r.Metas["severity"]
			tbl.AddRow(r.Identifier, r.Namespace, cat, sev, strings.Join(r.Tags, ","))
		}
		tbl.Print()
	}
	
	fmt.Printf("\nTotal: %d rules\n", len(filtered))
	return nil
}

func runSignatureValidate(cmd *cobra.Command, args []string) error {
	file, _ := cmd.Flags().GetString("file")
	dir, _ := cmd.Flags().GetString("dir")
	
	if file == "" && dir == "" {
		return fmt.Errorf("file or dir is required")
	}
	
	logger := Logger()
	logger.Info("Validating signatures")
	
	var files []string
	if file != "" {
		files = []string{file}
	} else {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if strings.HasSuffix(path, ".yar") || strings.HasSuffix(path, ".yara") {
				files = append(files, path)
			}
			return nil
		})
	}
	
	compiler, err := yara.NewCompiler()
	if err != nil {
		return err
	}
	
	hasErrors := false
	for _, f := range files {
		err := compiler.AddFile(f, "")
		if err != nil {
			fmt.Printf("❌ %s: %v\n", f, err)
			hasErrors = true
		} else {
			fmt.Printf("✅ %s\n", f)
		}
	}
	
	if hasErrors {
		return fmt.Errorf("validation failed")
	}
	
	fmt.Println("\nAll rules valid")
	return nil
}

func runSignatureCreate(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	category, _ := cmd.Flags().GetString("category")
	severity, _ := cmd.Flags().GetString("severity")
	author, _ := cmd.Flags().GetString("author")
	description, _ := cmd.Flags().GetString("description")
	output, _ := cmd.Flags().GetString("output")
	
	if name == "" {
		return fmt.Errorf("name is required")
	}
	
	if output == "" {
		output = filepath.Join("./signatures", category, name+".yar")
	}
	
	os.MkdirAll(filepath.Dir(output), 0755)
	
	template := fmt.Sprintf(`rule %s
{
    meta:
        author = "%s"
        description = "%s"
        category = "%s"
        severity = "%s"
        date = "%s"
        version = "1.0"
        reference = ""
    
    strings:
        $string1 = "suspicious_string" nocase
        $string2 = { 4D 5A }  // MZ header
    
    condition:
        any of them
}
`, name, author, description, category, severity, time.Now().Format("2006-01-02"))
	
	err := os.WriteFile(output, []byte(template), 0644)
	if err != nil {
		return err
	}
	
	fmt.Printf("Created rule: %s\n", output)
	return nil
}

func runSignatureUpdate(cmd *cobra.Command, args []string) error {
	dir, _ := cmd.Flags().GetString("dir")
	feeds, _ := cmd.Flags().GetString("feeds")
	force, _ := cmd.Flags().GetBool("force")
	
	logger := Logger()
	logger.Info("Updating signatures", zap.String("dir", dir))
	
	// Download from threat intel feeds
	// Merge with existing rules
	// Validate
	// Backup old rules
	
	fmt.Println("Signature update not fully implemented")
	return nil
}

func runSignatureTest(cmd *cobra.Command, args []string) error {
	rulesPath, _ := cmd.Flags().GetString("rules")
	samplesDir, _ := cmd.Flags().GetString("samples")
	verbose, _ := cmd.Flags().GetBool("verbose")
	
	if rulesPath == "" || samplesDir == "" {
		return fmt.Errorf("rules and samples are required")
	}
	
	logger := Logger()
	logger.Info("Testing signatures", zap.String("rules", rulesPath), zap.String("samples", samplesDir))
	
	// Load rules
	// Scan samples
	// Report matches
	
	fmt.Println("Signature test not fully implemented")
	return nil
}

func runSignatureExport(cmd *cobra.Command, args []string) error {
	dir, _ := cmd.Flags().GetString("dir")
	format, _ := cmd.Flags().GetString("format")
	output, _ := cmd.Flags().GetString("output")
	
	logger := Logger()
	logger.Info("Exporting signatures", zap.String("format", format))
	
	// Load rules
	// Convert to STIX/MISP/OpenIOC/JSON
	// Write output
	
	fmt.Println("Signature export not fully implemented")
	return nil
}

func loadRulesFromDir(dir string) ([]*yara.Rule, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}
	
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil { return nil }
		if strings.HasSuffix(path, ".yar") || strings.HasSuffix(path, ".yara") {
			compiler.AddFile(path, "")
		}
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	return compiler.GetRules()
}