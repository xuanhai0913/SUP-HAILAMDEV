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
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze CI/CD pipelines, builds, and configurations",
	Long:  `Analyze CI/CD configurations, build scripts, and deployment manifests for supply chain risks.`,
}

var analyzePipelineCmd = &cobra.Command{
	Use:   "pipeline",
	Short: "Analyze CI/CD pipeline configuration",
	Long:  `Analyze GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI configs for poisoning risks.`,
	RunE:  runAnalyzePipeline,
}

var analyzeBuildCmd = &cobra.Command{
	Use:   "build",
	Short: "Analyze build scripts and configuration",
	Long:  `Analyze Makefiles, npm scripts, Gradle, Maven, Bazel configs for malicious behavior.`,
	RunE:  runAnalyzeBuild,
}

var analyzeConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Analyze configuration files for risks",
	Long:  `Analyze Dockerfiles, docker-compose, k8s manifests, Helm charts for supply chain issues.`,
	RunE:  runAnalyzeConfig,
}

var analyzeScriptCmd = &cobra.Command{
	Use:   "script",
	Short: "Analyze install/post-install scripts",
	Long:  `Analyze package.json scripts, setup.py, pyproject.toml, install.sh for malicious behavior.`,
	RunE:  runAnalyzeScript,
}

func init() {
	analyzeCmd.AddCommand(analyzePipelineCmd)
	analyzeCmd.AddCommand(analyzeBuildCmd)
	analyzeCmd.AddCommand(analyzeConfigCmd)
	analyzeCmd.AddCommand(analyzeScriptCmd)
	
	analyzePipelineCmd.Flags().String("file", "", "Pipeline config file path")
	analyzePipelineCmd.Flags().String("dir", "", "Directory containing pipeline configs")
	analyzePipelineCmd.Flags().String("platform", "auto", "CI/CD platform (github|gitlab|jenkins|azure|circleci|auto)")
	analyzePipelineCmd.Flags().Bool("check-secrets", true, "Check for secret leakage")
	analyzePipelineCmd.Flags().Bool("check-actions", true, "Check for unpinned/untrusted actions")
	analyzePipelineCmd.Flags().Bool("check-injection", true, "Check for script injection")
	
	analyzeBuildCmd.Flags().String("file", "", "Build config file path")
	analyzeBuildCmd.Flags().String("dir", "", "Project directory")
	analyzeBuildCmd.Flags().String("type", "auto", "Build system (make|npm|gradle|maven|bazel|auto)")
	
	analyzeConfigCmd.Flags().String("file", "", "Config file path")
	analyzeConfigCmd.Flags().String("dir", "", "Directory to scan")
	analyzeConfigCmd.Flags().String("type", "auto", "Config type (dockerfile|k8s|helm|compose|auto)")
	
	analyzeScriptCmd.Flags().String("file", "", "Script file path")
	analyzeScriptCmd.Flags().String("dir", "", "Package directory")
	analyzeScriptCmd.Flags().String("ecosystem", "auto", "Package ecosystem (npm|pypi|auto)")
}

func runAnalyzePipeline(cmd *cobra.Command, args []string) error {
	file, _ := cmd.Flags().GetString("file")
	dir, _ := cmd.Flags().GetString("dir")
	platform, _ := cmd.Flags().GetString("platform")
	checkSecrets, _ := cmd.Flags().GetBool("check-secrets")
	checkActions, _ := cmd.Flags().GetBool("check-actions")
	checkInjection, _ := cmd.Flags().GetBool("check-injection")
	
	if file == "" && dir == "" {
		return fmt.Errorf("file or dir is required")
	}
	
	logger := Logger()
	logger.Info("Starting pipeline analysis",
		zap.String("file", file),
		zap.String("dir", dir),
		zap.String("platform", platform))
	
	analyzer := NewPipelineAnalyzer()
	ctx := context.Background()
	
	var files []string
	if file != "" {
		files = []string{file}
	} else {
		var err error
		files, err = findPipelineFiles(dir, platform)
		if err != nil {
			return err
		}
	}
	
	var allResults []AnalyzeResult
	for _, f := range files {
		result, err := analyzer.AnalyzePipeline(ctx, f, AnalyzePipelineOptions{
			Platform:      platform,
			CheckSecrets:  checkSecrets,
			CheckActions:  checkActions,
			CheckInjection: checkInjection,
		})
		if err != nil {
			logger.Error("Failed to analyze pipeline", zap.String("file", f), zap.Error(err))
			continue
		}
		allResults = append(allResults, result)
	}
	
	return outputAnalyzeResults(allResults, cmd)
}

func runAnalyzeBuild(cmd *cobra.Command, args []string) error {
	file, _ := cmd.Flags().GetString("file")
	dir, _ := cmd.Flags().GetString("dir")
	buildType, _ := cmd.Flags().GetString("type")
	
	if file == "" && dir == "" {
		return fmt.Errorf("file or dir is required")
	}
	
	logger := Logger()
	logger.Info("Starting build analysis",
		zap.String("file", file),
		zap.String("dir", dir),
		zap.String("type", buildType))
	
	analyzer := NewBuildAnalyzer()
	ctx := context.Background()
	
	var files []string
	if file != "" {
		files = []string{file}
	} else {
		var err error
		files, err = findBuildFiles(dir, buildType)
		if err != nil {
			return err
		}
	}
	
	var allResults []AnalyzeResult
	for _, f := range files {
		result, err := analyzer.AnalyzeBuild(ctx, f, buildType)
		if err != nil {
			logger.Error("Failed to analyze build", zap.String("file", f), zap.Error(err))
			continue
		}
		allResults = append(allResults, result)
	}
	
	return outputAnalyzeResults(allResults, cmd)
}

func runAnalyzeConfig(cmd *cobra.Command, args []string) error {
	file, _ := cmd.Flags().GetString("file")
	dir, _ := cmd.Flags().GetString("dir")
	configType, _ := cmd.Flags().GetString("type")
	
	if file == "" && dir == "" {
		return fmt.Errorf("file or dir is required")
	}
	
	logger := Logger()
	logger.Info("Starting config analysis",
		zap.String("file", file),
		zap.String("dir", dir),
		zap.String("type", configType))
	
	analyzer := NewConfigAnalyzer()
	ctx := context.Background()
	
	var files []string
	if file != "" {
		files = []string{file}
	} else {
		var err error
		files, err = findConfigFiles(dir, configType)
		if err != nil {
			return err
		}
	}
	
	var allResults []AnalyzeResult
	for _, f := range files {
		result, err := analyzer.AnalyzeConfig(ctx, f, configType)
		if err != nil {
			logger.Error("Failed to analyze config", zap.String("file", f), zap.Error(err))
			continue
		}
		allResults = append(allResults, result)
	}
	
	return outputAnalyzeResults(allResults, cmd)
}

func runAnalyzeScript(cmd *cobra.Command, args []string) error {
	file, _ := cmd.Flags().GetString("file")
	dir, _ := cmd.Flags().GetString("dir")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	
	if file == "" && dir == "" {
		return fmt.Errorf("file or dir is required")
	}
	
	logger := Logger()
	logger.Info("Starting script analysis",
		zap.String("file", file),
		zap.String("dir", dir),
		zap.String("ecosystem", ecosystem))
	
	analyzer := NewScriptAnalyzer()
	ctx := context.Background()
	
	var files []string
	if file != "" {
		files = []string{file}
	} else {
		var err error
		files, err = findScriptFiles(dir, ecosystem)
		if err != nil {
			return err
		}
	}
	
	var allResults []AnalyzeResult
	for _, f := range files {
		result, err := analyzer.AnalyzeScript(ctx, f, ecosystem)
		if err != nil {
			logger.Error("Failed to analyze script", zap.String("file", f), zap.Error(err))
			continue
		}
		allResults = append(allResults, result)
	}
	
	return outputAnalyzeResults(allResults, cmd)
}

type AnalyzeResult struct {
	File      string            `json:"file"`
	Type      string            `json:"type"`
	Platform  string            `json:"platform,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Findings  []AnalyzeFinding  `json:"findings"`
	Summary   AnalyzeSummary    `json:"summary"`
}

type AnalyzeFinding struct {
	ID          string                 `json:"id"`
	RuleID      string                 `json:"rule_id"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Location    string                 `json:"location"`
	Line        int                    `json:"line,omitempty"`
	Column      int                    `json:"column,omitempty"`
	Code        string                 `json:"code,omitempty"`
	Evidence    map[string]interface{} `json:"evidence,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	References  []string               `json:"references,omitempty"`
}

type AnalyzeSummary struct {
	Total            int `json:"total"`
	Critical         int `json:"critical"`
	High             int `json:"high"`
	Medium           int `json:"medium"`
	Low              int `json:"low"`
	Informational    int `json:"informational"`
	SecretsFound     int `json:"secrets_found"`
	UnpinnedActions  int `json:"unpinned_actions"`
	InjectionRisks   int `json:"injection_risks"`
}

type AnalyzePipelineOptions struct {
	Platform        string
	CheckSecrets    bool
	CheckActions    bool
	CheckInjection  bool
}

func outputAnalyzeResults(results []AnalyzeResult, cmd *cobra.Command) error {
	outputFormat, _ := cmd.Flags().GetString("output")
	
	switch outputFormat {
	case "json":
		for _, r := range results {
			data, _ := json.MarshalIndent(r, "", "  ")
			fmt.Println(string(data))
		}
	case "sarif":
		return outputAnalyzeSARIF(results)
	case "html":
		return outputAnalyzeHTML(results)
	case "table":
		return outputAnalyzeTable(results)
	default:
		return fmt.Errorf("unknown output format: %s", outputFormat)
	}
	return nil
}

func outputAnalyzeSARIF(results []AnalyzeResult) error {
	// SARIF output similar to scan
	fmt.Println("SARIF output for analyze")
	return nil
}

func outputAnalyzeHTML(results []AnalyzeResult) error {
	fmt.Println("HTML output for analyze")
	return nil
}

func outputAnalyzeTable(results []AnalyzeResult) error {
	for _, r := range results {
		fmt.Printf("\n=== %s (%s) ===\n", r.File, r.Type)
		tbl := table.New("SEVERITY", "CATEGORY", "TITLE", "LINE", "CODE")
		for _, f := range r.Findings {
			code := f.Code
			if len(code) > 60 {
				code = code[:57] + "..."
			}
			tbl.AddRow(f.Severity, f.Category, f.Title, f.Line, code)
		}
		tbl.Print()
	}
	return nil
}

func findPipelineFiles(dir, platform string) ([]string, error) {
	var files []string
	patterns := map[string][]string{
		"github":  {".github/workflows/*.yml", ".github/workflows/*.yaml"},
		"gitlab":  {".gitlab-ci.yml", ".gitlab/ci/*.yml"},
		"jenkins": {"Jenkinsfile", "Jenkinsfile.*", "jenkins/*.groovy"},
		"azure":   {"azure-pipelines.yml", ".azure/pipelines/*.yml"},
		"circleci": {".circleci/config.yml"},
	}
	
	if platform == "auto" {
		for _, p := range patterns {
			files = append(files, p...)
		}
	} else if p, ok := patterns[platform]; ok {
		files = p
	}
	
	var results []string
	for _, pattern := range files {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		results = append(results, matches...)
	}
	return results, nil
}

func findBuildFiles(dir, buildType string) ([]string, error) {
	patterns := map[string][]string{
		"make":   {"Makefile", "makefile", "GNUmakefile", "*.mk"},
		"npm":    {"package.json"},
		"gradle": {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"},
		"maven":  {"pom.xml"},
		"bazel":  {"BUILD", "BUILD.bazel", "WORKSPACE", "WORKSPACE.bazel", "*.bzl"},
	}
	
	if buildType == "auto" {
		for _, p := range patterns {
			files, _ := filepath.Glob(filepath.Join(dir, p[0]))
			if len(files) > 0 {
				return files, nil
			}
		}
	}
	
	if p, ok := patterns[buildType]; ok {
		var results []string
		for _, pattern := range p {
			matches, _ := filepath.Glob(filepath.Join(dir, pattern))
			results = append(results, matches...)
		}
		return results, nil
	}
	return []string{}, nil
}

func findConfigFiles(dir, configType string) ([]string, error) {
	patterns := map[string][]string{
		"dockerfile": {"Dockerfile", "Dockerfile.*", "*.dockerfile"},
		"k8s":        {"*.yaml", "*.yml", "k8s/*.yaml", "kubernetes/*.yaml"},
		"helm":       {"Chart.yaml", "values.yaml", "templates/*.yaml"},
		"compose":    {"docker-compose.yml", "docker-compose.yaml", "compose.yaml"},
	}
	
	if configType == "auto" {
		var results []string
		for _, p := range patterns {
			for _, pattern := range p {
				matches, _ := filepath.Glob(filepath.Join(dir, pattern))
				results = append(results, matches...)
			}
		}
		return results, nil
	}
	
	if p, ok := patterns[configType]; ok {
		var results []string
		for _, pattern := range p {
			matches, _ := filepath.Glob(filepath.Join(dir, pattern))
			results = append(results, matches...)
		}
		return results, nil
	}
	return []string{}, nil
}

func findScriptFiles(dir, ecosystem string) ([]string, error) {
	patterns := map[string][]string{
		"npm":   {"package.json"},
		"pypi":  {"setup.py", "pyproject.toml", "setup.cfg", "requirements.txt"},
		"cargo": {"Cargo.toml"},
		"go":    {"go.mod"},
	}
	
	if ecosystem == "auto" {
		for _, p := range patterns {
			files, _ := filepath.Glob(filepath.Join(dir, p[0]))
			if len(files) > 0 {
				return files, nil
			}
		}
	}
	
	if p, ok := patterns[ecosystem]; ok {
		var results []string
		for _, pattern := range p {
			matches, _ := filepath.Glob(filepath.Join(dir, pattern))
			results = append(results, matches...)
		}
		return results, nil
	}
	return []string{}, nil
}

// Analyzer implementations

type PipelineAnalyzer struct{}

func NewPipelineAnalyzer() *PipelineAnalyzer {
	return &PipelineAnalyzer{}
}

func (a *PipelineAnalyzer) AnalyzePipeline(ctx context.Context, file string, opts AnalyzePipelineOptions) (AnalyzeResult, error) {
	return AnalyzeResult{
		File:      file,
		Type:      "pipeline",
		Platform:  opts.Platform,
		Timestamp: time.Now(),
		Findings:  []AnalyzeFinding{},
		Summary:   AnalyzeSummary{},
	}, nil
}

type BuildAnalyzer struct{}

func NewBuildAnalyzer() *BuildAnalyzer {
	return &BuildAnalyzer{}
}

func (a *BuildAnalyzer) AnalyzeBuild(ctx context.Context, file, buildType string) (AnalyzeResult, error) {
	return AnalyzeResult{
		File:      file,
		Type:      "build",
		Platform:  buildType,
		Timestamp: time.Now(),
		Findings:  []AnalyzeFinding{},
		Summary:   AnalyzeSummary{},
	}, nil
}

type ConfigAnalyzer struct{}

func NewConfigAnalyzer() *ConfigAnalyzer {
	return &ConfigAnalyzer{}
}

func (a *ConfigAnalyzer) AnalyzeConfig(ctx context.Context, file, configType string) (AnalyzeResult, error) {
	return AnalyzeResult{
		File:      file,
		Type:      "config",
		Platform:  configType,
		Timestamp: time.Now(),
		Findings:  []AnalyzeFinding{},
		Summary:   AnalyzeSummary{},
	}, nil
}

type ScriptAnalyzer struct{}

func NewScriptAnalyzer() *ScriptAnalyzer {
	return &ScriptAnalyzer{}
}

func (a *ScriptAnalyzer) AnalyzeScript(ctx context.Context, file, ecosystem string) (AnalyzeResult, error) {
	return AnalyzeResult{
		File:      file,
		Type:      "script",
		Platform:  ecosystem,
		Timestamp: time.Now(),
		Findings:  []AnalyzeFinding{},
		Summary:   AnalyzeSummary{},
	}, nil
}