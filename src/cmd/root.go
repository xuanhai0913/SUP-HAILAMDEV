package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	Version   string
	BuildDate string
	Commit    string
	cfgFile   string
	logger    *zap.Logger
)

var rootCmd = &cobra.Command{
	Use:   "sup",
	Short: "Supply Chain Attack Detection & Analysis Framework",
	Long: `SUP detects supply chain compromises across package registries,
CI/CD pipelines, build systems, container images, and git repositories.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initLogger()
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./config/sup.yaml)")
	rootCmd.PersistentFlags().StringP("output", "o", "json", "output format (json|sarif|html|cyclonedx)")
	rootCmd.PersistentFlags().StringP("output-dir", "d", "./reports", "output directory")
	rootCmd.PersistentFlags().Bool("verbose", false, "verbose output")
	rootCmd.PersistentFlags().Bool("no-color", false, "disable colored output")
	
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("output-dir", rootCmd.PersistentFlags().Lookup("output-dir"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("no-color", rootCmd.PersistentFlags().Lookup("no-color"))
	
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(huntCmd)
	rootCmd.AddCommand(signatureCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("sup")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("./config")
		viper.AddConfigPath("/home/hainx/Documents/SUP-HAILAMDEV/config")
		viper.AddConfigPath("$HOME/.sup")
		viper.AddConfigPath("/etc/sup")
	}
	
	viper.SetEnvPrefix("SUP")
	viper.AutomaticEnv()
	
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		}
	}
}

func initLogger() error {
	cfg := zap.NewProductionConfig()
	
	if viper.GetBool("verbose") {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	
	if viper.GetBool("no-color") {
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	} else {
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncoderConfig.CallerKey = "caller"
	cfg.EncoderConfig.StacktraceKey = "stacktrace"
	
	var err error
	logger, err = cfg.Build()
	return err
}

func Logger() *zap.Logger {
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	return logger
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("SUP v%s\n", Version)
		fmt.Printf("Build Date: %s\n", BuildDate)
		fmt.Printf("Commit: %s\n", Commit)
		fmt.Printf("Go Version: %s\n", runtime.Version())
		fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management",
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan targets for supply chain threats",
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze CI/CD pipelines, builds, and configurations",
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify build reproducibility and artifact integrity",
}

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare SBOMs, configs, and artifacts",
}

var huntCmd = &cobra.Command{
	Use:   "hunt",
	Short: "Threat hunting with signatures and behavioral patterns",
}

var signatureCmd = &cobra.Command{
	Use:   "signature",
	Short: "Manage YARA signatures and IOCs",
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate and manage reports",
}