package main

import (
	"fmt"
	"os"

	"github.com/hailamdev/sup/cmd"
)

var (
	version = "1.0.0"
	buildDate = "unknown"
	commit = "unknown"
)

func main() {
	cmd.Version = version
	cmd.BuildDate = buildDate
	cmd.Commit = commit
	
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}