package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "Go-vulns",
	Short: "Go-Vulns is a HTTP vulnerability scanner",
	Long:  `A fast, modular CLI security tool built in Go to audit HTTP headers and CORS policies concurrently using worker pools.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}