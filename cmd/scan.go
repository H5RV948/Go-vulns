package cmd

import (
	"fmt"
	"sync"

	"github.com/spf13/cobra"
	"github.com/H5RV948/Go-vulns/pkg/plugins"
	"github.com/H5RV948/Go-vulns/pkg/scanner"
)

var (
	targets    []string
	numWorkers int
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security checks against target URLs",
	Run: func(cmd *cobra.Command, args []string) {
		if len(targets) == 0 {
			fmt.Println("❌ Error: You must specify at least one target using -t or --target")
			return
		}

		checkers := []scanner.Checker{
			plugins.HeaderChecker{},
			plugins.CorsChecker{},
		}

		var wg sync.WaitGroup
		numJobs := len(targets) * len(checkers)
		results := make(chan scanner.Result, numJobs)
		jobs := make(chan scanner.Job, numJobs)

		// Worker Pool based on CLI flag
		fmt.Printf("Starting scanner with %d workers across %d targets...\n\n", numWorkers, len(targets))
		for i := 1; i <= numWorkers; i++ {
			wg.Add(1)
			go scanner.Worker(i, jobs, results, &wg)
		}

		for _, c := range checkers {
			for _, t := range targets {
				jobs <- scanner.Job{Target: t, Checker: c}
			}
		}
		close(jobs)

		// Wait for completition
		go func() {
			wg.Wait()
			close(results)
		}()

		// Collector
		for res := range results {
			status := "PASS :D"
			if !res.Passed {
				status = "FAIL ;("
			}
			fmt.Printf("%s [%s] Target: %s | Details: %s\n", status, res.Check, res.Target, res.Details)
		}

		fmt.Println("\n--- SCANS COMPLETED SUCCESSFULLY ---")
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Define command-line flags
	scanCmd.Flags().StringSliceVarP(&targets, "target", "t", []string{}, "Target URLs to scan (comma-separated)")
	scanCmd.Flags().IntVarP(&numWorkers, "workers", "w", 3, "Number of concurrent worker threads")
}