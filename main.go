package main

import (
	"fmt"
	"sync"

	"github.com/H5RV948/Go-vulns/pkg/plugins"
	"github.com/H5RV948/Go-vulns/pkg/scanner"
)

func main() {
	targets := []string{"https://google.com", "https://nmap.org"}
	checkers := []scanner.Checker {
		plugins.HeaderChecker{}, 
		plugins.CorsChecker{},
	}

	var wg sync.WaitGroup

	numJobs := len(targets) * len(checkers)
	results := make(chan scanner.Result, numJobs)
	jobs := make(chan scanner.Job, numJobs)
	
	numWorkers := 3
	for i := 1; i <= numWorkers; i++ {
		wg.Add(1)
		go scanner.Worker(i, jobs, results, &wg)
	}

	
	for _, c := range checkers {
		for _, t := range targets {
			jobs <- scanner.Job {Target: t, Checker: c }
		}
	}
	close(jobs)
	
	// wait until workers are finished 
	go func() {
		wg.Wait()
		close(results)
	}()

	// collector
	for res := range results { // A channel is a stream of values (no index)
		status := "PASS :D"
		if !res.Passed {
			status = "FAIL ;("
		}
		fmt.Printf("%s [%s] Target: %s | Details: %s\n", status, res.Check, res.Target, res.Details)
	}
	
	fmt.Printf("\n--- SCANS COMPLETED SUCCESSFULLY ---")
}

