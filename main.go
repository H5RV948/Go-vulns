package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Result struct {
	Target string
	Check string
	Passed bool
	Details string
}

type Checker interface {
	Name() string
	Run (ctx context.Context, target string) Result
}

// Http
type HeaderChecker struct {}

func (h HeaderChecker) Name() string {
	return "HTTP security Headers"
 }

func (h HeaderChecker) Run(ctx context.Context, target string) Result {
	// REQUEST
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Result {
			Target: target,
			Check: h.Name(),
			Passed: false,
			Details: "Invalid URL or request error: " + err.Error(),
		}
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return Result{
			Target: target,
			Check: h.Name(),
			Passed: false,
			Details: "Connction failed/timed out: "+ err.Error(),
		}
	}
	defer resp.Body.Close()

	// Inspection of security headers
	missing := []string{}
	if resp.Header.Get("Strict-Transport-Security") == "" {
		missing = append(missing, "HSTS")
	}
	if resp.Header.Get("X-Frame-Options") == "" {
		missing = append(missing, "X-Frame-Options")
	}
	if resp.Header.Get("X-Content-Type-Options") == "" {
		missing = append(missing, "X-Content-Type-Options")
	}

	if len(missing) > 0 {
		return Result {
			Target: target,
			Check: h.Name(),
			Passed: false,
			Details: fmt.Sprintf("Missing security headers: %v", missing),
		}
	}
	
 	return Result {
  		Target: target,
   		Check: h.Name(),
    	Passed: true,
     	Details: "All security headers present",
  }
}

// Cors
type CorsChecker struct {}

func (c CorsChecker) Name() string {
	return	"CORS insecure configuration checker"
}

func (c CorsChecker) Run(ctx context.Context, target string) Result {
	// REQUEST
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, target, nil)
	if err != nil {
		return Result {
			Target: target,
			Check: c.Name(),
			Passed: false,
			Details: err.Error(),
		}
	}

	Origin := "https://eh.com"
	req.Header.Set("Origin", Origin)
	req.Header.Set("Access-Control-Request-Method", "GET")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return Result {
			Target: target,
			Check: c.Name(),
			Passed: false,
			Details: "Connection failed/timed out: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")


	if allowOrigin == "*" || allowOrigin == Origin {
		return Result {
			Target: target,
			Check: c.Name(),
			Passed: false,
			Details: fmt.Sprintf("[Vulnerable CORS Policy detected] Allowed Origin: %s", allowOrigin),
		}
	}
	
	return Result {
		Target: target,
		Check: c.Name(),
		Passed: true,
		Details: "CORS policy configured correctly",
	}
}

type Job struct {
	Target string
	Checker Checker
}

func worker(id int, jobs <- chan Job, results chan <- Result, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)

		res := job.Checker.Run(ctx, job.Target)
		cancel()
		
		results <- res
	}
}


func main() {
	targets := []string{"https://google.com", "https://nmap.org"}
	checkers := []Checker{HeaderChecker{}, CorsChecker{}}

	var wg sync.WaitGroup

	numJobs := len(targets) * len(checkers)
	results := make(chan Result, numJobs)
	jobs := make(chan Job, numJobs)
	
	numWorkers := 3
	for i := 1; i <= numWorkers; i++ {
		wg.Add(1)
		go worker(i, jobs, results, &wg)
	}

	
	for _, c := range checkers {
		for _, t := range targets {
			jobs <- Job {Target: t, Checker: c }
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

