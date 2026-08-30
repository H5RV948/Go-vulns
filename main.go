package main

import (
	"fmt"
	"sync"
	"time"
	"context"
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
	time.Sleep(500*time.Millisecond) // testing
 	return Result {
  		Target: target,
   		Check: h.Name(),
    	Passed: true,
     	Details: "eh http",
  }
}

// Cors
type CorsChecker struct {}

func (c CorsChecker) Name() string {
	return	"CORS insecure configration checker"
}

func (c CorsChecker) Run(ctx context.Context, target string) Result {
	time.Sleep(300*time.Millisecond) // testing
	return Result {
		Target: target,
		Check: c.Name(),
		Passed: true,
		Details: "eh cors",
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
	for res := range results { // A channel is a strem of values (no index)
		fmt.Printf("[%s] Target: %s | Passed: %t | Details: %s\n", res.Check, res.Target, res.Passed, res.Details)
	}
	
	fmt.Println("yayaayayayayayayay")
		 
}

