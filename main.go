package main

import (
	"fmt"
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
	Run (target string) Result
}

// Http
type HeaderChecker struct {}

func (h HeaderChecker) Name() string {
	return "HTTP security Headers"
 }

func (h HeaderChecker) Run(target string) Result {
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

func (c CorsChecker) Run(target string) Result {
	time.Sleep(300*time.Millisecond) // testing
	return Result {
		Target: target,
		Check: c.Name(),
		Passed: true,
		Details: "eh cors",
	}
}

func main() {
	targets := []string{"https://google.com", "https://nmap.org"}
	checkers := []Checker{HeaderChecker{}, CorsChecker{}}

	var wg sync.WaitGroup
	results := make(chan Result, 20)

	for _, c := range checkers {
		for _, t := range targets {
			wg.Add(1)
			go func(c Checker, t string) {
				defer wg.Done()
				res := c.Run(t)
				results <- res
			} (c, t)
		}
	}

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

