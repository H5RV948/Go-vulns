package main

import (
	"fmt"
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

type HeaderChecker struct {}

 func (h HeaderChecker) Name() string {
 	return "HTTP security Headers"
 }

 func (h HeaderChecker) Run(target string) Result {
 	return Result {
  		Target: target,
   		Check: h.Name(),
    	Passed: true,
     	Details: "HSTS and X-Frame-Options present",
  }
}

type CorsChecker struct {}

func (CorsChecker) Name() string {
	return	"CORS insecure configration checker"
}

func (c CorsChecker) Run(target string) Result {
	return Result{
		Target: target,
		Check: c.Name(),
		Passed: true,
		Details: "????",
	}
}

func main() {
	 
}