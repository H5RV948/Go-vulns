package scanner

import "context"

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

type Job struct {
	Target string
	Checker Checker
}