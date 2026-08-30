package scanner

import (
	"context"
	"sync"
	"time"
)

func Worker(id int, jobs <- chan Job, results chan <- Result, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)

		res := job.Checker.Run(ctx, job.Target)
		cancel()
		
		results <- res
	}
}