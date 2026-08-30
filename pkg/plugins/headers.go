package plugins

import (
	"context"
	"fmt"
	"net/http"
	
	"github.com/H5RV948/Go-vulns/pkg/scanner"
)

// Http
type HeaderChecker struct {}

func (h HeaderChecker) Name() string {
	return "HTTP security Headers"
 }

func (h HeaderChecker) Run(ctx context.Context, target string) scanner.Result {
	// REQUEST
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return scanner.Result {
			Target: target,
			Check: h.Name(),
			Passed: false,
			Details: "Invalid URL or request error: " + err.Error(),
		}
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return scanner.Result{
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
		return scanner.Result {
			Target: target,
			Check: h.Name(),
			Passed: false,
			Details: fmt.Sprintf("Missing security headers: %v", missing),
		}
	}
	
 	return scanner.Result {
  		Target: target,
   		Check: h.Name(),
    	Passed: true,
     	Details: "All security headers present",
  }
}