package plugins

import (
	"context"
	"fmt"
	"net/http"

	"github.com/H5RV948/Go-vulns/pkg/scanner"
)

// Cors
type CorsChecker struct {}

func (c CorsChecker) Name() string {
	return	"CORS insecure configuration checker"
}

func (c CorsChecker) Run(ctx context.Context, target string) scanner.Result {
	// REQUEST
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, target, nil)
	if err != nil {
		return scanner.Result {
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
		return scanner.Result {
			Target: target,
			Check: c.Name(),
			Passed: false,
			Details: "Connection failed/timed out: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")


	if allowOrigin == "*" || allowOrigin == Origin {
		return scanner.Result {
			Target: target,
			Check: c.Name(),
			Passed: false,
			Details: fmt.Sprintf("[Vulnerable CORS Policy detected] Allowed Origin: %s", allowOrigin),
		}
	}
	
	return scanner.Result {
		Target: target,
		Check: c.Name(),
		Passed: true,
		Details: "CORS policy configured correctly",
	}
}

