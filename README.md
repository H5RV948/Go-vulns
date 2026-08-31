
# What is Go-vulns?
Is a concurrent HTTP security configuration and vulnerability scanner built in Go. It performs automated audits on web applications to identify common security risks—such as missing security headers and misconfigured Cross-Origin Resource Sharing (CORS) policies.

# How it works
## Worker Pool and Lifecycles 
The worker loop continuously reads Job tasks from the input channel until closed. Each execution is bounded by a strict context.Context timeout (default 2s) to prevent hung network connections from exhausting thread workers.

## Data flow diagram
```
                  [ CLI / Cobra Input ]
                            │
                            ▼
                  [ Jobs Channel (Queue) ]
                            │
       ┌────────────────────┼────────────────────┐
       ▼                    ▼                    ▼
[ Worker #1 ]        [ Worker #2 ]        [ Worker #3 ] <-- Configurable Pool Size
       │                    │                    │
       ├────────────────────┼────────────────────┤
       │                    │                    │
       ▼                    ▼                    ▼
(Header Checker)      (CORS Checker)      (Future Plugin)
       │                    │                    │
       └────────────────────┼────────────────────┘
                            ▼
                 [ Results Channel (Stream) ]
                            │
                            ▼
                  [ Results Collector ]
                            │
                            ▼
                  [ Console / Output ]
```

## Security Check Plugins
A. Security Headers Plugin (pkg/plugins/headers.go)
Sends an HTTP GET request and checks for key defense-in-depth headers:
- HSTS (Strict-Transport-Security): Ensures enforcement of HTTPS.
- Clickjacking Protection (X-Frame-Options): Prevents framing by external domains.
- MIME-Sniffing Defense (X-Content-Type-Options): Prevents browsers from sniffing content types away from the declared header.

B. CORS Misconfiguration Plugin (pkg/plugins/cors.go)
Sends an HTTP OPTIONS preflight request containing an untrusted origin (Origin: [https://evil.com](https://evil.com)). It flags targets that:
- Return wildcards (Access-Control-Allow-Origin: *).
- Dynamically reflect arbitrary untrusted origins (Access-Control-Allow-Origin: [https://evil.com](https://evil.com)).

# Usage
## CLI Command guide
```
# Build binary
go build -o Go-vulns main.go

# Run help menu
./Go-vulns --help

# Execute scan across targets with 5 parallel workers
./Go-vulns scan -t https://google.com,https://nmap.org -w 5
```

## Docker execution
```
# Build image
docker build -t go-vulns .

# Run containerized scan
docker run --rm go-vulns scan -t https://google.com,https://example.com -w 3
```

# Dir Structure
```
go-vulns/
├── go.mod
├── main.go               # Entry point (delegates execution to Cobra CLI)
├── cmd/                  # CLI routing and command flags
│   ├── root.go           # Base command definition
│   └── scan.go           # Scan subcommand & worker pool triggering
├── pkg/                  # Core domain logic
│   ├── scanner/          # Engine abstractions & worker routines
│   │   ├── checker.go    # Data structs & Checker interface
│   │   └── worker.go     # Worker pool execution logic
│   └── plugins/          # Security check implementations
│       ├── headers.go    # HTTP Security Header plugin
│       └── cors.go       # CORS Misconfiguration plugin
└── Dockerfile            # Multi-stage container specification
```