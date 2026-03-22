# publicdns-go

Go library for [publicdns.info](https://publicdns.info) — programmatic access to the world's largest continuously-validated public DNS resolver directory (8,500+ servers, re-verified every 72 hours).

Zero external dependencies. Drop-in replacement for [rvelhote/go-public-dns](https://github.com/rvelhote/go-public-dns), which wraps the stale public-dns.info dataset.

## Features

- **Fetch resolvers** — all servers or filtered by country
- **Live validation** — measure latency and reliability with real DNS queries
- **Benchmark** — detailed stats: avg, min, max, median, P95, P99, jitter
- **Privacy resolvers** — curated list with NoLog/DNSSEC/DoH/DoT metadata
- **NXDOMAIN integrity check** — detect hijacking resolvers
- **Zero dependencies** — pure Go standard library, no external packages
- **Thread-safe** — parallel validation with configurable worker pools
- **CLI included** — run directly with `go run publicdns.go`

## Installation

```bash
go get github.com/riankellyjn-a11y/publicdns-go
```

## Library Usage

```go
import "github.com/riankellyjn-a11y/publicdns-go"

// Fetch all resolvers (no live validation, instant)
resolvers, err := publicdns.GetResolvers(publicdns.Options{})

// Fetch with live validation
resolvers, err := publicdns.GetResolvers(publicdns.Options{Validate: true})

// Filter by country
irish, err := publicdns.GetResolversByCountry("IE", publicdns.Options{})

// Get the 10 fastest resolvers from your location (always live-tested)
fastest, err := publicdns.GetFastest(10, publicdns.Options{})

// Privacy-focused resolvers (Cloudflare, Quad9, Mullvad, AdGuard...)
private := publicdns.GetPrivacyResolvers(publicdns.Options{Validate: true})

// Validate a single resolver
result, err := publicdns.ValidateResolver("1.1.1.1", publicdns.Options{})
fmt.Printf("Alive: %v, Avg: %.2fms, Reliability: %.1f%%\n",
    result.Alive, result.AvgMs, result.Reliability)

// Full benchmark with percentile stats
stats, err := publicdns.BenchmarkResolver("8.8.8.8", publicdns.Options{})
fmt.Printf("P95: %.2fms, Jitter: %.2fms\n", stats.P95Ms, stats.JitterMs)
```

## Options

```go
opts := publicdns.Options{
    Validate:   true,          // Run live DNS queries
    MaxWorkers: 50,            // Goroutine pool size (default: 50)
    Timeout:    2*time.Second, // Per-query timeout (default: 2s)
    Rounds:     3,             // Queries per resolver (default: auto)
}
```

## Resolver struct

```go
type Resolver struct {
    IP          string  // IPv4 address
    Country     string  // ISO 3166-1 alpha-2 (e.g. "IE", "US", "DE")
    AvgMs       float64 // Average latency in ms (0 if not validated)
    Reliability float64 // Success rate 0-100 (0 if not validated)
    NXDomainOK  bool    // True = correct NXDOMAIN; False = hijacking
}
```

## CLI Usage

```bash
# List all resolvers
go run publicdns.go --list

# List with live validation
go run publicdns.go --list --do-validate

# Resolvers for a specific country
go run publicdns.go --country ie

# Top 10 fastest resolvers from your location
go run publicdns.go --fastest 10

# Privacy-focused resolvers
go run publicdns.go --privacy --do-validate

# Test a specific resolver
go run publicdns.go --validate 1.1.1.1

# Full benchmark
go run publicdns.go --benchmark 8.8.8.8
```

## Why publicdns-go?

| | publicdns-go | rvelhote/go-public-dns |
|---|---|---|
| Data source | publicdns.info (8,500+ servers, live-tested every 72h) | public-dns.info (stale, unmaintained) |
| Live validation | Yes — latency, reliability, NXDOMAIN | No |
| Benchmarking | Yes — P95/P99/jitter | No |
| Privacy resolver list | Yes | No |
| Dependencies | Zero | Zero |
| Maintained | Yes | No (last commit 2019) |

## Source

Data sourced from [publicdns.info](https://publicdns.info) — the most comprehensive public DNS directory, continuously validated with real resolver testing.

## License

MIT — see [LICENSE](LICENSE)
