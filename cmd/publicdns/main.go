// Command publicdns is the CLI for the publicdns-go library.
//
// Usage:
//
//	go run ./cmd/publicdns --list
//	go run ./cmd/publicdns --country ie
//	go run ./cmd/publicdns --fastest 10
//	go run ./cmd/publicdns --validate 1.1.1.1
//	go run ./cmd/publicdns --benchmark 8.8.8.8
//
// Or build it:
//
//	go build -o publicdns ./cmd/publicdns
//	./publicdns --fastest 5
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	publicdns "github.com/riankellyjn-a11y/publicdns-go"
)

func main() {
	fs := flag.NewFlagSet("publicdns", flag.ExitOnError)
	cmdList := fs.Bool("list", false, "List all resolvers from publicdns.info")
	cmdCountry := fs.String("country", "", "List resolvers for a country code (e.g. US, IE, DE)")
	cmdFastest := fs.Int("fastest", 0, "Show the N fastest resolvers")
	cmdPrivacy := fs.Bool("privacy", false, "List privacy-focused resolvers")
	cmdValidate := fs.String("validate", "", "Validate a specific resolver IP")
	cmdBenchmark := fs.String("benchmark", "", "Benchmark a specific resolver IP")
	doValidate := fs.Bool("do-validate", false, "Validate resolvers when using --list or --country")
	timeout := fs.Float64("timeout", 2.0, "DNS query timeout in seconds")
	rounds := fs.Int("rounds", 0, "Query rounds per resolver (0=auto)")
	limit := fs.Int("limit", 0, "Limit number of results (0=all)")
	ver := fs.Bool("version", false, "Print version and exit")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}
	if *ver {
		fmt.Println("publicdns-go", publicdns.Version)
		return
	}

	opts := publicdns.Options{
		Validate:   *doValidate,
		Timeout:    time.Duration(*timeout*1000) * time.Millisecond,
		Rounds:     *rounds,
		MaxWorkers: 50,
	}

	switch {
	case *cmdList:
		resolvers, err := publicdns.GetResolvers(opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printResolvers(resolvers, *limit)

	case *cmdCountry != "":
		resolvers, err := publicdns.GetResolversByCountry(*cmdCountry, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printResolvers(resolvers, *limit)

	case *cmdFastest > 0:
		opts.Validate = true
		resolvers, err := publicdns.GetFastest(*cmdFastest, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printResolvers(resolvers, 0)

	case *cmdPrivacy:
		resolvers := publicdns.GetPrivacyResolvers(opts)
		printPrivacyResolvers(resolvers)

	case *cmdValidate != "":
		result, err := publicdns.ValidateResolver(*cmdValidate, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printValidation(result)

	case *cmdBenchmark != "":
		result, err := publicdns.BenchmarkResolver(*cmdBenchmark, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printBenchmark(result)

	default:
		fmt.Fprintf(os.Stderr, "publicdns-go %s\nSource: https://publicdns.info\n\n", publicdns.Version)
		fmt.Fprintln(os.Stderr, "Usage:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  go run ./cmd/publicdns --list")
		fmt.Fprintln(os.Stderr, "  go run ./cmd/publicdns --country ie")
		fmt.Fprintln(os.Stderr, "  go run ./cmd/publicdns --fastest 10")
		fmt.Fprintln(os.Stderr, "  go run ./cmd/publicdns --validate 1.1.1.1")
		fmt.Fprintln(os.Stderr, "  go run ./cmd/publicdns --benchmark 8.8.8.8")
		os.Exit(1)
	}
}

func printResolvers(rs []publicdns.Resolver, limit int) {
	fmt.Printf("  %-4s  %-16s  %-10s  %8s  %7s  %4s\n", "#", "IP", "Country", "Avg ms", "Rel %", "NX")
	fmt.Printf("  %-4s  %-16s  %-10s  %8s  %7s  %4s\n", "---", "---", "---", "---", "---", "---")
	show := rs
	if limit > 0 && limit < len(rs) {
		show = rs[:limit]
	}
	for i, r := range show {
		nx := "OK"
		if !r.NXDomainOK {
			nx = "HJ"
		}
		avgStr := "N/A"
		if r.AvgMs > 0 {
			avgStr = fmt.Sprintf("%.1fms", r.AvgMs)
		}
		relStr := "N/A"
		if r.Reliability > 0 {
			relStr = fmt.Sprintf("%.0f%%", r.Reliability)
		}
		fmt.Printf("  %-4d  %-16s  %-10s  %8s  %7s  %4s\n", i+1, r.IP, r.Country, avgStr, relStr, nx)
	}
	if limit > 0 && len(rs) > limit {
		fmt.Printf("\n  Showing %d of %d resolvers.\n", limit, len(rs))
	}
}

func printPrivacyResolvers(rs []publicdns.PrivacyResolver) {
	fmt.Printf("  %-4s  %-16s  %-14s  %-6s  %-6s  %-5s  %-5s  %-5s\n",
		"#", "IP", "Provider", "NoLog", "DNSSEC", "DoH", "DoT", "Avg ms")
	fmt.Println("  " + strings.Repeat("-", 80))
	for i, r := range rs {
		avgStr := "N/A"
		if r.AvgMs > 0 {
			avgStr = fmt.Sprintf("%.1fms", r.AvgMs)
		}
		fmt.Printf("  %-4d  %-16s  %-14s  %-6s  %-6s  %-5s  %-5s  %-8s\n",
			i+1, r.IP, r.Provider, yn(r.NoLog), yn(r.DNSSEC), yn(r.DoH), yn(r.DoT), avgStr)
	}
}

func printValidation(r publicdns.ValidationResult) {
	alive := "DEAD"
	if r.Alive {
		alive = "ALIVE"
	}
	nx := "OK"
	if !r.NXDomainOK {
		nx = "HIJACKING"
	}
	fmt.Printf("\n  Resolver: %s\n  Status:   %s\n", r.IP, alive)
	if r.Alive {
		fmt.Printf("  Avg:      %.2fms\n  Rel:      %.1f%%\n  NXDOMAIN: %s\n  Queries:  %d/%d\n",
			r.AvgMs, r.Reliability, nx, r.QueriesOK, r.QueriesSent)
	}
}

func printBenchmark(r publicdns.BenchmarkResult) {
	alive := "DEAD"
	if r.Alive {
		alive = "ALIVE"
	}
	fmt.Printf("\n  Benchmark: %s  Status: %s\n", r.IP, alive)
	if !r.Alive {
		return
	}
	nx := "OK"
	if !r.NXDomainOK {
		nx = "HIJACKING"
	}
	fmt.Printf("  Queries:   %d/%d  Rel: %.1f%%  NXDOMAIN: %s\n\n",
		r.SuccessfulQueries, r.TotalQueries, r.Reliability, nx)
	fmt.Printf("  %-14s  %10s\n", "Metric", "Value")
	fmt.Printf("  %-14s  %10s\n", "------", "-----")
	fmt.Printf("  %-14s  %8.2fms\n", "Average", r.AvgMs)
	fmt.Printf("  %-14s  %8.2fms\n", "Minimum", r.MinMs)
	fmt.Printf("  %-14s  %8.2fms\n", "Maximum", r.MaxMs)
	fmt.Printf("  %-14s  %8.2fms\n", "Median", r.MedianMs)
	fmt.Printf("  %-14s  %8.2fms\n", "Jitter (SD)", r.JitterMs)
	fmt.Printf("  %-14s  %8.2fms\n", "P95", r.P95Ms)
	fmt.Printf("  %-14s  %8.2fms\n", "P99", r.P99Ms)
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
