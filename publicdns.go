// Package publicdns provides programmatic access to publicdns.info resolver data.
//
// Zero-dependency Go library for querying, filtering, validating, and
// benchmarking public DNS resolvers sourced from publicdns.info — the largest
// continuously-validated public DNS directory (8,500+ servers, re-verified
// every 72 hours).
//
// Drop-in replacement for rvelhote/go-public-dns, which wraps the stale
// public-dns.info dataset.
//
// Usage:
//
//	import "github.com/riankellyjn-a11y/publicdns-go"
//
//	resolvers, _ := publicdns.GetResolvers(publicdns.Options{})
//	irish, _     := publicdns.GetResolversByCountry("IE", publicdns.Options{})
//	top10, _     := publicdns.GetFastest(10, publicdns.Options{})
//	private      := publicdns.GetPrivacyResolvers(publicdns.Options{})
//	result, _    := publicdns.ValidateResolver("1.1.1.1", publicdns.Options{})
//	stats, _     := publicdns.BenchmarkResolver("8.8.8.8", publicdns.Options{})
package publicdns

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Version is the current library version.
const Version = "1.0.0"

const (
	baseURL   = "https://publicdns.info"
	userAgent = "publicdns-go/" + Version + " (https://github.com/riankellyjn-a11y/publicdns-go)"
)

// Options controls validation and performance behaviour for API calls.
type Options struct {
	// Validate sends live DNS queries to each resolver.
	// When false (default), AvgMs and Reliability will be zero.
	Validate bool

	// MaxWorkers is the goroutine pool size for parallel validation.
	// Default: 50.
	MaxWorkers int

	// Timeout is the per-query DNS socket timeout. Default: 2s.
	Timeout time.Duration

	// Rounds is the number of test queries per resolver during validation.
	// Default: 2 for list calls, 3 for fastest/validate, 5 for benchmark.
	Rounds int
}

func (o *Options) defaults(rounds int) Options {
	out := *o
	if out.MaxWorkers <= 0 {
		out.MaxWorkers = 50
	}
	if out.Timeout <= 0 {
		out.Timeout = 2 * time.Second
	}
	if out.Rounds <= 0 {
		out.Rounds = rounds
	}
	return out
}

// Resolver holds metadata for a public DNS resolver.
type Resolver struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	AvgMs       float64 `json:"avg_ms"`
	Reliability float64 `json:"reliability"`
	NXDomainOK  bool    `json:"nxdomain_ok"`
}

// PrivacyResolver extends Resolver with privacy and protocol metadata.
type PrivacyResolver struct {
	Resolver
	Provider string `json:"provider"`
	NoLog    bool   `json:"no_log"`
	DNSSEC   bool   `json:"dnssec"`
	DoH      bool   `json:"doh"`
	DoT      bool   `json:"dot"`
}

// ValidationResult holds the result of validating a single resolver.
type ValidationResult struct {
	IP          string  `json:"ip"`
	Alive       bool    `json:"alive"`
	AvgMs       float64 `json:"avg_ms"`
	Reliability float64 `json:"reliability"`
	NXDomainOK  bool    `json:"nxdomain_ok"`
	QueriesSent int     `json:"queries_sent"`
	QueriesOK   int     `json:"queries_ok"`
}

// BenchmarkResult holds detailed performance statistics for a resolver.
type BenchmarkResult struct {
	IP                string    `json:"ip"`
	Alive             bool      `json:"alive"`
	TotalQueries      int       `json:"total_queries"`
	SuccessfulQueries int       `json:"successful_queries"`
	FailedQueries     int       `json:"failed_queries"`
	Reliability       float64   `json:"reliability"`
	AvgMs             float64   `json:"avg_ms"`
	MinMs             float64   `json:"min_ms"`
	MaxMs             float64   `json:"max_ms"`
	MedianMs          float64   `json:"median_ms"`
	JitterMs          float64   `json:"jitter_ms"`
	P95Ms             float64   `json:"p95_ms"`
	P99Ms             float64   `json:"p99_ms"`
	NXDomainOK        bool      `json:"nxdomain_ok"`
	Latencies         []float64 `json:"latencies"`
}

// ---------------------------------------------------------------------------
// DNS wire-protocol engine (zero external dependencies)
// ---------------------------------------------------------------------------

var testDomains = []string{
	"google.com", "cloudflare.com", "amazon.com", "microsoft.com",
	"github.com", "apple.com", "netflix.com", "wikipedia.org",
}

var ipRE = regexp.MustCompile(
	`\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}` +
		`(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b`,
)

func buildDNSQuery(domain string) ([]byte, uint16, error) {
	tid := uint16(rand.Intn(65536))
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:], tid)
	binary.BigEndian.PutUint16(buf[2:], 0x0100) // standard query, RD=1
	binary.BigEndian.PutUint16(buf[4:], 1)       // QDCOUNT=1

	domain = strings.TrimSuffix(domain, ".")
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, fmt.Errorf("invalid DNS label: %q", label)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00)                   // root label
	buf = append(buf, 0x00, 0x01)             // QTYPE A
	buf = append(buf, 0x00, 0x01)             // QCLASS IN
	return buf, tid, nil
}

func parseDNSResponse(data []byte, expectedTID uint16) (rcode int, hasAnswer bool) {
	if len(data) < 12 {
		return -1, false
	}
	tid := binary.BigEndian.Uint16(data[0:])
	if tid != expectedTID {
		return -1, false
	}
	flags := binary.BigEndian.Uint16(data[2:])
	ancount := binary.BigEndian.Uint16(data[6:])
	return int(flags & 0x0F), ancount > 0
}

func dnsQuery(server, domain string, timeout time.Duration) (float64, bool) {
	packet, tid, err := buildDNSQuery(domain)
	if err != nil {
		return 0, false
	}
	conn, err := net.DialTimeout("udp", server+":53", timeout)
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	if _, err = conn.Write(packet); err != nil {
		return 0, false
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, false
	}
	elapsed := float64(time.Since(start).Microseconds()) / 1000.0
	rcode, hasAnswer := parseDNSResponse(buf[:n], tid)
	if rcode == 0 && hasAnswer {
		return elapsed, true
	}
	return 0, false
}

func checkNXDomain(server string, timeout time.Duration) bool {
	fake := fmt.Sprintf("nxtest-%d.definitelynotreal.example", rand.Intn(900000)+100000)
	packet, tid, err := buildDNSQuery(fake)
	if err != nil {
		return true
	}
	conn, err := net.DialTimeout("udp", server+":53", timeout)
	if err != nil {
		return true // timeout: assume OK
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err = conn.Write(packet); err != nil {
		return true
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return true // timeout: assume OK
	}
	rcode, _ := parseDNSResponse(buf[:n], tid)
	return rcode == 3 // NXDOMAIN
}

func isPrivateIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return true
	}
	parseOctet := func(s string) int {
		n := 0
		for _, c := range s {
			if c < '0' || c > '9' {
				return -1
			}
			n = n*10 + int(c-'0')
		}
		return n
	}
	a := parseOctet(parts[0])
	b := parseOctet(parts[1])
	if a < 0 || b < 0 {
		return true
	}
	switch {
	case a == 10:
		return true
	case a == 172 && b >= 16 && b <= 31:
		return true
	case a == 192 && b == 168:
		return true
	case a == 169 && b == 254:
		return true
	case a == 0 || a == 127 || a >= 224:
		return true
	case a == 100 && b >= 64 && b <= 127:
		return true // CGNAT RFC 6598
	case a == 198 && b >= 18 && b <= 19:
		return true // benchmarking RFC 2544
	}
	return false
}

// ---------------------------------------------------------------------------
// HTTP scraper
// ---------------------------------------------------------------------------

var (
	httpClient = &http.Client{Timeout: 30 * time.Second}
	pageCache  sync.Map // map[string]string
)

func fetchPage(url string) string {
	if cached, ok := pageCache.Load(url); ok {
		return cached.(string)
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return ""
	}
	s := string(body)
	pageCache.Store(url, s)
	return s
}

func extractIPs(html string) []string {
	skip := map[string]bool{"0.0.0.0": true, "127.0.0.1": true, "255.255.255.255": true}
	seen := map[string]bool{}
	var result []string
	for _, ip := range ipRE.FindAllString(html, -1) {
		if !seen[ip] && !skip[ip] && !isPrivateIP(ip) {
			seen[ip] = true
			result = append(result, ip)
		}
	}
	return result
}

var countryRE1 = regexp.MustCompile(`%s.{0,300}?/country/([a-zA-Z]{2})\.html`)
var countryRE2 = regexp.MustCompile(`/country/([a-zA-Z]{2})\.html.{0,300}?%s`)

func extractCountry(html, ip string) string {
	esc := regexp.QuoteMeta(ip)
	if m := regexp.MustCompile(esc + `.{0,300}?/country/([a-zA-Z]{2})\.html`).FindStringSubmatch(html); len(m) > 1 {
		return strings.ToUpper(m[1])
	}
	if m := regexp.MustCompile(`/country/([a-zA-Z]{2})\.html.{0,300}?` + esc).FindStringSubmatch(html); len(m) > 1 {
		return strings.ToUpper(m[1])
	}
	return ""
}

func scrapeMain() []Resolver {
	html := fetchPage(baseURL)
	if html == "" {
		return nil
	}
	var out []Resolver
	for _, ip := range extractIPs(html) {
		out = append(out, Resolver{
			IP:         ip,
			Country:    extractCountry(html, ip),
			NXDomainOK: true,
		})
	}
	return out
}

func scrapeCountry(code string) []Resolver {
	url := fmt.Sprintf("%s/country/%s.html", baseURL, strings.ToLower(code))
	html := fetchPage(url)
	if html == "" {
		return nil
	}
	var out []Resolver
	for _, ip := range extractIPs(html) {
		out = append(out, Resolver{
			IP:         ip,
			Country:    strings.ToUpper(code),
			NXDomainOK: true,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

func validateOne(r *Resolver, opts Options) {
	var latencies []float64
	for i := 0; i < opts.Rounds; i++ {
		domain := testDomains[rand.Intn(len(testDomains))]
		if ms, ok := dnsQuery(r.IP, domain, opts.Timeout); ok {
			latencies = append(latencies, ms)
		}
	}
	if len(latencies) > 0 {
		var sum float64
		for _, v := range latencies {
			sum += v
		}
		r.AvgMs = round2(sum / float64(len(latencies)))
		r.Reliability = round1(float64(len(latencies)) / float64(opts.Rounds) * 100)
		r.NXDomainOK = checkNXDomain(r.IP, opts.Timeout)
	} else {
		r.AvgMs = 0
		r.Reliability = 0
		r.NXDomainOK = false
	}
}

func validateBatch(resolvers []Resolver, opts Options) []Resolver {
	result := make([]Resolver, len(resolvers))
	copy(result, resolvers)
	sem := make(chan struct{}, opts.MaxWorkers)
	var wg sync.WaitGroup
	for i := range result {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			validateOne(&result[idx], opts)
		}(i)
	}
	wg.Wait()
	return result
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// GetResolvers fetches all public DNS resolvers from publicdns.info.
//
// With opts.Validate=false (default), the list is returned immediately without
// live testing. Set opts.Validate=true to populate AvgMs and Reliability.
func GetResolvers(opts Options) ([]Resolver, error) {
	opts = opts.defaults(2)
	resolvers := scrapeMain()
	if resolvers == nil {
		return nil, fmt.Errorf("publicdns: failed to fetch resolvers from %s", baseURL)
	}
	if opts.Validate {
		resolvers = validateBatch(resolvers, opts)
	}
	return resolvers, nil
}

// GetResolversByCountry fetches resolvers for a specific country.
//
// countryCode must be a valid ISO 3166-1 alpha-2 code (e.g. "US", "IE", "DE").
func GetResolversByCountry(countryCode string, opts Options) ([]Resolver, error) {
	code := strings.TrimSpace(strings.ToUpper(countryCode))
	if len(code) != 2 {
		return nil, fmt.Errorf("publicdns: invalid country code %q (expected 2-letter ISO 3166-1 alpha-2)", countryCode)
	}
	opts = opts.defaults(2)
	resolvers := scrapeCountry(code)
	if resolvers == nil {
		return nil, fmt.Errorf("publicdns: failed to fetch resolvers for country %s", code)
	}
	if opts.Validate {
		resolvers = validateBatch(resolvers, opts)
	}
	return resolvers, nil
}

// GetFastest returns the top n fastest resolvers measured by live latency.
//
// Always performs live validation; opts.Validate is ignored.
func GetFastest(n int, opts Options) ([]Resolver, error) {
	if n <= 0 {
		n = 10
	}
	opts = opts.defaults(3)
	opts.Validate = true
	resolvers, err := GetResolvers(opts)
	if err != nil {
		return nil, err
	}
	var alive []Resolver
	for _, r := range resolvers {
		if r.AvgMs > 0 {
			alive = append(alive, r)
		}
	}
	sort.Slice(alive, func(i, j int) bool {
		return alive[i].AvgMs < alive[j].AvgMs
	})
	if n > len(alive) {
		n = len(alive)
	}
	return alive[:n], nil
}

// privacyProviders lists well-known privacy-focused DNS providers.
var privacyProviders = []PrivacyResolver{
	{Resolver: Resolver{IP: "1.1.1.1", NXDomainOK: true}, Provider: "Cloudflare", NoLog: true, DNSSEC: true, DoH: true, DoT: true},
	{Resolver: Resolver{IP: "1.0.0.1", NXDomainOK: true}, Provider: "Cloudflare", NoLog: true, DNSSEC: true, DoH: true, DoT: true},
	{Resolver: Resolver{IP: "9.9.9.9", NXDomainOK: true}, Provider: "Quad9", NoLog: true, DNSSEC: true, DoH: true, DoT: true},
	{Resolver: Resolver{IP: "149.112.112.112", NXDomainOK: true}, Provider: "Quad9", NoLog: true, DNSSEC: true, DoH: true, DoT: true},
	{Resolver: Resolver{IP: "194.242.2.2", NXDomainOK: true}, Provider: "Mullvad", NoLog: true, DNSSEC: true, DoH: true, DoT: true},
	{Resolver: Resolver{IP: "94.140.14.14", NXDomainOK: true}, Provider: "AdGuard", NoLog: true, DNSSEC: true, DoH: true, DoT: true},
	{Resolver: Resolver{IP: "94.140.15.15", NXDomainOK: true}, Provider: "AdGuard", NoLog: true, DNSSEC: true, DoH: true, DoT: true},
	{Resolver: Resolver{IP: "84.200.69.80", NXDomainOK: true}, Provider: "DNS.Watch", NoLog: true, DNSSEC: true, DoH: false, DoT: false},
	{Resolver: Resolver{IP: "84.200.70.40", NXDomainOK: true}, Provider: "DNS.Watch", NoLog: true, DNSSEC: true, DoH: false, DoT: false},
	{Resolver: Resolver{IP: "45.90.28.0", NXDomainOK: true}, Provider: "NextDNS", NoLog: true, DNSSEC: true, DoH: true, DoT: true},
	{Resolver: Resolver{IP: "76.76.2.0", NXDomainOK: true}, Provider: "Control D", NoLog: true, DNSSEC: true, DoH: true, DoT: true},
	{Resolver: Resolver{IP: "149.112.121.10", NXDomainOK: true}, Provider: "CIRA Shield", NoLog: true, DNSSEC: true, DoH: true, DoT: true},
	{Resolver: Resolver{IP: "149.112.122.10", NXDomainOK: true}, Provider: "CIRA Shield", NoLog: true, DNSSEC: true, DoH: true, DoT: true},
}

// GetPrivacyResolvers returns well-known privacy-focused DNS resolvers.
//
// Each entry includes Provider, NoLog, DNSSEC, DoH, and DoT fields in
// addition to the standard Resolver fields.
func GetPrivacyResolvers(opts Options) []PrivacyResolver {
	opts = opts.defaults(3)
	result := make([]PrivacyResolver, len(privacyProviders))
	copy(result, privacyProviders)
	if opts.Validate {
		var wg sync.WaitGroup
		for i := range result {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				validateOne(&result[idx].Resolver, opts)
			}(i)
		}
		wg.Wait()
	}
	return result
}

// ValidateResolver tests a single DNS resolver and returns live performance data.
func ValidateResolver(ip string, opts Options) (ValidationResult, error) {
	ip = strings.TrimSpace(ip)
	if !ipRE.MatchString(ip) {
		return ValidationResult{}, fmt.Errorf("publicdns: invalid IPv4 address: %q", ip)
	}
	opts = opts.defaults(3)
	var latencies []float64
	for i := 0; i < opts.Rounds; i++ {
		domain := testDomains[rand.Intn(len(testDomains))]
		if ms, ok := dnsQuery(ip, domain, opts.Timeout); ok {
			latencies = append(latencies, ms)
		}
	}
	alive := len(latencies) > 0
	var avgMs float64
	if alive {
		var sum float64
		for _, v := range latencies {
			sum += v
		}
		avgMs = round2(sum / float64(len(latencies)))
	}
	nxOK := false
	if alive {
		nxOK = checkNXDomain(ip, opts.Timeout)
	}
	return ValidationResult{
		IP:          ip,
		Alive:       alive,
		AvgMs:       avgMs,
		Reliability: round1(float64(len(latencies)) / float64(opts.Rounds) * 100),
		NXDomainOK:  nxOK,
		QueriesSent: opts.Rounds,
		QueriesOK:   len(latencies),
	}, nil
}

// BenchmarkResolver runs a thorough multi-domain latency test against a resolver.
func BenchmarkResolver(ip string, opts Options) (BenchmarkResult, error) {
	ip = strings.TrimSpace(ip)
	if !ipRE.MatchString(ip) {
		return BenchmarkResult{}, fmt.Errorf("publicdns: invalid IPv4 address: %q", ip)
	}
	opts = opts.defaults(5)
	var latencies []float64
	failures := 0
	for i := 0; i < opts.Rounds; i++ {
		for _, domain := range testDomains {
			if ms, ok := dnsQuery(ip, domain, opts.Timeout); ok {
				latencies = append(latencies, ms)
			} else {
				failures++
			}
		}
	}
	total := opts.Rounds * len(testDomains)
	alive := len(latencies) > 0
	result := BenchmarkResult{
		IP:                ip,
		Alive:             alive,
		TotalQueries:      total,
		SuccessfulQueries: len(latencies),
		FailedQueries:     failures,
		Latencies:         latencies,
	}
	if alive {
		sorted := make([]float64, len(latencies))
		copy(sorted, latencies)
		sort.Float64s(sorted)
		n := len(sorted)
		var sum float64
		for _, v := range sorted {
			sum += v
		}
		result.AvgMs = round2(sum / float64(n))
		result.MinMs = round2(sorted[0])
		result.MaxMs = round2(sorted[n-1])
		if n%2 == 1 {
			result.MedianMs = round2(sorted[n/2])
		} else {
			result.MedianMs = round2((sorted[n/2-1] + sorted[n/2]) / 2)
		}
		if n > 1 {
			result.JitterMs = round2(stddev(sorted, result.AvgMs))
		}
		p95idx := min(int(float64(n)*0.95), n-1)
		p99idx := min(int(float64(n)*0.99), n-1)
		result.P95Ms = round2(sorted[p95idx])
		result.P99Ms = round2(sorted[p99idx])
		result.Reliability = round1(float64(len(latencies)) / float64(total) * 100)
		result.NXDomainOK = checkNXDomain(ip, opts.Timeout)
	}
	return result, nil
}

// ClearCache purges the internal HTTP page cache, forcing a fresh fetch
// from publicdns.info on the next API call within the same process.
func ClearCache() {
	pageCache.Range(func(k, _ any) bool {
		pageCache.Delete(k)
		return true
	})
}

// ---------------------------------------------------------------------------
// Math helpers
// ---------------------------------------------------------------------------

func round2(v float64) float64 { return math.Round(v*100) / 100 }
func round1(v float64) float64 { return math.Round(v*10) / 10 }
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func stddev(sorted []float64, mean float64) float64 {
	var variance float64
	for _, v := range sorted {
		d := v - mean
		variance += d * d
	}
	return math.Sqrt(variance / float64(len(sorted)))
}

// ---------------------------------------------------------------------------
// CLI  (go run publicdns.go --help)
// ---------------------------------------------------------------------------

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
	version := fs.Bool("version", false, "Print version and exit")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}
	if *version {
		fmt.Println("publicdns-go", Version)
		return
	}

	opts := Options{
		Validate:   *doValidate,
		Timeout:    time.Duration(*timeout*1000) * time.Millisecond,
		Rounds:     *rounds,
		MaxWorkers: 50,
	}

	switch {
	case *cmdList:
		resolvers, err := GetResolvers(opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printResolvers(resolvers, *limit)

	case *cmdCountry != "":
		resolvers, err := GetResolversByCountry(*cmdCountry, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printResolvers(resolvers, *limit)

	case *cmdFastest > 0:
		opts.Validate = true
		resolvers, err := GetFastest(*cmdFastest, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printResolvers(resolvers, 0)

	case *cmdPrivacy:
		resolvers := GetPrivacyResolvers(opts)
		printPrivacyResolvers(resolvers)

	case *cmdValidate != "":
		result, err := ValidateResolver(*cmdValidate, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printValidation(result)

	case *cmdBenchmark != "":
		result, err := BenchmarkResolver(*cmdBenchmark, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printBenchmark(result)

	default:
		fmt.Fprintf(os.Stderr, "publicdns-go %s\nSource: %s\n\n", Version, baseURL)
		fmt.Fprintln(os.Stderr, "Usage:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  go run publicdns.go --list")
		fmt.Fprintln(os.Stderr, "  go run publicdns.go --country ie")
		fmt.Fprintln(os.Stderr, "  go run publicdns.go --fastest 10")
		fmt.Fprintln(os.Stderr, "  go run publicdns.go --validate 1.1.1.1")
		fmt.Fprintln(os.Stderr, "  go run publicdns.go --benchmark 8.8.8.8")
		os.Exit(1)
	}
}

func printResolvers(rs []Resolver, limit int) {
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

func printPrivacyResolvers(rs []PrivacyResolver) {
	fmt.Printf("  %-4s  %-16s  %-14s  %-6s  %-6s  %-5s  %-5s  %-5s\n",
		"#", "IP", "Provider", "NoLog", "DNSSEC", "DoH", "DoT", "Avg ms")
	fmt.Println("  " + strings.Repeat("-", 80))
	for i, r := range rs {
		noLog := yesNo(r.NoLog)
		dnssec := yesNo(r.DNSSEC)
		doh := yesNo(r.DoH)
		dot := yesNo(r.DoT)
		avgStr := "N/A"
		if r.AvgMs > 0 {
			avgStr = fmt.Sprintf("%.1fms", r.AvgMs)
		}
		fmt.Printf("  %-4d  %-16s  %-14s  %-6s  %-6s  %-5s  %-5s  %-8s\n",
			i+1, r.IP, r.Provider, noLog, dnssec, doh, dot, avgStr)
	}
}

func printValidation(r ValidationResult) {
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

func printBenchmark(r BenchmarkResult) {
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

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
