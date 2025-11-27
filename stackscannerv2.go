package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/spaolacci/murmur3"
)

const defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// ===== Struct Data =====

type TechStack struct {
	URL         string            `json:"url"`
	FinalURL    string            `json:"final_url"`
	Headers     map[string]string `json:"headers"`
	TLSValid    bool              `json:"tls_valid"`
	TLSIssuer   string            `json:"tls_issuer"`
	IPs         []string          `json:"ips"`
	CNAME       string            `json:"cname"`
	ReverseDNS  []string          `json:"reverse_dns"`
	FaviconSHA1 string            `json:"favicon_sha1"`
	FaviconMMH3 uint32            `json:"favicon_mmh3"`

	CMS          []string            `json:"cms"`
	Frontend     []string            `json:"frontend"`
	Backend      []string            `json:"backend"`
	Analytics    []string            `json:"analytics"`
	CDN          []string            `json:"cdn"`
	Hosting      []string            `json:"hosting"`
	Fingerprints []string            `json:"fingerprints"`
	Other        map[string][]string `json:"other_categories,omitempty"`
}

type ProbeResult struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	BodySample string `json:"body_sample"`
}

type ScanEnv struct {
	HTML       string
	Headers    map[string]string
	ScriptSrcs []string
	CNAME      string
	RDNS       []string
	IPs        []string
	FavSHA1    string
	FavMMH3    uint32

	Probes []ProbeResult
}

type Signal struct {
	Source string `json:"source"`           // html, header, header_key, script_src, dns_cname, dns_rdns, ip, favicon_sha1, favicon_mmh3, probe_status, probe_body
	Type   string `json:"type"`             // contains, equals, prefix
	Key    string `json:"key,omitempty"`    // untuk header (mis. X-Powered-By)
	Value  string `json:"value"`            // pattern
	Weight int    `json:"weight,omitempty"` // default 1
}

type TechRule struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Category  string   `json:"category"`  // cms, frontend, backend, analytics, cdn, hosting, fingerprint, dll.
	Threshold int      `json:"threshold"` // minimal skor buat dianggap match
	Signals   []Signal `json:"signals"`
}

type RulesFile struct {
	Technologies []TechRule `json:"technologies"`
}

// ===== Flags =====

func main() {
	var (
		verbose   bool
		asJSON    bool
		rulesPath string
		deepMode  bool
	)

	flag.BoolVar(&verbose, "v", false, "verbose mode (debug logs to stderr)")
	flag.BoolVar(&asJSON, "json", false, "output JSON instead of human-readable text")
	flag.StringVar(&rulesPath, "rules", "rules.json", "path to rules JSON file")
	flag.BoolVar(&deepMode, "deep", false, "enable deep probing (extra paths & error page)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("Usage:")
		fmt.Println("  stackscanner_rules [-v] [-json] [--deep] [-rules rules.json] <url>")
		os.Exit(1)
	}

	target := flag.Arg(0)

	if verbose {
		log.Printf("[*] Loading rules from: %s\n", rulesPath)
	}

	rules, err := loadRules(rulesPath)
	if err != nil {
		log.Fatalf("failed to load rules: %v\n", err)
	}

	if verbose {
		log.Printf("[*] Scanning target: %s (deep=%v)\n", target, deepMode)
	}

	info, err := scan(target, verbose, deepMode, rules)
	if err != nil {
		log.Fatalf("scan failed: %v\n", err)
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(info); err != nil {
			log.Fatalf("json encode failed: %v\n", err)
		}
		return
	}

	printHuman(info)
}

// ===== Rules Engine =====

func loadRules(path string) (*RulesFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rf RulesFile
	dec := json.NewDecoder(f)
	if err := dec.Decode(&rf); err != nil {
		return nil, err
	}

	for i := range rf.Technologies {
		if rf.Technologies[i].Threshold == 0 {
			rf.Technologies[i].Threshold = 1
		}
		for j := range rf.Technologies[i].Signals {
			if rf.Technologies[i].Signals[j].Weight == 0 {
				rf.Technologies[i].Signals[j].Weight = 1
			}
		}
	}
	return &rf, nil
}

func applyRules(env *ScanEnv, rules *RulesFile) map[string][]string {
	scores := make(map[string]int)
	categories := make(map[string]string)
	names := make(map[string]string)

	for _, tech := range rules.Technologies {
		categories[tech.ID] = tech.Category
		names[tech.ID] = tech.Name
		for _, sig := range tech.Signals {
			if matchSignal(env, sig) {
				scores[tech.ID] += max(sig.Weight, 1)
			}
		}
	}

	result := make(map[string][]string)
	for _, tech := range rules.Technologies {
		if scores[tech.ID] >= tech.Threshold {
			cat := tech.Category
			result[cat] = append(result[cat], tech.Name)
		}
	}

	for cat, list := range result {
		result[cat] = uniqueStrings(list)
	}

	return result
}

func matchSignal(env *ScanEnv, s Signal) bool {
	switch s.Source {
	case "html":
		return matchString(env.HTML, s)
	case "header":
		if s.Key == "" {
			return false
		}
		val := ""
		for k, v := range env.Headers {
			if strings.EqualFold(k, s.Key) {
				val = v
				break
			}
		}
		return matchString(val, s)
	case "header_key":
		for k := range env.Headers {
			if matchString(k, s) {
				return true
			}
		}
		return false
	case "script_src":
		for _, src := range env.ScriptSrcs {
			if matchString(src, s) {
				return true
			}
		}
		return false
	case "dns_cname":
		return matchString(env.CNAME, s)
	case "dns_rdns":
		for _, r := range env.RDNS {
			if matchString(r, s) {
				return true
			}
		}
		return false
	case "ip":
		for _, ip := range env.IPs {
			if matchString(ip, s) {
				return true
			}
		}
		return false
	case "favicon_sha1":
		return matchString(env.FavSHA1, s)
	case "favicon_mmh3":
		if s.Type == "equals" && s.Value != "" {
			return fmt.Sprint(env.FavMMH3) == s.Value
		}
		return false
	case "probe_status":
		for _, p := range env.Probes {
			token := fmt.Sprintf("%s:%d", strings.ToLower(p.Path), p.StatusCode)
			if matchString(token, s) {
				return true
			}
		}
		return false
	case "probe_body":
		for _, p := range env.Probes {
			if matchString(p.BodySample, s) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func matchString(target string, s Signal) bool {
	t := strings.ToLower(strings.TrimSpace(target))
	v := strings.ToLower(strings.TrimSpace(s.Value))

	switch s.Type {
	case "contains":
		return strings.Contains(t, v)
	case "equals":
		return t == v
	case "prefix":
		return strings.HasPrefix(t, v)
	default:
		return false
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ===== Scanner Core =====

func scan(rawURL string, verbose bool, deepMode bool, rules *RulesFile) (*TechStack, error) {
	normalized := normalizeURL(rawURL)
	if verbose {
		log.Printf("[*] Normalized URL: %s\n", normalized)
	}

	resp, err := fetch(normalized)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	host := resp.Request.URL.Hostname()
	if verbose {
		log.Printf("[*] Final URL after redirects: %s (host: %s)\n", finalURL, host)
	}

	headers := extractHeaders(resp)

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	htmlLower := strings.ToLower(string(bodyBytes))

	if verbose {
		log.Printf("[*] HTML size: %d bytes\n", len(bodyBytes))
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	scriptSrcs := extractScriptSrcs(doc)

	ips, cname, reverse := dnsLookup(host, verbose)
	tlsValid, tlsIssuer := checkTLS(host)
	if verbose {
		log.Printf("[*] TLS: valid=%v issuer=%s\n", tlsValid, tlsIssuer)
	}

	favSHA, favMMH, _ := hashFavicon(finalURL, verbose)

	var probes []ProbeResult
	if deepMode {
		probes = probePaths(finalURL, verbose)
	}

	env := &ScanEnv{
		HTML:       htmlLower,
		Headers:    headers,
		ScriptSrcs: scriptSrcs,
		CNAME:      cname,
		RDNS:       reverse,
		IPs:        ips,
		FavSHA1:    favSHA,
		FavMMH3:    favMMH,
		Probes:     probes,
	}

	detected := applyRules(env, rules)

	ts := &TechStack{
		URL:          rawURL,
		FinalURL:     finalURL,
		Headers:      headers,
		TLSValid:     tlsValid,
		TLSIssuer:    tlsIssuer,
		IPs:          ips,
		CNAME:        cname,
		ReverseDNS:   reverse,
		FaviconSHA1:  favSHA,
		FaviconMMH3:  favMMH,
		CMS:          detected["cms"],
		Frontend:     detected["frontend"],
		Backend:      detected["backend"],
		Analytics:    detected["analytics"],
		CDN:          detected["cdn"],
		Hosting:      detected["hosting"],
		Fingerprints: detected["fingerprint"],
	}

	other := make(map[string][]string)
	for cat, list := range detected {
		switch cat {
		case "cms", "frontend", "backend", "analytics", "cdn", "hosting", "fingerprint":
		default:
			other[cat] = list
		}
	}
	if len(other) > 0 {
		ts.Other = other
	}

	return ts, nil
}

// ===== Helpers: HTTP, DNS, TLS, favicon, probes =====

func normalizeURL(target string) string {
	target = strings.TrimSpace(target)
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	return target
}

func fetch(target string) (*http.Response, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	return client.Do(req)
}

func extractHeaders(resp *http.Response) map[string]string {
	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}
	return headers
}

func extractScriptSrcs(doc *goquery.Document) []string {
	var srcs []string
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		if src, ok := s.Attr("src"); ok && src != "" {
			srcs = append(srcs, strings.ToLower(src))
		}
	})
	return srcs
}

func dnsLookup(host string, verbose bool) ([]string, string, []string) {
	var ips []string
	var rdns []string
	if host == "" {
		return ips, "", rdns
	}

	cname, _ := net.LookupCNAME(host)

	ipObjs, _ := net.LookupIP(host)
	for _, ip := range ipObjs {
		if ipv4 := ip.To4(); ipv4 != nil {
			s := ipv4.String()
			ips = append(ips, s)
			ptrs, _ := net.LookupAddr(s)
			for _, p := range ptrs {
				rdns = append(rdns, strings.TrimSuffix(p, "."))
			}
		}
	}

	ips = uniqueStrings(ips)
	rdns = uniqueStrings(rdns)

	if verbose {
		log.Printf("[*] DNS: cname=%s ips=%v rdns=%v\n", cname, ips, rdns)
	}

	return ips, cname, rdns
}

func checkTLS(host string) (bool, string) {
	if host == "" {
		return false, ""
	}
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{
		ServerName: host,
	})
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		return true, cert.Issuer.CommonName
	}
	return true, ""
}

func hashFavicon(pageURL string, verbose bool) (string, uint32, string) {
	u, err := url.Parse(pageURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		if verbose {
			log.Printf("[!] cannot parse URL for favicon: %s (%v)\n", pageURL, err)
		}
		return "N/A", 0, ""
	}

	base := u.Scheme + "://" + u.Host
	favURL := base + "/favicon.ico"

	if verbose {
		log.Printf("[*] Fetching favicon: %s\n", favURL)
	}

	client := &http.Client{Timeout: 7 * time.Second}
	req, err := http.NewRequest("GET", favURL, nil)
	if err != nil {
		return "N/A", 0, ""
	}
	req.Header.Set("User-Agent", defaultUA)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if verbose {
			if err != nil {
				log.Printf("[!] favicon request error: %v\n", err)
			} else {
				log.Printf("[!] favicon status: %d\n", resp.StatusCode)
			}
		}
		return "N/A", 0, ""
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil || len(data) == 0 {
		if verbose {
			log.Printf("[!] favicon read error or empty body\n")
		}
		return "N/A", 0, ""
	}

	sha := sha1.Sum(data)
	shaStr := hex.EncodeToString(sha[:])
	mmh := murmur3.Sum32(data)

	if verbose {
		log.Printf("[*] favicon sha1=%s mmh3=%d\n", shaStr, mmh)
	}

	return shaStr, mmh, ""
}

// Deep probing: path signatures + 404/error page
func probePaths(finalURL string, verbose bool) []ProbeResult {
	u, err := url.Parse(finalURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		if verbose {
			log.Printf("[!] cannot parse URL for probing: %s (%v)\n", finalURL, err)
		}
		return nil
	}
	base := u.Scheme + "://" + u.Host

	paths := []string{
		"/robots.txt",
		"/sitemap.xml",
		"/wp-json/",
		"/wp-login.php",
		"/wp-admin/",
	}

	rand.Seed(time.Now().UnixNano())
	randomPath := fmt.Sprintf("/__stackscanner_%d__", rand.Intn(1_000_000_000))
	paths = append(paths, randomPath)

	client := &http.Client{Timeout: 10 * time.Second}
	var probes []ProbeResult

	for _, p := range paths {
		full := base + p
		if verbose {
			log.Printf("[*] Probe %s\n", full)
		}
		req, err := http.NewRequest("GET", full, nil)
		if err != nil {
			if verbose {
				log.Printf("[!] probe request build error for %s: %v\n", full, err)
			}
			continue
		}
		req.Header.Set("User-Agent", defaultUA)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		resp, err := client.Do(req)
		if err != nil {
			if verbose {
				log.Printf("[!] probe error for %s: %v\n", full, err)
			}
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		sample := strings.ToLower(string(body))
		const maxSample = 1024
		if len(sample) > maxSample {
			sample = sample[:maxSample]
		}

		if verbose {
			log.Printf("[*] Probe %s -> %d (%d bytes)\n", p, resp.StatusCode, len(body))
		}

		probes = append(probes, ProbeResult{
			Path:       p,
			StatusCode: resp.StatusCode,
			BodySample: sample,
		})
	}

	return probes
}

// ===== Utils =====

func uniqueStrings(input []string) []string {
	set := make(map[string]struct{})
	var out []string
	for _, v := range input {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := set[v]; !ok {
			set[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

func printHuman(info *TechStack) {
	fmt.Println("📡 Scan Result for:", info.URL)
	if info.URL != info.FinalURL && info.FinalURL != "" {
		fmt.Println("   ↳ Final URL:", info.FinalURL)
	}
	fmt.Println(strings.Repeat("─", 60))

	fmt.Printf("🔒 TLS handshake OK: %v", info.TLSValid)
	if info.TLSIssuer != "" {
		fmt.Printf(" (Issuer: %s)", info.TLSIssuer)
	}
	fmt.Println()

	if len(info.Hosting) > 0 {
		fmt.Println("🏢 Hosting / Infra Guess:", strings.Join(info.Hosting, ", "))
	}
	if len(info.CDN) > 0 {
		fmt.Println("🌐 CDN / WAF Hints:", strings.Join(info.CDN, ", "))
	}

	if len(info.IPs) > 0 {
		fmt.Println("📡 IPs:", strings.Join(info.IPs, ", "))
	}
	if len(info.ReverseDNS) > 0 {
		fmt.Println("🔎 rDNS:", strings.Join(info.ReverseDNS, ", "))
	}
	if info.CNAME != "" && !strings.EqualFold(info.CNAME, info.FinalURL) {
		fmt.Println("🔗 CNAME:", info.CNAME)
	}

	if len(info.Backend) > 0 {
		fmt.Println("⚙️  Backend Detected:", strings.Join(info.Backend, ", "))
	} else {
		fmt.Println("⚙️  Backend Detected: (not detected)")
	}

	if len(info.Frontend) > 0 {
		fmt.Println("🎨 Frontend Detected:", strings.Join(info.Frontend, ", "))
	} else {
		fmt.Println("🎨 Frontend Detected: (not detected)")
	}

	if len(info.CMS) > 0 {
		fmt.Println("📦 CMS / Platform:", strings.Join(info.CMS, ", "))
	} else {
		fmt.Println("📦 CMS / Platform: (not detected)")
	}

	if len(info.Analytics) > 0 {
		fmt.Println("📈 Analytics / Tags:", strings.Join(info.Analytics, ", "))
	} else {
		fmt.Println("📈 Analytics / Tags: (not detected)")
	}

	if len(info.Fingerprints) > 0 {
		fmt.Println("🧬 Fingerprints:", strings.Join(info.Fingerprints, ", "))
	}

	if info.FaviconSHA1 != "N/A" {
		fmt.Printf("🖼️ Favicon SHA1: %s\n", info.FaviconSHA1)
		fmt.Printf("   Favicon MMH3: %d\n", info.FaviconMMH3)
	} else {
		fmt.Println("🖼️ Favicon: not fetched")
	}

	if len(info.Other) > 0 {
		fmt.Println("📚 Other Detected Categories:")
		for cat, list := range info.Other {
			fmt.Printf("  - %s: %s\n", cat, strings.Join(list, ", "))
		}
	}

	fmt.Println(strings.Repeat("─", 60))
}
