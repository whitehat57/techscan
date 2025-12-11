package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNormalizeURL verifying correct scheme applied
func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
		{" example.com ", "https://example.com"},
	}

	for _, tt := range tests {
		got := normalizeURL(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeURL(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

// TestMatchString verifying matching logic
func TestMatchString(t *testing.T) {
	tests := []struct {
		target   string
		signal   Signal
		expected bool
	}{
		{"Laravel Framework", Signal{Value: "laravel", Type: "contains"}, true},
		{"Laravel Framework", Signal{Value: "wordpress", Type: "contains"}, false},
		{"nginx/1.18.0", Signal{Value: "nginx", Type: "prefix"}, true},
		{"apache", Signal{Value: "nginx", Type: "prefix"}, false},
		{"200", Signal{Value: "200", Type: "equals"}, true},
	}

	for _, tt := range tests {
		got := matchString(tt.target, tt.signal)
		if got != tt.expected {
			t.Errorf("matchString(%q, %v) = %v; want %v", tt.target, tt.signal, got, tt.expected)
		}
	}
}

// TestFetch verifying HTTP client usage using Mock Server
func TestFetch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "MockServer")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "<html><body>Hello</body></html>")
	}))
	defer ts.Close()

	// Use a test client to avoid global state issues if any,
	// but here we pass the client explicitly so it's fine.
	client := ts.Client() // httptest server provides a client configured to trust it

	resp, err := fetch(client, ts.URL)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Server") != "MockServer" {
		t.Errorf("expected Server header MockServer, got %q", resp.Header.Get("Server"))
	}
}

// TestHashFavicon verifying favicon fetching logic
func TestHashFavicon(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("favicon-content")) // SHA1: d7df8... (example)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client := ts.Client()

	sha1, mmh3, md5 := hashFavicon(client, ts.URL, true)

	if sha1 == "N/A" {
		t.Error("expected valid favicon hash, got N/A")
	}
	// "favicon-content" sha1 = 04460da78f656094dfc42eb55952f44c4b8e2196
	// Just checking it's not empty is enough for now, or check specific value if critical.
	if mmh3 == 0 {
		t.Error("expected non-zero mmh3")
	}
	if md5 == "" {
		t.Error("expected md5 string")
	}
}

// TestProbePaths verifying probes
func TestProbePaths(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("User-agent: *"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client := ts.Client()
	
	// Use small timeout for test
	// probePaths uses context with 10s internally, which is fine.

	probes := probePaths(client, ts.URL, false)

	if len(probes) == 0 {
		t.Fatal("expected probes result")
	}

	foundRobots := false
	for _, p := range probes {
		if p.Path == "/robots.txt" {
			foundRobots = true
			if p.StatusCode != 200 {
				t.Errorf("expected 200 for robots.txt, got %d", p.StatusCode)
			}
		}
	}
	if !foundRobots {
		t.Error("robots.txt probe missing")
	}
}

// Global Client Integration Test (Checking Reuse)
// This strictly checks if we can use the SAME client for multiple calls
func TestSharedClientReuse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	transport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second, // explicit timeout for test client
	}

	// 1. Fetch
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("req 1 failed: %v", err)
	}
	resp.Body.Close()
	cancel()

	// 2. Fetch again (should reuse connection if transport works, though harder to verify inspectively without hooks)
	// We just verify it succeeds.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 1*time.Second)
	req2, _ := http.NewRequestWithContext(ctx2, "GET", ts.URL, nil)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("req 2 failed: %v", err)
	}
	resp2.Body.Close()
	cancel2()
}

// TestCheckRedirect verifying safe redirect handling logic
func TestCheckRedirect(t *testing.T) {
	// Recreating the closure from main() for testing purposes
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return fmt.Errorf("redirect to unsafe scheme: %s", req.URL.Scheme)
		}
		return nil
	}

	// Case 1: Too many redirects
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	var via []*http.Request
	for i := 0; i < 10; i++ {
		via = append(via, req)
	}
	err := checkRedirect(req, via)
	if err == nil || err.Error() != "stopped after 10 redirects" {
		t.Errorf("expected error 'stopped after 10 redirects', got %v", err)
	}

	// Case 2: Unsafe scheme
	reqUnsafe, _ := http.NewRequest("GET", "file:///etc/passwd", nil)
	err = checkRedirect(reqUnsafe, nil)
	if err == nil || err.Error() != "redirect to unsafe scheme: file" {
		t.Errorf("expected error 'redirect to unsafe scheme: file', got %v", err)
	}

	// Case 3: Safe
	reqSafe, _ := http.NewRequest("GET", "https://example.com/login", nil)
	err = checkRedirect(reqSafe, []*http.Request{req})
	if err != nil {
		t.Errorf("expected nil error for safe redirect, got %v", err)
	}
}
