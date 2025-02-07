package tests

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"spidey_sense/proxy"
	"testing"
	"time"
)

// Test function for startProxy
func TestStartProxy(t *testing.T) {
	// Run the proxy in a Goroutine
	go func() {
		proxy.StartProxy()
	}()

	// Give the proxy some time to start
	time.Sleep(1 * time.Second)

	// Create a test server to act as the backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from backend"))
	}))
	defer backend.Close()

	// Parse the proxy URL
	proxyURL, err := url.Parse("http://localhost:8080")
	if err != nil {
		t.Fatalf("Failed to parse proxy URL: %v", err)
	}

	// Make an HTTP request through the proxy
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("Failed to send request through proxy: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Check if the response matches expected output
	expected := "Hello from backend"
	if string(body) != expected {
		t.Errorf("Expected %q but got %q", expected, string(body))
	}
}
