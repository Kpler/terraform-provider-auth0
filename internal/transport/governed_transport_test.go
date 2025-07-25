package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"

	"github.com/auth0/terraform-provider-auth0/internal/ratelimit"
)

type mockRoundTripper struct {
	response *http.Response
	err      error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.response, m.err
}

func TestGovernedTransport_RoundTrip(t *testing.T) {
	// Create a mock rate limit manager
	rateLimitManager, _ := ratelimit.NewRateLimitManager(80)
	
	// Create a logger
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "test",
		Output: io.Discard,
	})
	
	// Create mock response with rate limit headers
	resetTime := time.Now().Unix() + 60
	mockResponse := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"x-ratelimit-limit":     []string{"100"},
			"x-ratelimit-remaining": []string{"95"},
			"x-ratelimit-reset":     []string{strconv.FormatInt(resetTime, 10)},
		},
		Body: io.NopCloser(bytes.NewBufferString("{}")),
	}
	
	mockRoundTripper := &mockRoundTripper{response: mockResponse}
	
	// Create governed transport
	transport := NewGovernedTransport(mockRoundTripper, rateLimitManager, logger)
	
	// Create test request
	req, _ := http.NewRequest("GET", "https://example.auth0.com/api/v2/users", nil)
	
	// Make request
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	
	if resp.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}
	
	// Check that rate limit status was updated
	status := rateLimitManager.Status("GET", "/api/v2/users")
	if status.Limit() != 100 {
		t.Errorf("Expected limit 100, got %d", status.Limit())
	}
	if status.Remaining() != 95 {
		t.Errorf("Expected remaining 95, got %d", status.Remaining())
	}
}

func TestGovernedTransport_PreRequestHook_NoThrottling(t *testing.T) {
	// Create rate limit manager with high capacity
	rateLimitManager, _ := ratelimit.NewRateLimitManager(90)
	
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "test",
		Output: io.Discard,
	})
	
	mockRoundTripper := &mockRoundTripper{response: &http.Response{StatusCode: 200}}
	transport := NewGovernedTransport(mockRoundTripper, rateLimitManager, logger)
	
	// Should not throttle when under capacity
	err := transport.preRequestHook(context.Background(), "GET", "/api/v2/users")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestGovernedTransport_PreRequestHook_WithThrottling(t *testing.T) {
	// Create rate limit manager with low capacity
	rateLimitManager, _ := ratelimit.NewRateLimitManager(10)
	
	// Update with high utilization (should trigger throttling)
	resetTime := time.Now().Unix() + 2 // Short reset time for test
	rateLimitManager.Update("GET", "/api/v2/users", 100, 10, resetTime)
	
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "test",
		Output: io.Discard,
	})
	
	mockRoundTripper := &mockRoundTripper{response: &http.Response{StatusCode: 200}}
	transport := NewGovernedTransport(mockRoundTripper, rateLimitManager, logger)
	
	// Create context with timeout to prevent test from hanging
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	start := time.Now()
	err := transport.preRequestHook(ctx, "GET", "/api/v2/users")
	duration := time.Since(start)
	
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	
	// Should have slept for at least 1 second
	if duration < time.Second {
		t.Errorf("Expected to sleep for at least 1 second, slept for %v", duration)
	}
}

func TestGovernedTransport_PostRequestHook_InvalidHeaders(t *testing.T) {
	rateLimitManager, _ := ratelimit.NewRateLimitManager(80)
	
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "test",
		Output: io.Discard,
	})
	
	mockRoundTripper := &mockRoundTripper{}
	transport := NewGovernedTransport(mockRoundTripper, rateLimitManager, logger)
	
	// Test with response missing headers
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}
	
	// Should not panic or error
	transport.postRequestHook("GET", "/api/v2/users", resp)
	
	// Test with nil response
	transport.postRequestHook("GET", "/api/v2/users", nil)
}

func TestGovernedTransport_RoundTrip_WithError(t *testing.T) {
	rateLimitManager, _ := ratelimit.NewRateLimitManager(80)
	
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "test",
		Output: io.Discard,
	})
	
	// Mock transport that returns an error
	mockRoundTripper := &mockRoundTripper{response: nil, err: fmt.Errorf("connection failed")}
	transport := NewGovernedTransport(mockRoundTripper, rateLimitManager, logger)
	
	req, _ := http.NewRequest("GET", "https://example.auth0.com/api/v2/users", nil)
	
	// This should return an error but still call postRequestHook
	_, err := transport.RoundTrip(req)
	if err == nil {
		t.Error("Expected an error from RoundTrip")
	}
}

func TestGovernedTransport_PreRequestHook_WithCancellation(t *testing.T) {
	rateLimitManager, _ := ratelimit.NewRateLimitManager(10)
	
	// Set high utilization to trigger throttling
	resetTime := time.Now().Unix() + 10 // 10 seconds in future
	rateLimitManager.Update("GET", "/api/v2/users", 100, 5, resetTime)
	
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "test",
		Output: io.Discard,
	})
	
	mockRoundTripper := &mockRoundTripper{response: &http.Response{StatusCode: 200}}
	transport := NewGovernedTransport(mockRoundTripper, rateLimitManager, logger)
	
	// Create context that is immediately cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	
	err := transport.preRequestHook(ctx, "GET", "/api/v2/users")
	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestGovernedTransport_PreRequestHook_WithTimeCapLimiting(t *testing.T) {
	rateLimitManager, _ := ratelimit.NewRateLimitManager(10)
	
	// Set high utilization with very long reset time (should be capped)
	resetTime := time.Now().Unix() + 500 // 500 seconds in future (should be capped to 300)
	rateLimitManager.Update("GET", "/api/v2/users", 100, 5, resetTime)
	
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "test",
		Output: io.Discard,
	})
	
	mockRoundTripper := &mockRoundTripper{response: &http.Response{StatusCode: 200}}
	transport := NewGovernedTransport(mockRoundTripper, rateLimitManager, logger)
	
	// This should cap the sleep time to 300 seconds, but for testing we'll use a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	
	start := time.Now()
	err := transport.preRequestHook(ctx, "GET", "/api/v2/users")
	duration := time.Since(start)
	
	// Should get context deadline exceeded
	if err == nil {
		t.Error("Expected context deadline exceeded error")
	}
	
	// Should have tried to sleep but been interrupted
	if duration < 50*time.Millisecond {
		t.Error("Expected to attempt sleeping before context cancellation")
	}
}

func TestGovernedTransport_PostRequestHook_WithMissingLimitHeader(t *testing.T) {
	rateLimitManager, _ := ratelimit.NewRateLimitManager(80)
	
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "test",
		Output: io.Discard,
	})
	
	mockRoundTripper := &mockRoundTripper{}
	transport := NewGovernedTransport(mockRoundTripper, rateLimitManager, logger)
	
	resetTime := time.Now().Unix() + 60
	
	// Response with only reset header, missing limit
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"x-ratelimit-reset": []string{strconv.FormatInt(resetTime, 10)},
			// Missing limit and remaining headers
		},
	}
	
	// Should not panic, should just return early
	transport.postRequestHook("GET", "/api/v2/users", resp)
	
	// Status should remain at defaults since update failed
	status := rateLimitManager.Status("GET", "/api/v2/users")
	if status.Limit() != 0 {
		t.Errorf("Expected limit to remain 0, got %d", status.Limit())
	}
}

func TestGovernedTransport_PostRequestHook_WithMissingRemainingHeader(t *testing.T) {
	rateLimitManager, _ := ratelimit.NewRateLimitManager(80)
	
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "test",
		Output: io.Discard,
	})
	
	mockRoundTripper := &mockRoundTripper{}
	transport := NewGovernedTransport(mockRoundTripper, rateLimitManager, logger)
	
	resetTime := time.Now().Unix() + 60
	
	// Response with reset and limit, missing remaining
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"x-ratelimit-reset": []string{strconv.FormatInt(resetTime, 10)},
			"x-ratelimit-limit": []string{"100"},
			// Missing remaining header
		},
	}
	
	// Should not panic, should just return early
	transport.postRequestHook("GET", "/api/v2/users", resp)
	
	// Status should remain at defaults since update failed
	status := rateLimitManager.Status("GET", "/api/v2/users")
	if status.Limit() != 0 {
		t.Errorf("Expected limit to remain 0, got %d", status.Limit())
	}
}

func TestGovernedTransport_PostRequestHook_AlternativeHeaders(t *testing.T) {
	rateLimitManager, _ := ratelimit.NewRateLimitManager(80)
	
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "test",
		Output: io.Discard,
	})
	
	mockRoundTripper := &mockRoundTripper{}
	transport := NewGovernedTransport(mockRoundTripper, rateLimitManager, logger)
	
	resetTime := time.Now().Unix() + 60
	
	// Test with alternative header names (capital R)
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-RateLimit-Limit":     []string{"100"},
			"X-RateLimit-Remaining": []string{"85"},
			"X-RateLimit-Reset":     []string{strconv.FormatInt(resetTime, 10)},
		},
	}
	
	transport.postRequestHook("GET", "/api/v2/users", resp)
	
	// Check that rate limit status was updated
	status := rateLimitManager.Status("GET", "/api/v2/users")
	if status.Limit() != 100 {
		t.Errorf("Expected limit 100, got %d", status.Limit())
	}
	if status.Remaining() != 85 {
		t.Errorf("Expected remaining 85, got %d", status.Remaining())
	}
}