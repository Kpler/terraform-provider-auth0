package transport

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/hashicorp/go-hclog"

	"github.com/auth0/terraform-provider-auth0/internal/ratelimit"
)

const (
	X_RATE_LIMIT_LIMIT     = "x-ratelimit-limit"
	X_RATE_LIMIT_REMAINING = "x-ratelimit-remaining" 
	X_RATE_LIMIT_RESET     = "x-ratelimit-reset"
)

type GovernedTransport struct {
	base            http.RoundTripper
	rateLimitManager *ratelimit.RateLimitManager
	logger          hclog.Logger
}

// NewGovernedTransport returns a governed transport that relies on pre- and post-
// requests from the http round tripper. The pre request consults the rate limit manager
// to determine if sleeping for the Auth0 API rate limit window is called for.
// The post request updates the information it is holding about the current api
// rate limits.
func NewGovernedTransport(base http.RoundTripper, rateLimitManager *ratelimit.RateLimitManager, logger hclog.Logger) *GovernedTransport {
	return &GovernedTransport{
		base:            base,
		rateLimitManager: rateLimitManager,
		logger:          logger,
	}
}

// RoundTrip returns the final http response after it has managed the api rate
// limit accounting in the pre and post request hooks.
func (t *GovernedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	path := req.URL.Path
	if err := t.preRequestHook(req.Context(), req.Method, path); err != nil {
		return nil, err
	}

	resp, err := t.base.RoundTrip(req)
	// always attempt to save rate limit headers
	t.postRequestHook(req.Method, path, resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (t *GovernedTransport) preRequestHook(ctx context.Context, method, path string) error {
	if t.rateLimitManager.HasCapacity(method, path) {
		return nil
	}

	status := t.rateLimitManager.Status(method, path)
	now := time.Now().Unix()
	timeToSleep := status.Reset() - now

	// Cap the sleep time to prevent excessive waiting
	if timeToSleep > 300 { // 5 minutes max
		timeToSleep = 300
	}
	if timeToSleep < 1 {
		timeToSleep = 1
	}

	line := fmt.Sprintf("Throttling Auth0 API requests; sleeping for %d seconds until rate limit reset (path class %q, bucket %q: %d remaining of %d total); current request \"%s %s\"",
		timeToSleep,
		t.rateLimitManager.Class(method, path),
		t.rateLimitManager.Bucket(method, path),
		status.Remaining(),
		status.Limit(),
		method,
		path,
	)
	t.logger.Info(line)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.NewTimer(time.Second * time.Duration(timeToSleep)).C:
		return nil
	}
}

func (t *GovernedTransport) postRequestHook(method, path string, resp *http.Response) {
	if resp == nil {
		return
	}
	
	// Auth0 uses X-RateLimit-Reset (Unix timestamp)
	// Try multiple header name variations due to inconsistencies in test environments
	resetHeader := resp.Header.Get("x-ratelimit-reset")
	if resetHeader == "" {
		if vals, ok := resp.Header["x-ratelimit-reset"]; ok && len(vals) > 0 {
			resetHeader = vals[0]
		} else if vals, ok := resp.Header["X-RateLimit-Reset"]; ok && len(vals) > 0 {
			resetHeader = vals[0]
		} else {
			resetHeader = resp.Header.Get("X-RateLimit-Reset")
		}
	}
	
	if resetHeader == "" {
		t.logger.Debug(fmt.Sprintf("No rate limit reset header found in response for %s %s. Headers: %v", method, path, resp.Header))
		return
	}
	
	reset, err := strconv.ParseInt(resetHeader, 10, 64)
	if err != nil {
		t.logger.Warn(fmt.Sprintf("%q response header is missing or invalid, skipping postRequestHook: %+v", X_RATE_LIMIT_RESET, err))
		return
	}
	
	limitHeader := resp.Header.Get("x-ratelimit-limit")
	if limitHeader == "" {
		// Try direct access
		if vals, ok := resp.Header["x-ratelimit-limit"]; ok && len(vals) > 0 {
			limitHeader = vals[0]
		} else if vals, ok := resp.Header["X-RateLimit-Limit"]; ok && len(vals) > 0 {
			limitHeader = vals[0]
		} else {
			limitHeader = resp.Header.Get("X-RateLimit-Limit")
		}
	}
	
	limit, err := strconv.Atoi(limitHeader)
	if err != nil {
		t.logger.Warn(fmt.Sprintf("%q response header is missing or invalid, skipping postRequestHook: %+v", X_RATE_LIMIT_LIMIT, err))
		return
	}
	
	remainingHeader := resp.Header.Get("x-ratelimit-remaining")
	if remainingHeader == "" {
		// Try direct access
		if vals, ok := resp.Header["x-ratelimit-remaining"]; ok && len(vals) > 0 {
			remainingHeader = vals[0]
		} else if vals, ok := resp.Header["X-RateLimit-Remaining"]; ok && len(vals) > 0 {
			remainingHeader = vals[0]
		} else {
			remainingHeader = resp.Header.Get("X-RateLimit-Remaining")
		}
	}
	
	remaining, err := strconv.Atoi(remainingHeader)
	if err != nil {
		t.logger.Warn(fmt.Sprintf("%q response header is missing or invalid, skipping postRequestHook: %+v", X_RATE_LIMIT_REMAINING, err))
		return
	}

	t.rateLimitManager.Update(method, path, limit, remaining, reset)
}