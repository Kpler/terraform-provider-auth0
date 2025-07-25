package ratelimit

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RateLimitManager synchronizes keeping account of current known rate limit values
// from Auth0 management endpoints. See:
// https://auth0.com/docs/troubleshoot/product-lifecycle/rate-limit-policy
//
// The Auth0 Terraform Provider can not account for other clients consumption of
// API limits but it can account for its own usage and attempt to preemptively
// react appropriately.
type RateLimitManager struct {
	lock     sync.Mutex
	capacity int
	status   map[string]*RateLimitStatus
	buckets  map[string]string
}

// RateLimitStatus is used to hold rate limit information from Auth0's API
type RateLimitStatus struct {
	limit     int
	remaining int
	reset     int64 // UTC epoch time in seconds
}

// NewRateLimitManager returns a new rate limit manager object that represents untilized
// capacity under the specified capacity percentage.
func NewRateLimitManager(capacity int) (*RateLimitManager, error) {
	rootStatus := &RateLimitStatus{}
	manager := &RateLimitManager{
		capacity: capacity,
		status: map[string]*RateLimitStatus{
			"/": rootStatus,
		},
		buckets: map[string]string{},
	}
	manager.initRateLimitMapping()

	return manager, nil
}

// HasCapacity approximates if there is capacity below the rate limit manager's maximum
// capacity threshold.
func (m *RateLimitManager) HasCapacity(method, endpoint string) bool {
	status := m.get(method, endpoint)

	// if the status hasn't been updated recently assume there is capacity
	if status.reset+60 < time.Now().Unix() {
		return true
	}

	// calculate utilization
	utilization := 100.0 * (float32(status.limit-status.remaining) / float32(status.limit))

	return utilization <= float32(m.capacity)
}

// Update updates the known status for the given API endpoint. It is synchronous
// and intelligently accounts for new values regardless of parallelism.
func (m *RateLimitManager) Update(method, endpoint string, limit, remaining int, reset int64) {
	m.lock.Lock()
	defer m.lock.Unlock()

	status := m.get(method, endpoint)
	if reset > status.reset {
		// reset value greater than current reset implies we are in a new Auth0 API
		// window. set/reset values.
		status.reset = reset
		status.remaining = remaining
		status.limit = limit
		return
	}

	if reset <= (status.reset - 60) {
		// these values are from the previous window, ignore
		return
	}

	if remaining < status.remaining {
		status.remaining = remaining
	}
}

// Status Returns the RateLimitStatus for the given method + endpoint combination.
func (m *RateLimitManager) Status(method, endpoint string) *RateLimitStatus {
	return m.get(method, endpoint)
}

// Class Returns the api endpoint class.
func (m *RateLimitManager) Class(method, endpoint string) string {
	path := reAuth0ID.ReplaceAllString(endpoint, "ID")
	return m.normalizedKey(method, path)
}

// Bucket Returns the rate limit bucket the api endpoint falls into.
func (m *RateLimitManager) Bucket(method, endpoint string) string {
	path := reAuth0ID.ReplaceAllString(endpoint, "ID")
	key := m.normalizedKey(method, path)
	bucket, ok := m.buckets[key]
	if !ok {
		return "/"
	}
	return bucket
}

func (m *RateLimitManager) normalizedKey(method, endpoint string) string {
	return fmt.Sprintf("%s %s", method, endpoint)
}

// Reset returns the current reset value of the rate limit status object.
func (s *RateLimitStatus) Reset() int64 {
	return s.reset
}

// Limit returns the current limit value of the rate limit status object.
func (s *RateLimitStatus) Limit() int {
	return s.limit
}

// Remaining returns the current remaining value of the rate limit status object.
func (s *RateLimitStatus) Remaining() int {
	return s.remaining
}

// Regex to match Auth0 IDs - includes various formats:
// - auth0|507f1f77bcf86cd799439011 (social connections)
// - YmF12345678901234567890 (client IDs)
// - rol_12345678901234567890 (role IDs)
// - org_12345678901234567890 (organization IDs)
// - con_12345678901234567890 (connection IDs)
var reAuth0ID = regexp.MustCompile(`(?:auth0\|[a-zA-Z0-9]+|[a-zA-Z]{3}_[a-zA-Z0-9]{20,}|[a-zA-Z0-9]{20,})`)

func (m *RateLimitManager) get(method, endpoint string) *RateLimitStatus {
	// The important point here is the replace all is performing this
	// transformation for the bucket lookup /api/v2/users/auth0|507f1f77bcf86cd799439011
	// to /api/v2/users/ID .
	path := reAuth0ID.ReplaceAllString(endpoint, "ID")
	key := m.normalizedKey(method, path)
	bucket, ok := m.buckets[key]
	if !ok {
		return m.status["/"]
	}
	return m.status[bucket]
}

func (m *RateLimitManager) initRateLimitMapping() {
	// Auth0 Management API endpoints and their rate limit buckets
	// Based on https://auth0.com/docs/troubleshoot/product-lifecycle/rate-limit-policy
	rateLimitLines := []string{
		// Users endpoints - these are often the most rate-limited
		"/api/v2/users GET /api/v2/users",
		"/api/v2/users POST /api/v2/users",
		"/api/v2/users/ID GET /api/v2/users/{id}",
		"/api/v2/users/ID PATCH /api/v2/users/{id}",
		"/api/v2/users/ID DELETE /api/v2/users/{id}",
		"/api/v2/users/ID/roles GET /api/v2/users",
		"/api/v2/users/ID/roles POST /api/v2/users",
		"/api/v2/users/ID/roles DELETE /api/v2/users",
		"/api/v2/users/ID/permissions GET /api/v2/users",
		"/api/v2/users/ID/permissions POST /api/v2/users",
		"/api/v2/users/ID/permissions DELETE /api/v2/users",
		
		// Clients/Applications
		"/api/v2/clients GET /api/v2/clients",
		"/api/v2/clients POST /api/v2/clients",
		"/api/v2/clients/ID GET /api/v2/clients/{id}",
		"/api/v2/clients/ID PATCH /api/v2/clients/{id}",
		"/api/v2/clients/ID DELETE /api/v2/clients/{id}",
		"/api/v2/clients/ID/credentials GET /api/v2/clients",
		"/api/v2/clients/ID/credentials POST /api/v2/clients",
		"/api/v2/clients/ID/credentials DELETE /api/v2/clients",
		
		// Connections
		"/api/v2/connections GET /api/v2/connections",
		"/api/v2/connections POST /api/v2/connections",
		"/api/v2/connections/ID GET /api/v2/connections/{id}",
		"/api/v2/connections/ID PATCH /api/v2/connections/{id}",
		"/api/v2/connections/ID DELETE /api/v2/connections/{id}",
		
		// Organizations
		"/api/v2/organizations GET /api/v2/organizations",
		"/api/v2/organizations POST /api/v2/organizations",
		"/api/v2/organizations/ID GET /api/v2/organizations/{id}",
		"/api/v2/organizations/ID PATCH /api/v2/organizations/{id}",
		"/api/v2/organizations/ID DELETE /api/v2/organizations/{id}",
		"/api/v2/organizations/ID/members GET /api/v2/organizations",
		"/api/v2/organizations/ID/members POST /api/v2/organizations",
		"/api/v2/organizations/ID/members DELETE /api/v2/organizations",
		
		// Roles
		"/api/v2/roles GET /api/v2/roles",
		"/api/v2/roles POST /api/v2/roles",
		"/api/v2/roles/ID GET /api/v2/roles/{id}",
		"/api/v2/roles/ID PATCH /api/v2/roles/{id}",
		"/api/v2/roles/ID DELETE /api/v2/roles/{id}",
		"/api/v2/roles/ID/permissions GET /api/v2/roles",
		"/api/v2/roles/ID/permissions POST /api/v2/roles",
		"/api/v2/roles/ID/permissions DELETE /api/v2/roles",
		
		// Resource Servers
		"/api/v2/resource-servers GET /api/v2/resource-servers",
		"/api/v2/resource-servers POST /api/v2/resource-servers",
		"/api/v2/resource-servers/ID GET /api/v2/resource-servers/{id}",
		"/api/v2/resource-servers/ID PATCH /api/v2/resource-servers/{id}",
		"/api/v2/resource-servers/ID DELETE /api/v2/resource-servers/{id}",
		
		// Actions
		"/api/v2/actions/actions GET /api/v2/actions",
		"/api/v2/actions/actions POST /api/v2/actions",
		"/api/v2/actions/actions/ID GET /api/v2/actions/{id}",
		"/api/v2/actions/actions/ID PATCH /api/v2/actions/{id}",
		"/api/v2/actions/actions/ID DELETE /api/v2/actions/{id}",
		
		// Tenant settings - lower rate limits typically
		"/api/v2/tenants/settings GET /api/v2/tenants",
		"/api/v2/tenants/settings PATCH /api/v2/tenants",
		
		// Default bucket for any unmatched endpoints
		"/ GET /",
		"/ POST /",
		"/ PATCH /",
		"/ DELETE /",
		"/ PUT /",
	}

	for _, line := range rateLimitLines {
		vals := strings.Fields(line)
		if len(vals) < 3 {
			continue
		}
		path := vals[0]
		method := vals[1]
		bucket := vals[2]

		key := m.normalizedKey(method, path)
		m.buckets[key] = bucket

		if _, ok := m.status[bucket]; !ok {
			m.status[bucket] = &RateLimitStatus{}
		}
	}
}