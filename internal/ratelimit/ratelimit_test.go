package ratelimit

import (
	"testing"
	"time"
)

func TestNewRateLimitManager(t *testing.T) {
	manager, err := NewRateLimitManager(80)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	
	if manager.capacity != 80 {
		t.Errorf("Expected capacity 80, got %d", manager.capacity)
	}
	
	// Check that default status exists
	if _, ok := manager.status["/"]; !ok {
		t.Error("Expected default status to exist")
	}
}

func TestHasCapacity(t *testing.T) {
	manager, _ := NewRateLimitManager(50)
	
	// Test with no previous data (should return true)
	if !manager.HasCapacity("GET", "/api/v2/users") {
		t.Error("Expected HasCapacity to return true for unused endpoint")
	}
	
	// Test with capacity exceeded (40 remaining out of 100 = 60% utilization, over 50% capacity)
	manager.Update("GET", "/api/v2/users", 100, 40, time.Now().Unix()+60)
	if manager.HasCapacity("GET", "/api/v2/users") {
		t.Error("Expected HasCapacity to return false when over 50% utilization")
	}
	
	// Test with capacity available (60 remaining out of 100 = 40% utilization, under 50% threshold)
	// Create new endpoint to avoid interference from previous update
	manager.Update("GET", "/api/v2/clients", 100, 60, time.Now().Unix()+60)
	if !manager.HasCapacity("GET", "/api/v2/clients") {
		t.Error("Expected HasCapacity to return true when under 50% utilization")
	}
}

func TestUpdate(t *testing.T) {
	manager, _ := NewRateLimitManager(80)
	
	// Test initial update
	reset := time.Now().Unix() + 60
	manager.Update("GET", "/api/v2/users", 100, 80, reset)
	
	status := manager.Status("GET", "/api/v2/users")
	if status.Limit() != 100 {
		t.Errorf("Expected limit 100, got %d", status.Limit())
	}
	if status.Remaining() != 80 {
		t.Errorf("Expected remaining 80, got %d", status.Remaining())
	}
	if status.Reset() != reset {
		t.Errorf("Expected reset %d, got %d", reset, status.Reset())
	}
	
	// Test update with newer reset time (should update all values)
	newReset := reset + 60
	manager.Update("GET", "/api/v2/users", 120, 90, newReset)
	
	status = manager.Status("GET", "/api/v2/users")
	if status.Limit() != 120 {
		t.Errorf("Expected limit 120, got %d", status.Limit())
	}
	if status.Remaining() != 90 {
		t.Errorf("Expected remaining 90, got %d", status.Remaining())
	}
	
	// Test update with same reset time but lower remaining (should update remaining)
	manager.Update("GET", "/api/v2/users", 120, 70, newReset)
	
	status = manager.Status("GET", "/api/v2/users")
	if status.Remaining() != 70 {
		t.Errorf("Expected remaining 70, got %d", status.Remaining())
	}
}

func TestClassAndBucket(t *testing.T) {
	manager, _ := NewRateLimitManager(80)
	
	// Test ID replacement
	class := manager.Class("GET", "/api/v2/users/auth0|507f1f77bcf86cd799439011")
	expected := "GET /api/v2/users/ID"
	if class != expected {
		t.Errorf("Expected class %q, got %q", expected, class)
	}
	
	// Test bucket mapping
	bucket := manager.Bucket("GET", "/api/v2/users")
	expected = "/api/v2/users"
	if bucket != expected {
		t.Errorf("Expected bucket %q, got %q", expected, bucket)
	}
	
	// Test default bucket for unmapped endpoint
	bucket = manager.Bucket("GET", "/api/v2/unknown")
	expected = "/"
	if bucket != expected {
		t.Errorf("Expected default bucket %q, got %q", expected, bucket)
	}
}

func TestNormalizedKey(t *testing.T) {
	manager, _ := NewRateLimitManager(80)
	
	key := manager.normalizedKey("GET", "/api/v2/users")
	expected := "GET /api/v2/users"
	if key != expected {
		t.Errorf("Expected key %q, got %q", expected, key)
	}
}

func TestUpdateWithOldReset(t *testing.T) {
	manager, _ := NewRateLimitManager(80)
	
	// Set initial state with current time
	currentTime := time.Now().Unix()
	manager.Update("GET", "/api/v2/users", 100, 80, currentTime)
	
	// Try to update with old reset time (should be ignored)
	oldResetTime := currentTime - 120 // 2 minutes ago
	manager.Update("GET", "/api/v2/users", 120, 70, oldResetTime)
	
	// Status should remain unchanged
	status := manager.Status("GET", "/api/v2/users")
	if status.Limit() != 100 {
		t.Errorf("Expected limit to remain 100, got %d", status.Limit())
	}
	if status.Remaining() != 80 {
		t.Errorf("Expected remaining to remain 80, got %d", status.Remaining())
	}
}

func TestGetWithUnmappedEndpoint(t *testing.T) {
	manager, _ := NewRateLimitManager(80)
	
	// Test with completely unmapped endpoint
	status := manager.get("POST", "/unknown/endpoint")
	
	// Should return the default root status
	if status != manager.status["/"] {
		t.Error("Expected unmapped endpoint to return root status")
	}
}

func TestInitRateLimitMappingWithInvalidLine(t *testing.T) {
	manager := &RateLimitManager{
		capacity: 50,
		status: map[string]*RateLimitStatus{
			"/": &RateLimitStatus{},
		},
		buckets: map[string]string{},
	}
	
	// This should test the continue case in initRateLimitMapping
	// We can't easily test this without modifying the rateLimitLines,
	// but we can test that the function handles empty bucket creation
	manager.initRateLimitMapping()
	
	// Verify that some standard buckets were created
	if _, ok := manager.status["/api/v2/users"]; !ok {
		t.Error("Expected /api/v2/users bucket to be created")
	}
}

func TestAuth0IDRegex(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"/api/v2/users/auth0|507f1f77bcf86cd799439011", "/api/v2/users/ID"},
		{"/api/v2/clients/YmF12345678901234567890", "/api/v2/clients/ID"},
		{"/api/v2/roles/rol_12345678901234567890", "/api/v2/roles/ID"},
		{"/api/v2/organizations/org_12345678901234567890/members", "/api/v2/organizations/ID/members"},
		{"/api/v2/connections/con_12345678901234567890", "/api/v2/connections/ID"},
		{"/api/v2/users", "/api/v2/users"}, // No ID to replace
	}
	
	for _, tc := range testCases {
		result := reAuth0ID.ReplaceAllString(tc.input, "ID")
		if result != tc.expected {
			t.Errorf("For input %q, expected %q, got %q", tc.input, tc.expected, result)
		}
	}
}