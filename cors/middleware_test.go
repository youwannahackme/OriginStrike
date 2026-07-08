package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecureCORS(t *testing.T) {
	mockNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	cfg := Config{
		AllowedOrigins: []string{"https://trusted.com", "https://sub.trusted.com"},
		AllowedMethods: []string{"GET", "POST"},
	}
	handler := NewHandler(mockNext, cfg)

	tests := []struct {
		name           string
		origin         string
		method         string
		expectedAllow  bool
		expectedOrigin string
	}{
		{
			name:           "Valid Trusted Origin",
			origin:         "https://trusted.com",
			method:         "GET",
			expectedAllow:  true,
			expectedOrigin: "https://trusted.com",
		},
		{
			name:          "Untrusted Origin (Blocked)",
			origin:        "https://evil.com",
			method:        "GET",
			expectedAllow: false,
		},
		{
			name:          "Null Origin Bypass (Blocked)",
			origin:        "null",
			method:        "GET",
			expectedAllow: false,
		},
		{
			name:          "Suffix Bypass Attempt (Blocked)",
			origin:        "https://trusted.com.evil.com",
			method:        "GET",
			expectedAllow: false,
		},
		{
			name:          "Prefix Bypass Attempt (Blocked)",
			origin:        "https://eviltrusted.com",
			method:        "GET",
			expectedAllow: false,
		},
		{
			name:          "Null Byte Bypass Attempt (Blocked)",
			origin:        "https://trusted.com\x00.evil.com",
			method:        "GET",
			expectedAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", nil)
			req.Header.Set("Origin", tt.origin)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			allowOrigin := rec.Header().Get("Access-Control-Allow-Origin")
			allowCreds := rec.Header().Get("Access-Control-Allow-Credentials")

			if tt.expectedAllow {
				if allowOrigin != tt.expectedOrigin {
					t.Errorf("expected Allow-Origin %q, got %q", tt.expectedOrigin, allowOrigin)
				}
				if allowCreds != "true" {
					t.Errorf("expected Allow-Credentials 'true', got %q", allowCreds)
				}
			} else {
				if allowOrigin != "" {
					t.Errorf("expected no Allow-Origin header, got %q", allowOrigin)
				}
				if allowCreds != "" {
					t.Errorf("expected no Allow-Credentials header, got %q", allowCreds)
				}
			}
		})
	}
}
