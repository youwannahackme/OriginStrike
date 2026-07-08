package cors

import (
	"net/http"
	"strings"
)

// Config holds the configuration for the CORS middleware
type Config struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	ExposeHeaders  []string
	MaxAge         int
}

// Handler wraps an http.Handler with secure CORS logic
type Handler struct {
	next           http.Handler
	allowedOrigins map[string]bool
	allowedMethods string
	allowedHeaders string
	exposeHeaders  string
	maxAge         string
}

// NewHandler creates a secure CORS middleware handler
func NewHandler(next http.Handler, cfg Config) *Handler {
	originsMap := make(map[string]bool)
	for _, origin := range cfg.AllowedOrigins {
		trimmed := strings.TrimSuffix(strings.TrimSpace(origin), "/")
		if trimmed != "" && trimmed != "*" {
			originsMap[trimmed] = true
		}
	}

	methods := strings.Join(cfg.AllowedMethods, ", ")
	if methods == "" {
		methods = "GET, POST, OPTIONS"
	}

	headers := strings.Join(cfg.AllowedHeaders, ", ")
	if headers == "" {
		headers = "Content-Type, Authorization"
	}

	return &Handler{
		next:           next,
		allowedOrigins: originsMap,
		allowedMethods: methods,
		allowedHeaders: headers,
		exposeHeaders:  strings.Join(cfg.ExposeHeaders, ", "),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	origin = strings.TrimSuffix(strings.TrimSpace(origin), "/")

	if h.allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		
		if h.exposeHeaders != "" {
			w.Header().Set("Access-Control-Expose-Headers", h.exposeHeaders)
		}
	}

	if r.Method == http.MethodOptions {
		if h.allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Methods", h.allowedMethods)
			w.Header().Set("Access-Control-Allow-Headers", h.allowedHeaders)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	h.next.ServeHTTP(w, r)
}
