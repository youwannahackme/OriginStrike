package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func main() {
	mux := http.NewServeMux()

	// 1. Wildcard CORS misconfiguration
	mux.HandleFunc("/wildcard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"vulnerable","type":"wildcard"}`))
	})

	// 2. Arbitrary Origin Reflection
	mux.HandleFunc("/reflect", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"vulnerable","type":"reflection","reflected": "` + origin + `"}`))
	})

	// 3. Credentials Exposure (Critical)
	mux.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "https://evil.com")
		}
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"vulnerable","type":"credentials","secret":"ADMIN_API_KEY_998877"}`))
	})

	// 4. Null Origin Allowance
	mux.HandleFunc("/null-origin", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "null" || strings.Contains(origin, "null") {
			w.Header().Set("Access-Control-Allow-Origin", "null")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"vulnerable","type":"null_origin"}`))
	})

	// 5. Prefix/Suffix Bypass (allows any domain containing "target.com")
	mux.HandleFunc("/prefix-bypass", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if strings.Contains(origin, "target.com") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"vulnerable","type":"prefix_bypass"}`))
	})

	port := "8888"
	fmt.Printf("[+] Vulnerable CORS Test Server running on http://127.0.0.1:%s\n", port)
	if err := http.ListenAndServe("127.0.0.1:"+port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
