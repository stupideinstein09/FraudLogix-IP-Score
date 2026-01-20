// Fraudlogix API Security Implementation - Go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
	APIKey          string
	BlockedPage     string
	CaptchaPage     string
	BannedCountries []string
	Scenarios       ScenarioConfig
}

type ScenarioConfig struct {
	BlockHighExtreme bool
	QuarantineMedium bool
	StrictMode       bool
	BlockProxies     bool
	BlockAnonymizers bool
	GeoBlocking      bool
}

type RiskData struct {
	IP              string `json:"IP"`
	RiskScore       string `json:"RiskScore"`
	CountryCode     string `json:"CountryCode"`
	Proxy           bool   `json:"Proxy"`
	VPN             bool   `json:"VPN"`
	TOR             bool   `json:"TOR"`
	SearchEngineBot bool   `json:"SearchEngineBot"`
}

var config = Config{
	APIKey:      getenv("FRAUDLOGIX_API_KEY", "YOUR_API_KEY_HERE"),
	BlockedPage: getenv("BLOCKED_PAGE", "https://yourdomain.com/blocked"),
	CaptchaPage: getenv("CAPTCHA_PAGE", "https://yourdomain.com/verify"),
	BannedCountries: func() []string {
		bc := getenv("BANNED_COUNTRIES", "CN,RU")
		return strings.Split(bc, ",")
	}(),
	Scenarios: ScenarioConfig{BlockHighExtreme: true, QuarantineMedium: false, StrictMode: false, BlockProxies: true, BlockAnonymizers: false, GeoBlocking: true},
}

func getenv(key, def string) string {
	v := os.Getenv(key)
	if v == "" { return def }
	return v
}

func FraudlogixSecurity(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		visitorIP := clientIP(r)
		riskData, err := checkIPRisk(visitorIP)
		if err != nil || riskData == nil {
			next(w, r)
			return
		}

		if config.Scenarios.BlockHighExtreme && (riskData.RiskScore == "High" || riskData.RiskScore == "Extreme") {
			http.Redirect(w, r, config.BlockedPage, http.StatusFound); return
		}
		if config.Scenarios.QuarantineMedium && riskData.RiskScore == "Medium" {
			http.Redirect(w, r, config.CaptchaPage, http.StatusFound); return
		}
		if config.Scenarios.StrictMode && riskData.RiskScore != "Low" && !riskData.SearchEngineBot {
			http.Redirect(w, r, config.BlockedPage, http.StatusFound); return
		}
		if config.Scenarios.BlockProxies && (riskData.Proxy || riskData.VPN || riskData.TOR) && !riskData.SearchEngineBot {
			http.Redirect(w, r, config.BlockedPage, http.StatusFound); return
		}
		if config.Scenarios.BlockAnonymizers && (riskData.RiskScore == "Extreme" || riskData.Proxy || riskData.VPN || riskData.TOR) {
			http.Redirect(w, r, config.BlockedPage, http.StatusFound); return
		}
		if config.Scenarios.GeoBlocking && contains(config.BannedCountries, riskData.CountryCode) {
			http.Redirect(w, r, config.BlockedPage, http.StatusFound); return
		}

		next(w, r)
	}
}

func checkIPRisk(ip string) (*RiskData, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://iplist.fraudlogix.com/v5?ip=%s", ip), nil)
	if err != nil { return nil, err }
	req.Header.Set("x-api-key", config.APIKey)
	resp, err := client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return nil, fmt.Errorf("status: %d", resp.StatusCode) }
	var risk RiskData
	if err := json.NewDecoder(resp.Body).Decode(&risk); err != nil { return nil, err }
	return &risk, nil
}

func clientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" { return strings.Split(xff, ",")[0] }
	return strings.Split(r.RemoteAddr, ":")[0]
}

func contains(list []string, item string) bool {
	for _, v := range list { if v == item { return true } }
	return false
}

func homeHandler(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "Welcome! You have passed our security checks.") }

func main() {
	http.HandleFunc("/", FraudlogixSecurity(homeHandler))
	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
