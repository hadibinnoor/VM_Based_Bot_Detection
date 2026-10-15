// Package config loads runtime configuration from environment variables.
//
// The .env file is loaded at process start (if present) but environment
// variables always win. Required values:
//
//	COOKIE_SECRET   at least 32 raw characters; used for HMAC-SHA256
//
// Optional values (with sensible defaults for local development):
//
//	PORT            default "8080"
//	REDIS_ADDR      default "localhost:6379"
//	ML_SERVICE_URL  default "http://127.0.0.1:5001"
//	GO_ENV          "production" (default) or "development"
package config

import (
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all runtime configuration.
type Config struct {
	Port         string
	RedisAddr    string
	MLServiceURL string
	CookieSecret []byte

	// SecureCookie controls the Secure flag on the clearance cookie.
	// Derived from GO_ENV: true unless GO_ENV=development. Browsers
	// silently drop Secure cookies over plain HTTP, so this must be
	// false when serving over plain HTTP during local development.
	SecureCookie bool

	// Env is the raw GO_ENV value, preserved for logging.
	Env string
}

// Load reads environment variables and returns a populated Config.
// It calls log.Fatal if a required variable is missing or too short.
func Load() *Config {
	// .env is optional; in production the vars are injected by the orchestrator.
	_ = godotenv.Load()

	secret := os.Getenv("COOKIE_SECRET")
	if len(secret) < 32 {
		log.Fatal("COOKIE_SECRET must be at least 32 characters")
	}

	env := strings.ToLower(getEnvOrDefault("GO_ENV", "production"))
	secureCookie := env != "development" && env != "dev"

	return &Config{
		Port:         getEnvOrDefault("PORT", "8080"),
		RedisAddr:    getEnvOrDefault("REDIS_ADDR", "localhost:6379"),
		MLServiceURL: getEnvOrDefault("ML_SERVICE_URL", "http://127.0.0.1:5001"),
		CookieSecret: []byte(secret),
		SecureCookie: secureCookie,
		Env:          env,
	}
}

func getEnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
