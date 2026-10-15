// Command bot-defense is the HTTP server that ties the three modules
// together:
//
//	Module 1 (this file + middleware/, config/)  HTTP lifecycle & routing
//	Module 2 (challenge/)                         Per-request VM generation
//	Module 3 (validation/)                        Payload scoring & cookies
//
// Run with: `go run .` — reads .env in the working directory.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"bot-defense/challenge"
	"bot-defense/config"
	"bot-defense/middleware"
	"bot-defense/session"
	"bot-defense/validation"
)

func main() {
	cfg := config.Load()

	// ── Dependency wiring ────────────────────────────────────────────
	redisClient := session.NewRedisClient(cfg.RedisAddr)
	sessionStore := session.NewStore(redisClient)

	pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := sessionStore.Ping(pingCtx); err != nil {
		log.Fatalf("redis unreachable at %s: %v", cfg.RedisAddr, err)
	}
	cancel()

	mlClient := validation.NewMLClient(cfg.MLServiceURL)
	healthCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	if err := mlClient.Health(healthCtx); err != nil {
		// Non-fatal: while ML is unavailable, /challenge/verify fails
		// closed (HTTP 503, no clearance cookie).
		log.Printf("warn: ML service health check failed: %v", err)
	}
	cancel()

	generator := challenge.MustNewGenerator()
	validationHandler := validation.NewHandler(sessionStore, mlClient, cfg.CookieSecret, cfg.SecureCookie)
	log.Printf("env=%s secure_cookie=%t", cfg.Env, cfg.SecureCookie)

	// ── Router ───────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(5 * time.Second))

	// Challenge endpoints — public, no clearance required.
	r.Get("/challenge/js", challengeHandler(generator, sessionStore))
	r.Post("/challenge/verify", validationHandler.Verify)

	// Protected API — requires a valid bd_token.
	r.Group(func(pr chi.Router) {
		pr.Use(middleware.BotGuard(cfg.CookieSecret))
		pr.Get("/api/data", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"message":"you are human"}`))
		})
	})

	// ── Server + graceful shutdown ───────────────────────────────────
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("bot-defense listening on :%s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
	_ = redisClient.Close()
	log.Println("shutdown complete")
}

// challengeHandler returns an http.HandlerFunc that generates and
// serves a fresh challenge. Extracted here so main() stays small and
// testable.
func challengeHandler(g *challenge.Generator, store *session.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		payload, err := g.Generate()
		if err != nil {
			log.Printf("challenge generate: %v", err)
			http.Error(w, "generation failed", http.StatusInternalServerError)
			return
		}
		if err := store.Save(req.Context(), payload.SessionID, session.SessionData{
			IssuedAt:    payload.IssuedAt,
			TokenRecipe: payload.TokenRecipe,
		}); err != nil {
			log.Printf("session save: %v", err)
			http.Error(w, "session store failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(payload.VMScript))
	}
}
