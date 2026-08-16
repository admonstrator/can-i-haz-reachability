package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/glinet/reflector/internal/api"
	"github.com/glinet/reflector/internal/config"
	"github.com/glinet/reflector/internal/limiter"
	"github.com/glinet/reflector/internal/logger"
)

// securityHeaders adds conservative hardening headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// recoverMiddleware turns a handler panic into a logged 500 instead of a dropped
// connection, and gives the otherwise-unused error log a purpose.
func recoverMiddleware(l *logger.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				l.LogError("error", "panic recovered", map[string]interface{}{
					"path": r.URL.Path,
					"err":  fmt.Sprintf("%v", rec),
				})
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `{"success":false,"error":"internal_error"}`)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func main() {
	cfg := config.LoadConfig()

	appLogger, err := logger.NewLogger(cfg.LogDir)
	if err != nil {
		log.Printf("Warning: Could not initialize file logger: %v", err)
		appLogger = logger.FallbackLogger()
	}
	defer appLogger.Close()

	rateLimiter := limiter.NewIPRateLimiter(cfg.RateLimitPerMin)

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			rateLimiter.Cleanup()
		}
	}()

	handlers := api.NewHandlers(cfg, rateLimiter, appLogger)

	mux := http.NewServeMux()
	mux.HandleFunc("/check", handlers.HandleCheck)
	mux.HandleFunc("/simple", handlers.HandleSimple)
	mux.HandleFunc("/health", handlers.HandleHealth)
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	handler := securityHeaders(recoverMiddleware(appLogger, mux))

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	idleClosed := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down gracefully...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
		}
		close(idleClosed)
	}()

	log.Printf("Reflector server starting on port %s", cfg.Port)
	log.Printf("Allowed ports: %v", cfg.AllowedPorts)
	log.Printf("Rate limit: %d requests/min per IP", cfg.RateLimitPerMin)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}

	// Wait for Shutdown to finish draining before exiting, so the shutdown is
	// actually graceful.
	<-idleClosed
	log.Println("Server stopped")
}
