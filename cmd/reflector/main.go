package main

import (
	"context"
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

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down gracefully...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		server.Shutdown(ctx)
	}()

	log.Printf("Reflector server starting on port %s", cfg.Port)
	log.Printf("Allowed ports: %v", cfg.AllowedPorts)
	log.Printf("Rate limit: %d requests/min per IP", cfg.RateLimitPerMin)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}

	log.Println("Server stopped")
}
