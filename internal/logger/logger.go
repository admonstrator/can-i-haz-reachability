package logger

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"

	"github.com/glinet/reflector/internal/util"
	"gopkg.in/natefinch/lumberjack.v2"
)

type AccessLogEntry struct {
	Timestamp  string          `json:"ts"`
	IP         string          `json:"ip"`
	Method     string          `json:"method"`
	Path       string          `json:"path"`
	Ports      []int           `json:"ports,omitempty"`
	Results    map[string]bool `json:"results,omitempty"`
	DurationMs int64           `json:"duration_ms"`
	Status     int             `json:"status"`
	Error      string          `json:"error,omitempty"`
}

type Logger struct {
	accessLog io.WriteCloser
	errorLog  io.WriteCloser
	mu        sync.Mutex
}

func NewLogger(logDir string) (*Logger, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, err
	}

	accessLog := &lumberjack.Logger{
		Filename:   logDir + "/access.log",
		MaxSize:    100,
		MaxBackups: 7,
		MaxAge:     30,
		Compress:   true,
	}

	errorLog := &lumberjack.Logger{
		Filename:   logDir + "/error.log",
		MaxSize:    100,
		MaxBackups: 7,
		MaxAge:     30,
		Compress:   true,
	}

	return &Logger{
		accessLog: accessLog,
		errorLog:  errorLog,
	}, nil
}

// FallbackLogger writes to stdout/stderr
func FallbackLogger() *Logger {
	return &Logger{
		accessLog: os.Stdout,
		errorLog:  os.Stderr,
	}
}

func (l *Logger) LogAccess(entry AccessLogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry.IP = util.AnonymizeIP(entry.IP)
	json.NewEncoder(l.accessLog).Encode(entry)
}

func (l *Logger) LogError(level, msg string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := map[string]interface{}{
		"ts":    time.Now().UTC().Format(time.RFC3339),
		"level": level,
		"msg":   msg,
	}
	for k, v := range fields {
		entry[k] = v
	}
	json.NewEncoder(l.errorLog).Encode(entry)
}

func (l *Logger) Close() {
	if l.accessLog != os.Stdout {
		l.accessLog.Close()
	}
	if l.errorLog != os.Stderr {
		l.errorLog.Close()
	}
}
