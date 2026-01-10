package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// GetIPAddress returns the client IP address
func GetIPAddress(r *http.Request) string {
	// Check for X-Forwarded-For header (proxy)
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	
	// Check for X-Real-IP header
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	
	// Fallback to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// JSONResponse sends a JSON response
func JSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// ErrorResponse sends an error JSON response
func ErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	JSONResponse(w, map[string]string{
		"error": message,
	}, statusCode)
}

// ParseJSON parses JSON request body
func ParseJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// ValidateRequiredFields checks for required fields in a map
func ValidateRequiredFields(data map[string]interface{}, required []string) error {
	for _, field := range required {
		if val, ok := data[field]; !ok || val == nil || val == "" {
			return fmt.Errorf("missing required field: %s", field)
		}
	}
	return nil
}

// CreateDirectory creates a directory if it doesn't exist
func CreateDirectory(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	}
	return nil
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// GetFileSize returns file size in bytes
func GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// CopyFile copies a file from src to dst
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// GetSystemInfo returns basic system information
func GetSystemInfo() map[string]interface{} {
	return map[string]interface{}{
		"go_version":   runtime.Version(),
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
		"num_cpu":      runtime.NumCPU(),
		"hostname":     getHostname(),
		"current_time": time.Now().Format(time.RFC3339),
	}
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// SanitizeFilename removes dangerous characters from filename
func SanitizeFilename(filename string) string {
	// Remove directory traversal attempts
	filename = filepath.Base(filename)
	
	// Remove dangerous characters
	dangerous := []string{"..", "/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range dangerous {
		filename = strings.ReplaceAll(filename, char, "_")
	}
	
	return filename
}

// GenerateTimestamp returns current timestamp in various formats
func GenerateTimestamp() map[string]string {
	now := time.Now()
	return map[string]string{
		"unix":      fmt.Sprintf("%d", now.Unix()),
		"unix_nano": fmt.Sprintf("%d", now.UnixNano()),
		"rfc3339":   now.Format(time.RFC3339),
		"iso8601":   now.Format(time.RFC3339),
		"human":     now.Format("2006-01-02 15:04:05"),
	}
}

// ParseDuration parses duration string with support for human format
func ParseDuration(durationStr string) (time.Duration, error) {
	// Add support for human readable durations
	mappings := map[string]string{
		"1m":  "1m",
		"5m":  "5m",
		"10m": "10m",
		"30m": "30m",
		"1h":  "1h",
		"6h":  "6h",
		"12h": "12h",
		"1d":  "24h",
		"7d":  "168h",
	}
	
	if mapped, ok := mappings[durationStr]; ok {
		durationStr = mapped
	}
	
	return time.ParseDuration(durationStr)
}

// SetLogLevel sets the logrus log level
func SetLogLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "warn", "warning":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "fatal":
		logrus.SetLevel(logrus.FatalLevel)
	case "panic":
		logrus.SetLevel(logrus.PanicLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}
}

// Retry executes a function with retry logic
func Retry(attempts int, sleep time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		
		if i < attempts-1 {
			time.Sleep(sleep)
			sleep *= 2 // Exponential backoff
		}
	}
	return fmt.Errorf("failed after %d attempts: %w", attempts, err)
}

// GenerateUniqueID generates a unique ID
func GenerateUniqueID(prefix string) string {
	return fmt.Sprintf("%s-%d-%x", prefix, time.Now().UnixNano(), rand.Int63())
}

// MaskSecret masks a secret for logging
func MaskSecret(secret string) string {
	if len(secret) <= 4 {
		return "****"
	}
	return secret[:2] + "****" + secret[len(secret)-2:]
}
