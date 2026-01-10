package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/time/rate"
)

// Authentication middleware
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for public endpoints
		publicPaths := []string{
			"/api/v1/auth/login",
			"/api/v1/agent/register",
			"/api/v1/agent/beacon",
			"/api/v1/agent/task/result",
			"/health",
		}
		
		for _, path := range publicPaths {
			if r.URL.Path == path {
				next.ServeHTTP(w, r)
				return
			}
		}
		
		// Get token from header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.errorResponse(w, "Authorization header required", http.StatusUnauthorized)
			return
		}
		
		// Check Bearer token format
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			s.errorResponse(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}
		
		tokenString := parts[1]
		
		// Parse and validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(s.config.JWTSecret), nil
		})
		
		if err != nil || !token.Valid {
			s.errorResponse(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			s.errorResponse(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}
		
		// Check expiration
		if exp, ok := claims["exp"].(float64); ok {
			if int64(exp) < time.Now().Unix() {
				s.errorResponse(w, "Token expired", http.StatusUnauthorized)
				return
			}
		}
		
		// Get user ID from claims
		userID, ok := claims["user_id"].(float64)
		if !ok {
			s.errorResponse(w, "Invalid user ID in token", http.StatusUnauthorized)
			return
		}
		
		// Check if user exists and is active
		var user User
		result := s.db.First(&user, uint(userID))
		if result.Error != nil || !user.IsActive {
			s.errorResponse(w, "User not found or inactive", http.StatusUnauthorized)
			return
		}
		
		// Add user info to context
		ctx := context.WithValue(r.Context(), "user_id", uint(userID))
		ctx = context.WithValue(ctx, "username", user.Username)
		ctx = context.WithValue(ctx, "user_role", user.Role)
		
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Rate limiting middleware
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	// Create rate limiter: 100 requests per minute per IP
	limiters := make(map[string]*rate.Limiter)
	var mu sync.RWMutex
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP
		ip := getIPAddress(r)
		
		// Get or create limiter for this IP
		mu.RLock()
		limiter, exists := limiters[ip]
		mu.RUnlock()
		
		if !exists {
			mu.Lock()
			limiter = rate.NewLimiter(rate.Every(time.Minute), 100)
			limiters[ip] = limiter
			mu.Unlock()
		}
		
		// Check if request is allowed
		if !limiter.Allow() {
			s.errorResponse(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// CORS middleware
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		origin := r.Header.Get("Origin")
		
		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range s.config.AllowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}
		
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "3600")
		}
		
		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// Logging middleware
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create response writer wrapper to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		// Process request
		next.ServeHTTP(rw, r)
		
		// Log request details
		duration := time.Since(start)
		
		s.logger.WithFields(logrus.Fields{
			"method":     r.Method,
			"path":       r.URL.Path,
			"status":     rw.statusCode,
			"duration":   duration.String(),
			"ip":         getIPAddress(r),
			"user_agent": r.UserAgent(),
		}).Info("HTTP request")
	})
}

// Response writer wrapper to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// API key middleware (for agent authentication)
func (s *Server) apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for API key in query parameter or header
		apiKey := r.URL.Query().Get("api_key")
		if apiKey == "" {
			apiKey = r.Header.Get("X-API-Key")
		}
		
		if apiKey == "" {
			s.errorResponse(w, "API key required", http.StatusUnauthorized)
			return
		}
		
		// Validate API key
		if apiKey != s.config.APIKey {
			s.errorResponse(w, "Invalid API key", http.StatusUnauthorized)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// Admin-only middleware
func (s *Server) adminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user role from context
		role, ok := r.Context().Value("user_role").(string)
		if !ok || role != "admin" {
			s.errorResponse(w, "Admin access required", http.StatusForbidden)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// Request validation middleware
func (s *Server) validateContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip for GET requests and file uploads
		if r.Method == "GET" || strings.Contains(r.URL.Path, "/upload") {
			next.ServeHTTP(w, r)
			return
		}
		
		// Check Content-Type for POST/PUT requests
		contentType := r.Header.Get("Content-Type")
		if !strings.Contains(contentType, "application/json") && 
		   !strings.Contains(contentType, "multipart/form-data") {
			s.errorResponse(w, "Content-Type must be application/json or multipart/form-data", http.StatusUnsupportedMediaType)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}
