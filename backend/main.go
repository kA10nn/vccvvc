package main

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

//go:embed frontend/build/*
var frontendFS embed.FS

type Config struct {
	Server struct {
		Host           string `yaml:"host"`
		Port           int    `yaml:"port"`
		EnableTLS      bool   `yaml:"enable_tls"`
		TLSCertPath    string `yaml:"tls_cert_path"`
		TLSKeyPath     string `yaml:"tls_key_path"`
		SessionSecret  string `yaml:"session_secret"`
		UploadDir      string `yaml:"upload_dir"`
		MaxUploadSize  int64  `yaml:"max_upload_size"`
	} `yaml:"server"`
	
	Database struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
		Name string `yaml:"name"`
		User string `yaml:"user"`
		Pass string `yaml:"password"`
	} `yaml:"database"`
	
	Security struct {
		JWTSecret     string   `yaml:"jwt_secret"`
		APIKey        string   `yaml:"api_key"`
		AdminUsername string   `yaml:"admin_username"`
		AdminPassword string   `yaml:"admin_password"`
		AllowedOrigins []string `yaml:"allowed_origins"`
	} `yaml:"security"`
}

var (
	config Config
	db     *gorm.DB
	logger *logrus.Logger
	hub    *Hub
)

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"uniqueIndex;size:50" json:"username"`
	PasswordHash string    `json:"-"`
	Email        string    `json:"email"`
	Role         string    `gorm:"default:'operator'" json:"role"`
	IsActive     bool      `gorm:"default:true" json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Agent struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	UUID         string    `gorm:"uniqueIndex;size:36" json:"uuid"`
	Hostname     string    `json:"hostname"`
	Username     string    `json:"username"`
	OS           string    `json:"os"`
	Arch         string    `json:"arch"`
	IPAddress    string    `json:"ip_address"`
	ProcessID    int       `json:"process_id"`
	SleepInterval int      `json:"sleep_interval"`
	Jitter       int       `json:"jitter"`
	Status       string    `gorm:"default:'offline'" json:"status"`
	LastSeen     time.Time `json:"last_seen"`
	CreatedAt    time.Time `json:"created_at"`
	Metadata     string    `json:"metadata"` // JSON string
}

type Task struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	AgentID     uint      `json:"agent_id"`
	Agent       Agent     `gorm:"foreignKey:AgentID" json:"agent,omitempty"`
	Command     string    `json:"command"`
	Arguments   string    `json:"arguments"`
	Status      string    `gorm:"default:'pending'" json:"status"`
	Output      string    `json:"output"`
	Error       string    `json:"error"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Priority    int       `gorm:"default:0" json:"priority"`
}

type File struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	AgentID      uint      `json:"agent_id"`
	Agent        Agent     `gorm:"foreignKey:AgentID" json:"agent,omitempty"`
	Filename     string    `json:"filename"`
	FilePath     string    `json:"file_path"`
	FileSize     int64     `json:"file_size"`
	MD5Hash      string    `json:"md5_hash"`
	UploadedAt   time.Time `json:"uploaded_at"`
	IsDownloadable bool    `gorm:"default:true" json:"is_downloadable"`
}

type WebSocketMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

type Client struct {
	hub    *Hub
	conn   *websocket.Conn
	send   chan []byte
	userID uint
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		for _, allowed := range config.Security.AllowedOrigins {
			if origin == allowed {
				return true
			}
		}
		return origin == "" // Allow empty origin for local testing
	},
}

func NewHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			
		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			
		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.Printf("WebSocket error: %v", err)
			}
			break
		}
		
		var wsMsg WebSocketMessage
		if err := json.Unmarshal(message, &wsMsg); err != nil {
			logger.Printf("Failed to parse WebSocket message: %v", err)
			continue
		}
		
		// Handle different message types
		switch wsMsg.Type {
		case "ping":
			c.send <- []byte(`{"type":"pong"}`)
		case "subscribe_agent":
			// Subscribe to agent updates
		case "unsubscribe_agent":
			// Unsubscribe from agent updates
		}
	}
}

func (c *Client) writePump() {
	defer func() {
		c.conn.Close()
	}()
	
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			
			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)
			
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}
			
			if err := w.Close(); err != nil {
				return
			}
		}
	}
}

func serveWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Printf("Failed to upgrade WebSocket: %v", err)
		return
	}
	
	token := r.URL.Query().Get("token")
	userID, err := validateToken(token)
	if err != nil {
		conn.WriteMessage(websocket.CloseMessage, []byte(`{"error":"invalid token"}`))
		conn.Close()
		return
	}
	
	client := &Client{
		hub:    hub,
		conn:   conn,
		send:   make(chan []byte, 256),
		userID: userID,
	}
	
	hub.register <- client
	
	go client.writePump()
	go client.readPump()
}

func validateToken(token string) (uint, error) {
	// Implement JWT validation
	return 1, nil // Simplified for example
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	var user User
	result := db.Where("username = ? AND is_active = true", creds.Username).First(&user)
	if result.Error != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	
	// Generate JWT token
	token, err := generateToken(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token": token,
		"user":  user,
	})
}

func generateToken(user User) (string, error) {
	// Implement JWT generation
	return "jwt-token-placeholder", nil
}

func handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var agentData struct {
		UUID         string `json:"uuid"`
		Hostname     string `json:"hostname"`
		Username     string `json:"username"`
		OS           string `json:"os"`
		Arch         string `json:"arch"`
		IPAddress    string `json:"ip_address"`
		SleepInterval int   `json:"sleep_interval"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&agentData); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	// Check if agent already exists
	var agent Agent
	result := db.Where("uuid = ?", agentData.UUID).First(&agent)
	
	if result.Error == gorm.ErrRecordNotFound {
		// Create new agent
		agent = Agent{
			UUID:         agentData.UUID,
			Hostname:     agentData.Hostname,
			Username:     agentData.Username,
			OS:           agentData.OS,
			Arch:         agentData.Arch,
			IPAddress:    agentData.IPAddress,
			SleepInterval: agentData.SleepInterval,
			Status:       "online",
			LastSeen:     time.Now(),
		}
		db.Create(&agent)
	} else {
		// Update existing agent
		agent.Status = "online"
		agent.LastSeen = time.Now()
		db.Save(&agent)
	}
	
	// Broadcast agent connection
	hub.broadcast <- []byte(fmt.Sprintf(`{"type":"agent_connected","payload":{"uuid":"%s","hostname":"%s"}}`, agent.UUID, agent.Hostname))
	
	// Return pending tasks
	var pendingTasks []Task
	db.Where("agent_id = ? AND status = 'pending'", agent.ID).Find(&pendingTasks)
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "registered",
		"agent_id": agent.ID,
		"tasks": pendingTasks,
	})
}

func handleAgentBeacon(w http.ResponseWriter, r *http.Request) {
	agentUUID := r.URL.Query().Get("uuid")
	if agentUUID == "" {
		http.Error(w, "Missing agent UUID", http.StatusBadRequest)
		return
	}
	
	var agent Agent
	result := db.Where("uuid = ?", agentUUID).First(&agent)
	if result.Error != nil {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}
	
	// Update last seen
	agent.LastSeen = time.Now()
	agent.Status = "online"
	db.Save(&agent)
	
	// Get pending tasks
	var tasks []Task
	db.Where("agent_id = ? AND status = 'pending'", agent.ID).Find(&tasks)
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks": tasks,
		"sleep": agent.SleepInterval,
	})
}

func handleTaskResult(w http.ResponseWriter, r *http.Request) {
	var result struct {
		TaskID  string `json:"task_id"`
		Output  string `json:"output"`
		Error   string `json:"error"`
		Status  string `json:"status"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	var task Task
	db.First(&task, result.TaskID)
	
	task.Status = result.Status
	task.Output = result.Output
	task.Error = result.Error
	task.CompletedAt = time.Now()
	db.Save(&task)
	
	// Broadcast task completion
	hub.broadcast <- []byte(fmt.Sprintf(`{"type":"task_completed","payload":{"task_id":%d,"agent_id":%d}}`, task.ID, task.AgentID))
	
	w.WriteHeader(http.StatusOK)
}

func handleFileUpload(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form
	r.ParseMultipartForm(config.Server.MaxUploadSize)
	
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	agentID := r.FormValue("agent_id")
	filename := handler.Filename
	
	// Create upload directory if it doesn't exist
	uploadDir := fmt.Sprintf("%s/%s", config.Server.UploadDir, agentID)
	os.MkdirAll(uploadDir, 0755)
	
	// Create file on disk
	filePath := fmt.Sprintf("%s/%s", uploadDir, filename)
	dst, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	
	// Copy file
	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	
	// Create database record
	fileRecord := File{
		AgentID:   parseUint(agentID),
		Filename:  filename,
		FilePath:  filePath,
		FileSize:  handler.Size,
		UploadedAt: time.Now(),
	}
	db.Create(&fileRecord)
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       fileRecord.ID,
		"filename": filename,
		"size":     handler.Size,
	})
}

func parseUint(s string) uint {
	var i uint
	fmt.Sscanf(s, "%d", &i)
	return i
}

func setupRoutes() *mux.Router {
	r := mux.NewRouter()
	
	// API routes
	api := r.PathPrefix("/api/v1").Subrouter()
	
	// Authentication
	api.HandleFunc("/auth/login", handleLogin).Methods("POST")
	
	// Agent endpoints (no auth required)
	api.HandleFunc("/agent/register", handleAgentRegister).Methods("POST")
	api.HandleFunc("/agent/beacon", handleAgentBeacon).Methods("GET")
	api.HandleFunc("/agent/task/result", handleTaskResult).Methods("POST")
	
	// Protected routes (require auth)
	protected := api.PathPrefix("").Subrouter()
	protected.Use(authMiddleware)
	
	protected.HandleFunc("/agents", handleListAgents).Methods("GET")
	protected.HandleFunc("/agents/{id}", handleGetAgent).Methods("GET")
	protected.HandleFunc("/agents/{id}/tasks", handleAgentTasks).Methods("GET")
	protected.HandleFunc("/tasks", handleCreateTask).Methods("POST")
	protected.HandleFunc("/tasks/{id}", handleGetTask).Methods("GET")
	protected.HandleFunc("/files/upload", handleFileUpload).Methods("POST")
	protected.HandleFunc("/files/{id}/download", handleFileDownload).Methods("GET")
	
	// WebSocket
	r.HandleFunc("/ws", serveWebSocket)
	
	// Health check
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	}).Methods("GET")
	
	// Serve frontend
	r.PathPrefix("/").Handler(http.FileServer(http.FS(frontendFS)))
	
	return r
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		
		if token == "" || !strings.HasPrefix(token, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		token = strings.TrimPrefix(token, "Bearer ")
		
		// Validate token
		_, err := validateToken(token)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func loadConfig() {
	// Load configuration from environment variables or config file
	// Simplified for example
	config.Server.Host = os.Getenv("SERVER_HOST")
	if config.Server.Host == "" {
		config.Server.Host = "0.0.0.0"
	}
	
	config.Server.Port = 8080
	config.Server.EnableTLS = os.Getenv("ENABLE_TLS") == "true"
	config.Security.JWTSecret = os.Getenv("JWT_SECRET")
	config.Security.AdminUsername = os.Getenv("ADMIN_USERNAME")
	config.Security.AdminPassword = os.Getenv("ADMIN_PASSWORD")
	
	// Database configuration
	config.Database.Host = os.Getenv("DB_HOST")
	config.Database.Port = 5432
	config.Database.Name = os.Getenv("DB_NAME")
	config.Database.User = os.Getenv("DB_USER")
	config.Database.Pass = os.Getenv("DB_PASSWORD")
}

func initDatabase() {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable",
		config.Database.Host, config.Database.User, config.Database.Pass,
		config.Database.Name, config.Database.Port)
	
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}
	
	// Auto migrate
	db.AutoMigrate(&User{}, &Agent{}, &Task{}, &File{})
	
	// Create admin user if not exists
	var adminUser User
	result := db.Where("username = ?", config.Security.AdminUsername).First(&adminUser)
	if result.Error == gorm.ErrRecordNotFound {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(config.Security.AdminPassword), bcrypt.DefaultCost)
		adminUser = User{
			Username:     config.Security.AdminUsername,
			PasswordHash: string(hashedPassword),
			Email:        "admin@ares.local",
			Role:         "admin",
			IsActive:     true,
		}
		db.Create(&adminUser)
		logger.Info("Created admin user")
	}
}

func initLogger() {
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)
	
	level := os.Getenv("LOG_LEVEL")
	if level == "" {
		level = "info"
	}
	
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logger.SetLevel(logLevel)
}

func main() {
	initLogger()
	loadConfig()
	initDatabase()
	
	hub = NewHub()
	go hub.Run()
	
	router := setupRoutes()
	
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	if config.Server.EnableTLS {
		server.TLSConfig = &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		}
	}
	
	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		logger.Infof("Starting server on %s", server.Addr)
		var err error
		if config.Server.EnableTLS {
			err = server.ListenAndServeTLS(config.Server.TLSCertPath, config.Server.TLSKeyPath)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server failed: %v", err)
		}
	}()
	
	<-stop
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := server.Shutdown(ctx); err != nil {
		logger.Printf("Graceful shutdown failed: %v", err)
	}
	
	logger.Info("Server stopped gracefully")
}
