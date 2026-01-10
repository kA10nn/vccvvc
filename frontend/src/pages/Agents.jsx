package api

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

// Auth handlers
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		s.errorResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	var user User
	result := s.db.Where("username = ? AND is_active = true", creds.Username).First(&user)
	if result.Error != nil {
		s.errorResponse(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	
	if !checkPasswordHash(creds.Password, user.PasswordHash) {
		s.errorResponse(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	
	token, err := s.generateToken(user.ID, user.Username, user.Role)
	if err != nil {
		s.errorResponse(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	
	s.jsonResponse(w, map[string]interface{}{
		"token": token,
		"user": map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
		},
	})
}

// Agent handlers
func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	var agents []Agent
	
	query := s.db.Model(&Agent{})
	
	// Apply filters
	if status := r.URL.Query().Get("status"); status != "" {
		query = query.Where("status = ?", status)
	}
	
	if search := r.URL.Query().Get("search"); search != "" {
		search = "%" + search + "%"
		query = query.Where("hostname LIKE ? OR username LIKE ? OR uuid LIKE ?", search, search, search)
	}
	
	// Pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize
	
	// Get total count
	var total int64
	query.Count(&total)
	
	// Get agents
	query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&agents)
	
	s.jsonResponse(w, map[string]interface{}{
		"agents":    agents,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["id"]
	
	var agent Agent
	result := s.db.First(&agent, agentID)
	if result.Error != nil {
		s.errorResponse(w, "Agent not found", http.StatusNotFound)
		return
	}
	
	// Get agent tasks
	var tasks []Task
	s.db.Where("agent_id = ?", agent.ID).Order("created_at DESC").Limit(50).Find(&tasks)
	
	// Get agent files
	var files []File
	s.db.Where("agent_id = ?", agent.ID).Order("uploaded_at DESC").Limit(50).Find(&files)
	
	s.jsonResponse(w, map[string]interface{}{
		"agent": agent,
		"tasks": tasks,
		"files": files,
	})
}

func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var agentData struct {
		UUID         string `json:"uuid"`
		Hostname     string `json:"hostname"`
		Username     string `json:"username"`
		OS           string `json:"os"`
		Arch         string `json:"arch"`
		IPAddress    string `json:"ip_address"`
		SleepInterval int   `json:"sleep_interval"`
		Jitter       int    `json:"jitter"`
		ProcessID    int    `json:"process_id"`
		Metadata     string `json:"metadata"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&agentData); err != nil {
		s.errorResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	// Validate required fields
	if agentData.UUID == "" || agentData.Hostname == "" {
		s.errorResponse(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	
	// Check if agent already exists
	var agent Agent
	result := s.db.Where("uuid = ?", agentData.UUID).First(&agent)
	
	if result.Error == gorm.ErrRecordNotFound {
		// Create new agent
		agent = Agent{
			UUID:         agentData.UUID,
			Hostname:     agentData.Hostname,
			Username:     agentData.Username,
			OS:           agentData.OS,
			Arch:         agentData.Arch,
			IPAddress:    agentData.IPAddress,
			ProcessID:    agentData.ProcessID,
			SleepInterval: agentData.SleepInterval,
			Jitter:       agentData.Jitter,
			Status:       "online",
			LastSeen:     time.Now(),
			Metadata:     agentData.Metadata,
		}
		
		if err := s.db.Create(&agent).Error; err != nil {
			s.errorResponse(w, "Failed to create agent", http.StatusInternalServerError)
			return
		}
		
		// Log activity
		s.logActivity(r, "agent_registered", fmt.Sprintf("New agent registered: %s", agentData.Hostname), &agent.ID)
	} else {
		// Update existing agent
		agent.Status = "online"
		agent.LastSeen = time.Now()
		agent.Hostname = agentData.Hostname
		agent.Username = agentData.Username
		agent.IPAddress = agentData.IPAddress
		agent.Metadata = agentData.Metadata
		
		if err := s.db.Save(&agent).Error; err != nil {
			s.errorResponse(w, "Failed to update agent", http.StatusInternalServerError)
			return
		}
		
		s.logActivity(r, "agent_checked_in", fmt.Sprintf("Agent checked in: %s", agentData.Hostname), &agent.ID)
	}
	
	// Get pending tasks for this agent
	var pendingTasks []Task
	s.db.Where("agent_id = ? AND status = 'pending'", agent.ID).Find(&pendingTasks)
	
	// Broadcast agent connection via WebSocket
	s.broadcastWebSocket("agent_connected", map[string]interface{}{
		"uuid":     agent.UUID,
		"hostname": agent.Hostname,
		"username": agent.Username,
		"os":       agent.OS,
		"arch":     agent.Arch,
		"ip":       agent.IPAddress,
	})
	
	s.jsonResponse(w, map[string]interface{}{
		"status":   "registered",
		"agent_id": agent.ID,
		"tasks":    pendingTasks,
		"sleep":    agent.SleepInterval,
		"jitter":   agent.Jitter,
	})
}

func (s *Server) handleAgentBeacon(w http.ResponseWriter, r *http.Request) {
	agentUUID := r.URL.Query().Get("uuid")
	if agentUUID == "" {
		s.errorResponse(w, "Missing agent UUID", http.StatusBadRequest)
		return
	}
	
	var agent Agent
	result := s.db.Where("uuid = ?", agentUUID).First(&agent)
	if result.Error != nil {
		s.errorResponse(w, "Agent not found", http.StatusNotFound)
		return
	}
	
	// Update last seen and status
	agent.LastSeen = time.Now()
	agent.Status = "online"
	s.db.Save(&agent)
	
	// Get pending tasks
	var tasks []Task
	s.db.Where("agent_id = ? AND status = 'pending'", agent.ID).Find(&tasks)
	
	s.jsonResponse(w, map[string]interface{}{
		"tasks": tasks,
		"sleep": agent.SleepInterval,
		"jitter": agent.Jitter,
	})
}

func (s *Server) handleTaskResult(w http.ResponseWriter, r *http.Request) {
	var result struct {
		TaskID  string `json:"task_id"`
		Output  string `json:"output"`
		Error   string `json:"error"`
		Status  string `json:"status"` // completed, failed
	}
	
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		s.errorResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	var task Task
	if err := s.db.First(&task, result.TaskID).Error; err != nil {
		s.errorResponse(w, "Task not found", http.StatusNotFound)
		return
	}
	
	// Update task
	task.Status = result.Status
	task.Output = result.Output
	task.Error = result.Error
	task.CompletedAt = time.Now()
	
	if err := s.db.Save(&task).Error; err != nil {
		s.errorResponse(w, "Failed to update task", http.StatusInternalServerError)
		return
	}
	
	// Get agent for WebSocket broadcast
	var agent Agent
	s.db.First(&agent, task.AgentID)
	
	// Broadcast task completion
	s.broadcastWebSocket("task_completed", map[string]interface{}{
		"task_id":   task.ID,
		"agent_id":  task.AgentID,
		"agent_uuid": agent.UUID,
		"command":   task.Command,
		"status":    task.Status,
		"output":    task.Output,
		"error":     task.Error,
	})
	
	// Log activity
	s.logActivity(r, "task_completed", 
		fmt.Sprintf("Task %d completed with status: %s", task.ID, task.Status),
		&task.AgentID,
	)
	
	w.WriteHeader(http.StatusOK)
}

// Task handlers
func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]
	
	var taskData struct {
		Command   string `json:"command"`
		Arguments string `json:"arguments"`
		Priority  int    `json:"priority"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&taskData); err != nil {
		s.errorResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	if taskData.Command == "" {
		s.errorResponse(w, "Command is required", http.StatusBadRequest)
		return
	}
	
	// Get current user from context
	userID, ok := r.Context().Value("user_id").(uint)
	if !ok {
		userID = 0
	}
	
	var user User
	s.db.First(&user, userID)
	
	// Create task
	task := Task{
		AgentID:   parseUint(agentID),
		Command:   taskData.Command,
		Arguments: taskData.Arguments,
		Priority:  taskData.Priority,
		Status:    "pending",
		CreatedBy: user.Username,
		CreatedAt: time.Now(),
	}
	
	if err := s.db.Create(&task).Error; err != nil {
		s.errorResponse(w, "Failed to create task", http.StatusInternalServerError)
		return
	}
	
	// Get agent for WebSocket broadcast
	var agent Agent
	s.db.First(&agent, task.AgentID)
	
	// Broadcast task creation
	s.broadcastWebSocket("task_created", map[string]interface{}{
		"task_id":    task.ID,
		"agent_id":   task.AgentID,
		"agent_uuid": agent.UUID,
		"command":    task.Command,
		"arguments":  task.Arguments,
		"created_by": task.CreatedBy,
	})
	
	// Log activity
	s.logActivity(r, "task_created", 
		fmt.Sprintf("Task created: %s %s", task.Command, task.Arguments),
		&task.AgentID,
	)
	
	s.jsonResponse(w, task)
}

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	var tasks []Task
	
	query := s.db.Preload("Agent")
	
	// Apply filters
	if status := r.URL.Query().Get("status"); status != "" {
		query = query.Where("status = ?", status)
	}
	
	if agentID := r.URL.Query().Get("agent_id"); agentID != "" {
		query = query.Where("agent_id = ?", agentID)
	}
	
	if search := r.URL.Query().Get("search"); search != "" {
		search = "%" + search + "%"
		query = query.Where("command LIKE ? OR arguments LIKE ?", search, search)
	}
	
	// Pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize
	
	// Get total count
	var total int64
	query.Model(&Task{}).Count(&total)
	
	// Get tasks
	query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&tasks)
	
	s.jsonResponse(w, map[string]interface{}{
		"tasks":     tasks,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// File handlers
func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form (max 100MB)
	if err := r.ParseMultipartForm(100 << 20); err != nil {
		s.errorResponse(w, "File too large", http.StatusRequestEntityTooLarge)
		return
	}
	
	// Get file from form
	file, handler, err := r.FormFile("file")
	if err != nil {
		s.errorResponse(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	agentID := r.FormValue("agent_id")
	if agentID == "" {
		s.errorResponse(w, "Agent ID is required", http.StatusBadRequest)
		return
	}
	
	// Create upload directory if it doesn't exist
	uploadDir := filepath.Join(s.config.UploadDir, agentID)
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		s.errorResponse(w, "Failed to create upload directory", http.StatusInternalServerError)
		return
	}
	
	// Create file path
	filename := fmt.Sprintf("%d_%s", time.Now().Unix(), handler.Filename)
	filePath := filepath.Join(uploadDir, filename)
	
	// Create destination file
	dst, err := os.Create(filePath)
	if err != nil {
		s.errorResponse(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	
	// Copy file and calculate MD5
	hash := md5.New()
	multiWriter := io.MultiWriter(dst, hash)
	
	if _, err := io.Copy(multiWriter, file); err != nil {
		os.Remove(filePath)
		s.errorResponse(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	
	// Get MD5 hash
	md5Hash := hex.EncodeToString(hash.Sum(nil))
	
	// Create file record
	fileRecord := File{
		AgentID:   parseUint(agentID),
		Filename:  handler.Filename,
		FilePath:  filePath,
		FileSize:  handler.Size,
		MD5Hash:   md5Hash,
		UploadedAt: time.Now(),
	}
	
	if err := s.db.Create(&fileRecord).Error; err != nil {
		os.Remove(filePath)
		s.errorResponse(w, "Failed to save file record", http.StatusInternalServerError)
		return
	}
	
	// Broadcast file upload
	s.broadcastWebSocket("file_uploaded", map[string]interface{}{
		"file_id":   fileRecord.ID,
		"agent_id":  fileRecord.AgentID,
		"filename":  fileRecord.Filename,
		"file_size": fileRecord.FileSize,
		"md5_hash":  fileRecord.MD5Hash,
	})
	
	// Log activity
	s.logActivity(r, "file_uploaded", 
		fmt.Sprintf("File uploaded: %s (%d bytes)", fileRecord.Filename, fileRecord.FileSize),
		&fileRecord.AgentID,
	)
	
	s.jsonResponse(w, map[string]interface{}{
		"id":       fileRecord.ID,
		"filename": fileRecord.Filename,
		"size":     fileRecord.FileSize,
		"md5_hash": fileRecord.MD5Hash,
		"uploaded_at": fileRecord.UploadedAt,
	})
}

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["id"]
	
	var fileRecord File
	if err := s.db.First(&fileRecord, fileID).Error; err != nil {
		s.errorResponse(w, "File not found", http.StatusNotFound)
		return
	}
	
	// Check if file exists
	if _, err := os.Stat(fileRecord.FilePath); os.IsNotExist(err) {
		s.errorResponse(w, "File not found on disk", http.StatusNotFound)
		return
	}
	
	// Open file
	file, err := os.Open(fileRecord.FilePath)
	if err != nil {
		s.errorResponse(w, "Failed to open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	// Set headers
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileRecord.Filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileRecord.FileSize))
	
	// Copy file to response
	io.Copy(w, file)
}

// System handlers
func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	// Get system information
	info := map[string]interface{}{
		"version":    "1.0.0",
		"build_time": s.config.BuildTime,
		"uptime":     time.Since(s.startTime).Seconds(),
		"agents": map[string]interface{}{
			"total":   s.db.Model(&Agent{}).Count(new(int64)),
			"online":  s.db.Model(&Agent{}).Where("status = ?", "online").Count(new(int64)),
			"offline": s.db.Model(&Agent{}).Where("status = ?", "offline").Count(new(int64)),
		},
		"tasks": map[string]interface{}{
			"total":     s.db.Model(&Task{}).Count(new(int64)),
			"pending":   s.db.Model(&Task{}).Where("status = ?", "pending").Count(new(int64)),
			"running":   s.db.Model(&Task{}).Where("status = ?", "running").Count(new(int64)),
			"completed": s.db.Model(&Task{}).Where("status = ?", "completed").Count(new(int64)),
			"failed":    s.db.Model(&Task{}).Where("status = ?", "failed").Count(new(int64)),
		},
		"files": map[string]interface{}{
			"total": s.db.Model(&File{}).Count(new(int64)),
			"total_size": func() int64 {
				var totalSize int64
				s.db.Model(&File{}).Select("COALESCE(SUM(file_size), 0)").Scan(&totalSize)
				return totalSize
			}(),
		},
	}
	
	s.jsonResponse(w, info)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Check database connection
	if err := s.db.Exec("SELECT 1").Error; err != nil {
		s.errorResponse(w, "Database connection failed", http.StatusServiceUnavailable)
		return
	}
	
	s.jsonResponse(w, map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// Helper functions
func (s *Server) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *Server) errorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

func (s *Server) broadcastWebSocket(eventType string, data interface{}) {
	message := map[string]interface{}{
		"type":    eventType,
		"payload": data,
		"time":    time.Now().Unix(),
	}
	
	jsonData, err := json.Marshal(message)
	if err != nil {
		s.logger.Error("Failed to marshal WebSocket message:", err)
		return
	}
	
	s.wsHub.Broadcast(jsonData)
}

func (s *Server) logActivity(r *http.Request, action, details string, agentID *uint) {
	activity := Activity{
		UserID:    getUserIdFromContext(r),
		AgentID:   agentID,
		Action:    action,
		Details:   details,
		IPAddress: getIPAddress(r),
		CreatedAt: time.Now(),
	}
	
	s.db.Create(&activity)
}

func getUserIdFromContext(r *http.Request) *uint {
	if userID, ok := r.Context().Value("user_id").(uint); ok {
		return &userID
	}
	return nil
}

func getIPAddress(r *http.Request) string {
	// Get IP from X-Forwarded-For header if behind proxy
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

func parseUint(s string) uint {
	var i uint
	fmt.Sscanf(s, "%d", &i)
	return i
}
