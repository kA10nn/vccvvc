package models

import (
	"fmt"
	"math/rand"
	"time"
)

// User represents an operator/admin user
type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"uniqueIndex;size:50;not null" json:"username"`
	PasswordHash string    `gorm:"not null" json:"-"`
	Email        string    `gorm:"size:100" json:"email"`
	Role         string    `gorm:"size:20;default:'operator'" json:"role"` // admin, operator
	IsActive     bool      `gorm:"default:true" json:"is_active"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// Agent represents a connected implant
type Agent struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	UUID         string    `gorm:"uniqueIndex;size:36;not null" json:"uuid"`
	Hostname     string    `gorm:"not null" json:"hostname"`
	Username     string    `gorm:"not null" json:"username"`
	OS           string    `gorm:"size:50;not null" json:"os"`
	Arch         string    `gorm:"size:20;not null" json:"arch"`
	IPAddress    string    `json:"ip_address"`
	ProcessID    int       `json:"process_id"`
	SleepInterval int      `gorm:"default:60" json:"sleep_interval"`
	Jitter       int       `gorm:"default:30" json:"jitter"`
	Status       string    `gorm:"size:20;default:'offline'" json:"status"` // online, offline, sleeping
	LastSeen     time.Time `json:"last_seen"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
	Metadata     string    `gorm:"type:text" json:"metadata"` // JSON string
}

// Task represents a command to be executed on an agent
type Task struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	AgentID     uint      `gorm:"index;not null" json:"agent_id"`
	Agent       Agent     `gorm:"foreignKey:AgentID" json:"agent,omitempty"`
	Command     string    `gorm:"size:50;not null" json:"command"`
	Arguments   string    `gorm:"type:text" json:"arguments"`
	Status      string    `gorm:"size:20;default:'pending'" json:"status"` // pending, running, completed, failed
	Output      string    `gorm:"type:text" json:"output"`
	Error       string    `gorm:"type:text" json:"error"`
	CreatedBy   string    `gorm:"size:50" json:"created_by"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Priority    int       `gorm:"default:50" json:"priority"`
}

// File represents uploaded/downloaded files
type File struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	AgentID        uint      `gorm:"index;not null" json:"agent_id"`
	Agent          Agent     `gorm:"foreignKey:AgentID" json:"agent,omitempty"`
	Filename       string    `gorm:"not null" json:"filename"`
	FilePath       string    `gorm:"not null" json:"file_path"`
	FileSize       int64     `json:"file_size"`
	MD5Hash        string    `gorm:"size:32" json:"md5_hash"`
	UploadedAt     time.Time `gorm:"autoCreateTime" json:"uploaded_at"`
	IsDownloadable bool      `gorm:"default:true" json:"is_downloadable"`
}

// Activity represents audit log entries
type Activity struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    *uint     `gorm:"index" json:"user_id"`
	AgentID   *uint     `gorm:"index" json:"agent_id"`
	Action    string    `gorm:"size:50;not null" json:"action"`
	Details   string    `gorm:"type:text" json:"details"`
	IPAddress string    `json:"ip_address"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}

// Config represents system configuration
type Config struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Key       string    `gorm:"uniqueIndex;size:100;not null" json:"key"`
	Value     string    `gorm:"type:text;not null" json:"value"`
	Type      string    `gorm:"size:20;default:'string'" json:"type"` // string, number, boolean, json
	Category  string    `gorm:"size:50;default:'general'" json:"category"`
	IsSecret  bool      `gorm:"default:false" json:"is_secret"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// Session represents user sessions for tracking
type Session struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"index;not null" json:"user_id"`
	Token     string    `gorm:"uniqueIndex;size:255;not null" json:"-"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}

// Webhook represents outgoing webhook configurations
type Webhook struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"size:100;not null" json:"name"`
	URL         string    `gorm:"not null" json:"url"`
	Method      string    `gorm:"size:10;default:'POST'" json:"method"`
	Events      string    `gorm:"type:text" json:"events"` // JSON array of events
	Headers     string    `gorm:"type:text" json:"headers"` // JSON object
	IsActive    bool      `gorm:"default:true" json:"is_active"`
	LastTrigger time.Time `json:"last_trigger"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
}

// CommandTemplate represents reusable command templates/scripts
type CommandTemplate struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"size:100;not null" json:"name"`
	Value       string    `gorm:"size:100;not null" json:"value"` // command type or identifier (eg. 'cmd', 'sysinfo')
	Description string    `gorm:"size:255" json:"description"`
	Template    string    `gorm:"type:text" json:"template"` // default arguments or payload
	CreatedBy   string    `gorm:"size:50" json:"created_by"`
	IsPublic    bool      `gorm:"default:false" json:"is_public"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// APIKey represents API keys for external integration
type APIKey struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"size:100;not null" json:"name"`
	Key         string    `gorm:"uniqueIndex;size:64;not null" json:"key"`
	Permissions string    `gorm:"type:text" json:"permissions"` // JSON array
	ExpiresAt   time.Time `json:"expires_at"`
	IsActive    bool      `gorm:"default:true" json:"is_active"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
	CreatedBy   string    `json:"created_by"`
}

// List of valid agent statuses
const (
	AgentStatusOnline   = "online"
	AgentStatusOffline  = "offline"
	AgentStatusSleeping = "sleeping"
)

// List of valid task statuses
const (
	TaskStatusPending   = "pending"
	TaskStatusRunning   = "running"
	TaskStatusCompleted = "completed"
	TaskStatusFailed    = "failed"
	TaskStatusCancelled = "cancelled"
)

// List of valid user roles
const (
	UserRoleAdmin    = "admin"
	UserRoleOperator = "operator"
)

// Common commands
const (
	CommandShell       = "cmd"
	CommandUpload      = "upload"
	CommandDownload    = "download"
	CommandScreenshot  = "screenshot"
	CommandKeylogger   = "keylogger"
	CommandPersistence = "persist"
	CommandSysInfo     = "sysinfo"
	CommandProcessList = "ps"
	CommandNetStat     = "netstat"
)

// Event types for WebSocket/Webhook
const (
	EventAgentConnected    = "agent_connected"
	EventAgentDisconnected = "agent_disconnected"
	EventTaskCreated       = "task_created"
	EventTaskCompleted     = "task_completed"
	EventFileUploaded      = "file_uploaded"
	EventFileDownloaded    = "file_downloaded"
	EventSystemAlert       = "system_alert"
)

// Methods for JSON serialization
func (a *Agent) BeforeCreate() error {
	if a.UUID == "" {
		a.UUID = generateUUID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	return nil
}

func (t *Task) BeforeCreate() error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	if t.Priority == 0 {
		t.Priority = 50
	}
	return nil
}

// Helper function to generate UUID (simplified)
func generateUUID() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		time.Now().Unix(),
		rand.Int63(),
		rand.Int63(),
		rand.Int63(),
		rand.Int63())
}
