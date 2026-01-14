package models

import (
	"fmt"
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// RunMigrations creates or updates database schema
func RunMigrations(db *gorm.DB) error {
	// Enable UUID extension for PostgreSQL
	db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")

	// Run auto-migration
	err := db.AutoMigrate(
		&User{},
		&Agent{},
		&Task{},
		&File{},
		&Activity{},
		&Config{},
		&Session{},
		&Webhook{},
		&APIKey{},
		&CommandTemplate{},
	)
	if err != nil {
		return fmt.Errorf("failed to run auto-migration: %w", err)
	}

	// Create indexes for command templates
	db.Exec("CREATE INDEX IF NOT EXISTS idx_command_templates_name ON command_templates(name);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_command_templates_is_public ON command_templates(is_public);")

	// Create indexes
	createIndexes(db)

	// Seed initial data
	seedInitialData(db)

	return nil
}

func createIndexes(db *gorm.DB) {
	// Agent indexes
	db.Exec("CREATE INDEX IF NOT EXISTS idx_agents_uuid ON agents(uuid);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);")
	
	// Task indexes
	db.Exec("CREATE INDEX IF NOT EXISTS idx_tasks_agent_id ON tasks(agent_id);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at);")
	
	// File indexes
	db.Exec("CREATE INDEX IF NOT EXISTS idx_files_agent_id ON files(agent_id);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_files_uploaded_at ON files(uploaded_at);")
	
	// Activity indexes
	db.Exec("CREATE INDEX IF NOT EXISTS idx_activity_created_at ON activities(created_at);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_activity_user_id ON activities(user_id);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_activity_agent_id ON activities(agent_id);")
	
	// Config indexes
	db.Exec("CREATE INDEX IF NOT EXISTS idx_config_key ON configs(key);")
	
	// Session indexes
	db.Exec("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);")
}

func seedInitialData(db *gorm.DB) {
	// Create default admin user if not exists
	var adminCount int64
	db.Model(&User{}).Where("username = ?", "admin").Count(&adminCount)
	
	if adminCount == 0 {
		hashedPassword, _ := hashPassword("admin123")
		admin := User{
			Username:     "admin",
			PasswordHash: hashedPassword,
			Email:        "admin@ares.local",
			Role:         UserRoleAdmin,
			IsActive:     true,
		}
		db.Create(&admin)
		fmt.Println("Created default admin user")
	}

	// Insert default configuration
	defaultConfigs := []Config{
		{
			Key:       "system.name",
			Value:     "ARES C2",
			Type:      "string",
			Category:  "general",
			IsSecret:  false,
		},
		{
			Key:       "system.version",
			Value:     "1.0.0",
			Type:      "string",
			Category:  "general",
			IsSecret:  false,
		},
		{
			Key:       "security.session_timeout",
			Value:     "3600",
			Type:      "number",
			Category:  "security",
			IsSecret:  false,
		},
		{
			Key:       "security.max_login_attempts",
			Value:     "5",
			Type:      "number",
			Category:  "security",
			IsSecret:  false,
		},
		{
			Key:       "agent.default_sleep",
			Value:     "60",
			Type:      "number",
			Category:  "agent",
			IsSecret:  false,
		},
		{
			Key:       "agent.default_jitter",
			Value:     "30",
			Type:      "number",
			Category:  "agent",
			IsSecret:  false,
		},
		{
			Key:       "logging.level",
			Value:     "info",
			Type:      "string",
			Category:  "logging",
			IsSecret:  false,
		},
		{
			Key:       "notifications.enabled",
			Value:     "true",
			Type:      "boolean",
			Category:  "notifications",
			IsSecret:  false,
		},
	}

	for _, cfg := range defaultConfigs {
		var existing Config
		if err := db.Where("key = ?", cfg.Key).First(&existing).Error; err != nil {
			db.Create(&cfg)
		}
	}

	// Create default API key if not exists
	var apiKeyCount int64
	db.Model(&APIKey{}).Where("name = ?", "Default API Key").Count(&apiKeyCount)
	
	if apiKeyCount == 0 {
		apiKey := APIKey{
			Name:        "Default API Key",
			Key:         generateAPIKey(),
			Permissions: `["agents:read", "agents:write", "tasks:read", "tasks:write"]`,
			ExpiresAt:   time.Now().AddDate(1, 0, 0), // 1 year from now
			IsActive:    true,
			CreatedBy:   "system",
		}
		db.Create(&apiKey)
		fmt.Println("Created default API key")
	}
}

func hashPassword(password string) (string, error) {
	// Using bcrypt for password hashing
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func generateAPIKey() string {
	// Generate a random API key
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const keyLength = 32
	
	bytes := make([]byte, keyLength)
	for i := range bytes {
		bytes[i] = chars[rand.Intn(len(chars))]
	}
	return string(bytes)
}
