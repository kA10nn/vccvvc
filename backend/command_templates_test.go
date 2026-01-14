package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	models "ares-c2/internal/models"

	"github.com/gorilla/mux"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestCommandTemplateCRUD(t *testing.T) {
	var err error
	// use in-memory sqlite for tests
	db, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	if err := models.RunMigrations(db); err != nil {
		t.Fatalf("migrations failed: %v", err)
	}

	// Create
	payload := map[string]interface{}{
		"name":        "t1",
		"value":       "cmd",
		"description": "desc",
		"template":    "-v",
		"is_public":   false,
	}
	b, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/settings/command-templates", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	// set a user in context (optional)
	req = req.WithContext(context.WithValue(req.Context(), authUserIDKey, uint(1)))
	rr := httptest.NewRecorder()

	handleCreateCommandTemplate(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d body %s", rr.Code, rr.Body.String())
	}

	var created map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("invalid response json: %v", err)
	}
	idFloat, ok := created["id"].(float64)
	if !ok {
		t.Fatalf("created id not found or wrong type")
	}
	id := int(idFloat)

	// List
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/settings/command-templates", nil)
	handleListCommandTemplates(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list failed: %d", rr.Code)
	}
	var list []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatalf("invalid list json: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 template, got %d", len(list))
	}

	// Update
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("PUT", fmt.Sprintf("/settings/command-templates/%d", id), bytes.NewReader([]byte(`{"name":"t1-up","template":"-al"}`)))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": strconv.Itoa(id)})
	handleUpdateCommandTemplate(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("update failed: %d body %s", rr.Code, rr.Body.String())
	}
	var updated map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &updated); err != nil {
		t.Fatalf("invalid update json: %v", err)
	}
	if updated["name"] != "t1-up" {
		t.Fatalf("expected name updated")
	}

	// Delete
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("DELETE", fmt.Sprintf("/settings/command-templates/%d", id), nil)
	req = mux.SetURLVars(req, map[string]string{"id": strconv.Itoa(id)})
	handleDeleteCommandTemplate(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on delete, got %d", rr.Code)
	}

	// List again
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/settings/command-templates", nil)
	handleListCommandTemplates(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list failed: %d", rr.Code)
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatalf("invalid list json: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected 0 templates after delete, got %d", len(list))
	}
}

func TestCreateTaskWithTemplateArguments(t *testing.T) {
	var err error
	// setup in-memory DB
	db, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := models.RunMigrations(db); err != nil {
		t.Fatalf("migrations failed: %v", err)
	}

	// create agent
	agent := Agent{
		UUID:      "agent-123",
		Hostname:  "host1",
		Username:  "svc",
		OS:        "linux",
		Arch:      "amd64",
		IPAddress: "127.0.0.1",
	}
	db.Create(&agent)

	// create template
	tmpl := models.CommandTemplate{
		Name:     "t2",
		Value:    "cmd",
		Template: "-la",
	}
	db.Create(&tmpl)

	// make create task request
	payload := map[string]interface{}{
		"agent_id":  agent.UUID,
		"command":   tmpl.Value,
		"arguments": tmpl.Template,
	}
	b, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/tasks", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	// set authenticated user
	req = req.WithContext(context.WithValue(req.Context(), authUserIDKey, uint(1)))
	rr := httptest.NewRecorder()

	handleCreateTask(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create task failed: %d body %s", rr.Code, rr.Body.String())
	}

	var created Task
	db.First(&created)
	if created.Arguments != tmpl.Template {
		t.Fatalf("expected arguments '%s' got '%s'", tmpl.Template, created.Arguments)
	}
}
