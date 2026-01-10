package websocket

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Hub struct {
	clients      map[*Client]bool
	broadcast    chan []byte
	register     chan *Client
	unregister   chan *Client
	agentClients map[string]*Client // agent UUID -> client
	mu           sync.RWMutex
}

type Client struct {
	hub      *Hub
	conn     *websocket.Conn
	send     chan []byte
	agentID  string
	username string
}

func NewHub() *Hub {
	return &Hub{
		broadcast:    make(chan []byte),
		register:     make(chan *Client),
		unregister:   make(chan *Client),
		clients:      make(map[*Client]bool),
		agentClients: make(map[string]*Client),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			if client.agentID != "" {
				h.agentClients[client.agentID] = client
			}
			h.mu.Unlock()
			
			// Broadcast agent connection
			if client.agentID != "" {
				msg := map[string]interface{}{
					"type": "agent_connected",
					"data": map[string]string{
						"agent_id": client.agentID,
						"time":     time.Now().Format(time.RFC3339),
					},
				}
				data, _ := json.Marshal(msg)
				h.Broadcast(data, client.agentID)
			}

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				if client.agentID != "" {
					delete(h.agentClients, client.agentID)
				}
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
					if client.agentID != "" {
						delete(h.agentClients, client.agentID)
					}
				}
			}
			h.mu.RUnlock()
		}
	}
}

func (h *Hub) Broadcast(data []byte, excludeAgentID string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	for client := range h.clients {
		if client.agentID == excludeAgentID {
			continue
		}
		select {
		case client.send <- data:
		default:
			log.Printf("Failed to send to client %s", client.agentID)
		}
	}
}

func (h *Hub) SendToAgent(agentID string, data []byte) bool {
	h.mu.RLock()
	client, ok := h.agentClients[agentID]
	h.mu.RUnlock()
	
	if !ok {
		return false
	}
	
	select {
	case client.send <- data:
		return true
	default:
		return false
	}
}
