#!/bin/bash
set -e

echo "=========================================="
echo "🚀 ARES Web C2 Platform - Production Deployment"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "\n${BLUE}▶ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites"
    
    command -v docker >/dev/null 2>&1 || { print_error "Docker is required"; exit 1; }
    command -v docker-compose >/dev/null 2>&1 || { print_error "Docker Compose is required"; exit 1; }
    command -v openssl >/dev/null 2>&1 || { print_error "OpenSSL is required"; exit 1; }
    
    print_success "All prerequisites met"
}

# Generate environment file
generate_env() {
    print_step "Generating environment configuration"
    
    if [ -f .env ]; then
        print_warning ".env file already exists"
        read -p "Overwrite? (y/N): " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && return
    fi
    
    # Generate secure passwords
    DB_PASSWORD=$(openssl rand -base64 32)
    JWT_SECRET=$(openssl rand -base64 64)
    ADMIN_PASSWORD=$(openssl rand -base64 16)
    API_KEY="ares-$(openssl rand -hex 16)"
    REDIS_PASSWORD=$(openssl rand -base64 24)
    
    cat > .env << EOF
# ==========================================
# ARES Web C2 Configuration
# Generated: $(date)
# ==========================================

# Database Configuration
DB_HOST=postgres
DB_PORT=5432
DB_NAME=ares_c2
DB_USER=ares
DB_PASSWORD=${DB_PASSWORD}

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=${REDIS_PASSWORD}

# Application Security
JWT_SECRET=${JWT_SECRET}
ADMIN_USERNAME=admin
ADMIN_PASSWORD=${ADMIN_PASSWORD}
API_KEY=${API_KEY}

# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
ENABLE_TLS=true
TLS_CERT_PATH=/app/ssl/cert.pem
TLS_KEY_PATH=/app/ssl/key.pem
UPLOAD_DIR=/app/uploads
LOG_LEVEL=info

# Frontend Configuration
REACT_APP_API_URL=/api/v1
REACT_APP_WS_URL=ws://\${DOMAIN:-localhost}/ws
REACT_APP_VERSION=1.0.0

# Nginx Configuration (optional)
DOMAIN=localhost
SSL_EMAIL=admin@localhost
EOF
    
    print_success "Environment file created"
    print_warning "Save these credentials in a secure location:"
    echo "Admin Password: $ADMIN_PASSWORD"
    echo "API Key: $API_KEY"
    echo "JWT Secret: $JWT_SECRET"
}

# Generate SSL certificates
generate_ssl() {
    print_step "Generating SSL certificates"
    
    mkdir -p ssl
    
    if [ ! -f ssl/cert.pem ] || [ ! -f ssl/key.pem ]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout ssl/key.pem -out ssl/cert.pem \
            -subj "/C=US/ST=State/L=City/O=ARES Security/CN=ares.local" \
            -addext "subjectAltName = DNS:localhost, DNS:ares.local, IP:127.0.0.1"
        
        print_success "SSL certificates generated"
    else
        print_warning "SSL certificates already exist"
    fi
}

# Initialize database
init_database() {
    print_step "Initializing database schema"
    
    mkdir -p init
    
    cat > init/init.sql << 'EOF'
-- ARES Database Schema
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table for operator authentication
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'operator',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Agents table
CREATE TABLE IF NOT EXISTS agents (
    id SERIAL PRIMARY KEY,
    uuid VARCHAR(36) UNIQUE NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    os VARCHAR(50) NOT NULL,
    arch VARCHAR(20) NOT NULL,
    ip_address INET,
    process_id INTEGER,
    sleep_interval INTEGER DEFAULT 60,
    jitter INTEGER DEFAULT 30,
    status VARCHAR(20) DEFAULT 'offline',
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB
);

-- Tasks table
CREATE TABLE IF NOT EXISTS tasks (
    id SERIAL PRIMARY KEY,
    agent_id INTEGER REFERENCES agents(id) ON DELETE CASCADE,
    command VARCHAR(50) NOT NULL,
    arguments TEXT,
    status VARCHAR(20) DEFAULT 'pending',
    output TEXT,
    error TEXT,
    created_by VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    priority INTEGER DEFAULT 0
);

-- Files table
CREATE TABLE IF NOT EXISTS files (
    id SERIAL PRIMARY KEY,
    agent_id INTEGER REFERENCES agents(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    file_size BIGINT,
    md5_hash VARCHAR(32),
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_downloadable BOOLEAN DEFAULT true
);

-- Activity log
CREATE TABLE IF NOT EXISTS activity_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    details TEXT,
    ip_address INET,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_agents_uuid ON agents(uuid);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_tasks_agent_id ON tasks(agent_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_files_agent_id ON files(agent_id);
CREATE INDEX IF NOT EXISTS idx_activity_created_at ON activity_log(created_at);

-- Insert default admin user (password will be hashed by application)
INSERT INTO users (username, password_hash, email, role)
VALUES ('admin', '', 'admin@ares.local', 'admin')
ON CONFLICT (username) DO NOTHING;

-- Create functions
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
EOF
    
    print_success "Database initialization script created"
}

# Build and deploy
deploy_services() {
    print_step "Building and deploying services"
    
    # Build images
    docker-compose build --no-cache
    
    # Start services
    docker-compose up -d
    
    # Wait for services to be healthy
    print_step "Waiting for services to start..."
    sleep 10
    
    # Check if backend is running
    if curl -s -f http://localhost:8080/api/v1/health > /dev/null; then
        print_success "Backend service is running"
    else
        print_error "Backend service failed to start"
        docker-compose logs backend
        exit 1
    fi
    
    print_success "All services deployed successfully"
}

# Print deployment summary
print_summary() {
    print_step "Deployment Complete!"
    echo ""
    echo "=========================================="
    echo "🌐 Access URLs:"
    echo "   Dashboard:    https://localhost"
    echo "   API:          https://localhost:8443"
    echo "   Health:       http://localhost:8080/api/v1/health"
    echo ""
    echo "🔑 Credentials:"
    echo "   Username:     admin"
    echo "   Password:     $(grep ADMIN_PASSWORD .env | cut -d '=' -f2)"
    echo ""
    echo "🛠️  Management Commands:"
    echo "   View logs:    docker-compose logs -f"
    echo "   Stop:         docker-compose down"
    echo "   Restart:      docker-compose restart"
    echo "   Update:       git pull && docker-compose up -d --build"
    echo ""
    echo "📁 Important Directories:"
    echo "   Uploads:      ./data/uploads"
    echo "   SSL Certs:    ./ssl"
    echo "   Logs:         docker-compose logs [service]"
    echo "=========================================="
}

# Main deployment process
main() {
    echo -e "${BLUE}"
    cat << "EOF"
    ___    ____  ______
   /   |  / __ \/ ____/
  / /| | / /_/ / __/   
 / ___ |/ _, _/ /___   
/_/  |_/_/ |_/_____/   
   Web C2 Platform
EOF
    echo -e "${NC}"
    
    check_prerequisites
    generate_env
    generate_ssl
    init_database
    deploy_services
    print_summary
}

# Run main function
main "$@"
