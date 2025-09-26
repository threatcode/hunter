#!/bin/bash

# AI Bug Hunter - Service Startup Script
# This script starts all the required services for the Bug Hunter framework

set -e

echo "🚀 Starting AI Bug Hunter services..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if a service is running
is_service_running() {
    pgrep -f "$1" >/dev/null 2>&1
}

# Function to wait for service to be ready
wait_for_service() {
    local service_name=$1
    local check_command=$2
    local max_attempts=30
    local attempt=1
    
    echo -e "${YELLOW}Waiting for $service_name to be ready...${NC}"
    
    while [ $attempt -le $max_attempts ]; do
        if eval "$check_command" >/dev/null 2>&1; then
            echo -e "${GREEN}✅ $service_name is ready${NC}"
            return 0
        fi
        
        echo -n "."
        sleep 1
        ((attempt++))
    done
    
    echo -e "${RED}❌ $service_name failed to start within $max_attempts seconds${NC}"
    return 1
}

# Check prerequisites
echo -e "${BLUE}Checking prerequisites...${NC}"

if ! command_exists python3; then
    echo -e "${RED}❌ Python 3 is not installed${NC}"
    exit 1
fi

if ! command_exists redis-server; then
    echo -e "${RED}❌ Redis is not installed${NC}"
    echo -e "${YELLOW}Install with: brew install redis (macOS) or apt-get install redis-server (Ubuntu)${NC}"
    exit 1
fi

if ! command_exists psql; then
    echo -e "${RED}❌ PostgreSQL client is not installed${NC}"
    echo -e "${YELLOW}Install with: brew install postgresql (macOS) or apt-get install postgresql-client (Ubuntu)${NC}"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating Python virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
echo -e "${BLUE}Activating virtual environment...${NC}"
source venv/bin/activate

# Install dependencies
echo -e "${BLUE}Installing Python dependencies...${NC}"
pip install -r requirements.txt

# Check if .env file exists
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo -e "${YELLOW}Creating .env file from .env.example...${NC}"
        cp .env.example .env
        echo -e "${YELLOW}⚠️  Please edit .env file and add your API keys${NC}"
    else
        echo -e "${RED}❌ No .env file found. Please create one with your configuration.${NC}"
        exit 1
    fi
fi

# Load environment variables
if [ -f ".env" ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Start Redis if not running
if ! is_service_running "redis-server"; then
    echo -e "${BLUE}Starting Redis server...${NC}"
    redis-server --daemonize yes
    wait_for_service "Redis" "redis-cli ping"
else
    echo -e "${GREEN}✅ Redis is already running${NC}"
fi

# Check PostgreSQL connection
echo -e "${BLUE}Checking PostgreSQL connection...${NC}"
if ! python3 -c "
import os
import psycopg2
try:
    conn = psycopg2.connect(os.getenv('DATABASE_URL', 'postgresql://postgres:password@localhost:5432/bug_hunter'))
    conn.close()
    print('PostgreSQL connection successful')
except Exception as e:
    print(f'PostgreSQL connection failed: {e}')
    exit(1)
"; then
    echo -e "${RED}❌ PostgreSQL connection failed${NC}"
    echo -e "${YELLOW}Please ensure PostgreSQL is running and DATABASE_URL is correct in .env${NC}"
    exit 1
fi

# Initialize database
echo -e "${BLUE}Initializing database...${NC}"
python3 scripts/init_db.py

# Install Playwright browsers (for screenshots)
echo -e "${BLUE}Installing Playwright browsers...${NC}"
playwright install chromium

# Start Celery worker in background
echo -e "${BLUE}Starting Celery worker...${NC}"
celery -A automation.orchestrator worker --loglevel=info --detach --pidfile=celery_worker.pid

# Wait for Celery to be ready
wait_for_service "Celery" "celery -A automation.orchestrator inspect ping"

# Start Celery beat scheduler (for periodic tasks)
echo -e "${BLUE}Starting Celery beat scheduler...${NC}"
celery -A automation.orchestrator beat --loglevel=info --detach --pidfile=celery_beat.pid

# Start the API server
echo -e "${BLUE}Starting API server...${NC}"
echo -e "${GREEN}🎉 All services started successfully!${NC}"
echo -e "${BLUE}API Documentation: http://localhost:8000/docs${NC}"
echo -e "${BLUE}API Health Check: http://localhost:8000/health${NC}"
echo ""
echo -e "${YELLOW}To stop services, run: ./scripts/stop_services.sh${NC}"
echo ""

# Start the API server (this will run in foreground)
python3 -m uvicorn ui.api:app --host 0.0.0.0 --port 8000 --reload
