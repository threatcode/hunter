#!/bin/bash

# AI Bug Hunter - Service Stop Script
# This script stops all the Bug Hunter framework services

set -e

echo "🛑 Stopping AI Bug Hunter services..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to stop a process by PID file
stop_by_pidfile() {
    local pidfile=$1
    local service_name=$2
    
    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${BLUE}Stopping $service_name (PID: $pid)...${NC}"
            kill "$pid"
            
            # Wait for process to stop
            local attempts=10
            while [ $attempts -gt 0 ] && kill -0 "$pid" 2>/dev/null; do
                sleep 1
                ((attempts--))
            done
            
            if kill -0 "$pid" 2>/dev/null; then
                echo -e "${YELLOW}Force killing $service_name...${NC}"
                kill -9 "$pid"
            fi
            
            echo -e "${GREEN}✅ $service_name stopped${NC}"
        else
            echo -e "${YELLOW}⚠️  $service_name PID file exists but process is not running${NC}"
        fi
        
        rm -f "$pidfile"
    else
        echo -e "${YELLOW}⚠️  No PID file found for $service_name${NC}"
    fi
}

# Function to stop processes by name
stop_by_name() {
    local process_name=$1
    local service_name=$2
    
    local pids=$(pgrep -f "$process_name" || true)
    if [ -n "$pids" ]; then
        echo -e "${BLUE}Stopping $service_name processes...${NC}"
        echo "$pids" | xargs kill
        
        # Wait a bit for graceful shutdown
        sleep 2
        
        # Force kill if still running
        local remaining_pids=$(pgrep -f "$process_name" || true)
        if [ -n "$remaining_pids" ]; then
            echo -e "${YELLOW}Force killing remaining $service_name processes...${NC}"
            echo "$remaining_pids" | xargs kill -9
        fi
        
        echo -e "${GREEN}✅ $service_name stopped${NC}"
    else
        echo -e "${YELLOW}⚠️  No $service_name processes found${NC}"
    fi
}

# Stop Celery worker
stop_by_pidfile "celery_worker.pid" "Celery Worker"

# Stop Celery beat
stop_by_pidfile "celery_beat.pid" "Celery Beat"

# Stop any remaining Celery processes
stop_by_name "celery.*automation.orchestrator" "Celery"

# Stop API server
stop_by_name "uvicorn.*ui.api:app" "API Server"

# Stop any remaining Python processes related to the project
stop_by_name "python.*ui/api.py" "API Server (alternative)"

# Optionally stop Redis (only if we started it)
read -p "Do you want to stop Redis server? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if pgrep redis-server >/dev/null; then
        echo -e "${BLUE}Stopping Redis server...${NC}"
        redis-cli shutdown || true
        echo -e "${GREEN}✅ Redis stopped${NC}"
    else
        echo -e "${YELLOW}⚠️  Redis is not running${NC}"
    fi
fi

# Clean up any remaining PID files
rm -f celery_worker.pid celery_beat.pid

echo -e "${GREEN}🎉 All services stopped successfully!${NC}"
