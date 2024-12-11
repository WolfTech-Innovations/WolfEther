#!/bin/bash

# Blockchain Node Runner Script
# Provides comprehensive management for blockchain node operations

# Configuration and Environment
CONFIG_DIR="../"
LOG_DIR="$CONFIG_DIR/logs"
DATA_DIR="$CONFIG_DIR/data"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    # Ensure log directory exists
    mkdir -p "$LOG_DIR"
    
    # Write to log file
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/node.log"
    
    # Print to console based on log level
    case $level in
        "ERROR")
            echo -e "${RED}[ERROR] $message${NC}" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN] $message${NC}"
            ;;
        "INFO")
            echo -e "${GREEN}[INFO] $message${NC}"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

# Validate system requirements
validate_system() {
    # Check Go version
    if ! command -v go &> /dev/null; then
        log "ERROR" "Go is not installed"
        exit 1
    fi

    GO_VERSION=$(go version | awk '{print $3}')
    REQUIRED_GO_VERSION="go1.21"
    
    if [[ "$(printf '%s\n' "$REQUIRED_GO_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_GO_VERSION" ]]; then
        log "ERROR" "Unsupported Go version. Required: $REQUIRED_GO_VERSION, Current: $GO_VERSION"
        exit 1
    fi

    # Check available disk space
    REQUIRED_SPACE=$((10 * 1024 * 1024 * 1024)) # 10GB
    AVAILABLE_SPACE=$(df -B1 "$CONFIG_DIR" | awk 'NR==2 {print $4}')
    
    if [[ $AVAILABLE_SPACE -lt $REQUIRED_SPACE ]]; then
        log "ERROR" "Insufficient disk space. Required: 10GB"
        exit 1
    fi
}

# Initialize node configuration
initialize_node() {
    log "INFO" "Initializing blockchain node configuration"
    
    # Create necessary directories
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"
    
    # Generate node configuration
    go run cmd/config/generate.go \
        --config-dir "$CONFIG_DIR" \
        --data-dir "$DATA_DIR"
    
    if [[ $? -ne 0 ]]; then
        log "ERROR" "Failed to generate node configuration"
        exit 1
    fi
}

# Check if the node process is running
is_node_running() {
    pgrep -f "cmd/node/main.go --config $CONFIG_DIR/config.yaml"
}

# Start the blockchain node
start_node() {
    validate_system

    # Check if node is already running
    if is_node_running &>/dev/null; then
        log "WARN" "Node is already running"
        return 1
    fi
    
    log "INFO" "Starting blockchain node"
    
    # Run node with comprehensive flags
    go run cmd/node/main.go \
        --config "$CONFIG_DIR/config.yaml" \
        --data-dir "$DATA_DIR" \
        --log-level debug \
        --metrics-port 9090 \
        --p2p-port 8080 \
        --validator-mode \
        > "$LOG_DIR/node_output.log" 2>&1 & 
    
    NODE_PID=$!
    sleep 5
    if kill -0 "$NODE_PID" 2>/dev/null; then
        log "INFO" "Node started successfully. PID: $NODE_PID"
    else
        log "ERROR" "Failed to start node"
        return 1
    fi
}

# Stop the blockchain node
stop_node() {
    NODE_PID=$(is_node_running)
    if [[ -z "$NODE_PID" ]]; then
        log "WARN" "No running node found"
        return 0
    fi
    
    log "INFO" "Stopping blockchain node"
    
    # Graceful shutdown attempt
    kill -SIGTERM "$NODE_PID"
    
    # Wait for graceful shutdown
    for i in {1..10}; do
        if ! kill -0 "$NODE_PID" 2>/dev/null; then
            log "INFO" "Node stopped successfully"
            return 0
        fi
        sleep 1
    done
    
    # Force kill if graceful shutdown fails
    kill -SIGKILL "$NODE_PID" 2>/dev/null
    log "WARN" "Node forcefully terminated"
}

# Backup blockchain data
backup_data() {
    BACKUP_DIR="$CONFIG_DIR/backups/$(date +"%Y%m%d_%H%M%S")"
    
    log "INFO" "Creating blockchain data backup"
    
    mkdir -p "$BACKUP_DIR"
    cp -R "$DATA_DIR"/* "$BACKUP_DIR"
    
    log "INFO" "Backup created at $BACKUP_DIR"
}

# Main script logic
case "$1" in
    start)
        start_node
        ;;
    stop)
        stop_node
        ;;
    restart)
        stop_node
        start_node
        ;;
    initialize)
        initialize_node
        ;;
    backup)
        backup_data
        ;;
    status)
        if is_node_running &>/dev/null; then
            log "INFO" "Node is running"
        else
            log "INFO" "No node is currently running"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|initialize|backup|status}"
        exit 1
esac

exit 0
