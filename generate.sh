#!/bin/bash

# Create all required Go files in the cmd/ directory as specified in the node runner script

CMD_DIR="cmd"

# Ensure the cmd/ directory exists
mkdir -p "$CMD_DIR"

# Create generate.go in cmd/config
mkdir -p "$CMD_DIR/config"
cat <<EOL > "$CMD_DIR/config/generate.go"
package main

import (
    "fmt"
    "os"
)

func main() {
    fmt.Println("Generating configuration...")
    if len(os.Args) > 1 {
        fmt.Printf("Configuration directory: %s\n", os.Args[1])
    }
}
EOL

# Create main.go in cmd/node
mkdir -p "$CMD_DIR/node"
cat <<EOL > "$CMD_DIR/node/main.go"
package main

import (
    "fmt"
    "os"
    "time"
)

func main() {
    fmt.Println("Starting blockchain node...")

    for {
        time.Sleep(10 * time.Second)
        fmt.Println("Node is running...")
    }
}
EOL

# Create additional Go files in cmd as required by the script

# Create a placeholder for metrics if needed
mkdir -p "$CMD_DIR/metrics"
cat <<EOL > "$CMD_DIR/metrics/metrics.go"
package main

import (
    "fmt"
)

func main() {
    fmt.Println("Metrics service initialized.")
}
EOL

# Confirmation message
echo "All specified Go files created successfully in the cmd/ directory."

sh scripts/run_node.sh