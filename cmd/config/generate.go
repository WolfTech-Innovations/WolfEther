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
