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
