package WalletDaemon

import (
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"time"
    "bufio"
)

func setupDatabase() {
	// Create or connect to the SQLite database
	conn, err := sql.Open("sqlite3", "wallets.db")
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer conn.Close()

	// Create a table to store wallet data if it doesn't already exist
	_, err = conn.Exec(`
        CREATE TABLE IF NOT EXISTS wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT NOT NULL,
            balance TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `)
	if err != nil {
		fmt.Println("Error creating table:", err)
		return
	}

	fmt.Println("Database and table are set up.")
}

func monitorTty() {
	// Regular expression to match "Wallet created:" lines with address and balance
	walletRegex := regexp.MustCompile(`Wallet created: Address ([0-9a-fA-Fx]+) Default Balance ([0-9.]+)`)

	for {
		for _, tty := range getTtyDevices() { // Get tty devices
			ttyPath := fmt.Sprintf("/dev/%s", tty)
			file, err := os.Open(ttyPath)
			if err != nil {
				continue
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				match := walletRegex.FindStringSubmatch(line)
				if match != nil {
					address := match[1]
					balance := match[2]
					saveWallet(address, balance)
				}
			}
		}
		time.Sleep(1 * time.Second) // Reduce CPU usage by waiting before rescanning
	}
}

func getTtyDevices() []string {
	var ttyDevices []string
	files, err := os.ReadDir("/dev")
	if err != nil {
		fmt.Println("Error reading /dev:", err)
		return nil
	}

	for _, file := range files {
		if file.IsDir() && len(file.Name()) > 3 && file.Name()[:3] == "tty" {
			ttyDevices = append(ttyDevices, file.Name())
		}
	}
	return ttyDevices
}

func saveWallet(address, balance string) {
	conn, err := sql.Open("sqlite3", "wallets.db")
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer conn.Close()

	_, err = conn.Exec("INSERT INTO wallets (address, balance) VALUES (?, ?)", address, balance)
	if err != nil {
		fmt.Println("Error saving wallet:", err)
	}
}

func main() {
	setupDatabase()
	fmt.Println("Starting to monitor tty devices for wallet creation logs...")
	monitorTty()
	select {} 
}

