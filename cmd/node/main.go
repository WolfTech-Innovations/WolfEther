package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mattn/go-colorable"
	"github.com/sirupsen/logrus"
)

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blockchain WebUI</title>
    <style>
        /* General Styles */
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f9;
            color: #333;
            margin: 0;
            padding: 0;
        }
        .container {
            width: 80%;
            margin: 0 auto;
            padding: 20px;
            max-width: 1200px;
        }
        h1 {
            text-align: center;
            font-size: 2em;
            margin-bottom: 30px;
            color: #2c3e50;
        }
        .section {
            background-color: white;
            margin-bottom: 20px;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        h2 {
            font-size: 1.6em;
            margin-bottom: 15px;
            color: #3498db;
        }
        input {
            padding: 10px;
            margin: 5px;
            width: 100%;
            max-width: 300px;
            border: 1px solid #ccc;
            border-radius: 4px;
            margin-bottom: 15px;
            font-size: 1em;
        }
        button {
            padding: 12px 20px;
            border: none;
            background-color: #007BFF;
            color: white;
            font-size: 1.1em;
            cursor: pointer;
            border-radius: 4px;
            transition: background-color 0.3s ease;
        }
        button:hover {
            background-color: #0056b3;
        }
        p {
            font-size: 1.2em;
            color: #333;
        }
        .response {
            margin-top: 15px;
            padding: 10px;
            background-color: #eaf7e6;
            border: 1px solid #2ecc71;
            border-radius: 4px;
            color: #2ecc71;
            font-weight: bold;
        }
        .error {
            background-color: #f8d7da;
            border-color: #dc3545;
            color: #dc3545;
        }
        .input-group {
            display: flex;
            flex-direction: column;
            margin-bottom: 20px;
        }
        .input-group input {
            width: 100%;
        }
        .input-group button {
            width: 100%;
        }
        .section-info {
            display: flex;
            justify-content: space-between;
        }
    </style>
</head>
<body>

    <div class="container">
        <h1>Blockchain WebUI</h1>

        <!-- Create Wallet -->
        <div class="section">
            <h2>Create Wallet</h2>
            <button id="createWalletBtn">Create Wallet</button>
            <p id="walletDetails" class="response"></p>
        </div>

        <!-- View Balance -->
        <div class="section">
            <h2>View Balance</h2>
            <div class="input-group">
                <input type="text" id="viewBalanceAddress" placeholder="Enter wallet address">
                <button id="viewBalanceBtn">View Balance</button>
            </div>
            <p id="balanceDetails" class="response"></p>
        </div>

        <!-- Send Transaction -->
        <div class="section">
            <h2>Send Transaction</h2>
            <div class="input-group">
                <input type="text" id="senderAddress" placeholder="Sender Address">
                <input type="text" id="receiverAddress" placeholder="Receiver Address">
                <input type="text" id="amount" placeholder="Amount">
                <button id="sendTransactionBtn">Send Transaction</button>
            </div>
            <p id="transactionStatus" class="response"></p>
        </div>

        <!-- Blockchain Info -->
        <div class="section">
            <h2>Blockchain Info</h2>
            <div class="section-info">
                <button id="getBlockNumberBtn">Get Block Number</button>
                <button id="getChainIdBtn">Get Chain ID</button>
            </div>
            <p id="blockNumber" class="response"></p>
            <p id="chainId" class="response"></p>
        </div>
    </div>

    <script>
        // Get the server IP address dynamically
        const apiUrl = ` + "`http://${window.location.hostname}:8545`" + `; // Automatically uses the current server's IP and port 8545

        // Create Wallet
        document.getElementById('createWalletBtn').addEventListener('click', () => {
            fetch(` + "`${apiUrl}/create_wallet`" + `, { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('walletDetails').innerText = ` + "`Address: ${data.address}, Private Key: ${data.private_key}`" + `;
                    document.getElementById('walletDetails').classList.remove('error');
                    document.getElementById('walletDetails').classList.add('response');
                })
                .catch(error => {
                    document.getElementById('walletDetails').innerText = 'Error creating wallet.';
                    document.getElementById('walletDetails').classList.remove('response');
                    document.getElementById('walletDetails').classList.add('error');
                });
        });

        // View Balance
        document.getElementById('viewBalanceBtn').addEventListener('click', () => {
            const address = document.getElementById('viewBalanceAddress').value;
            fetch(` + "`${apiUrl}/eth_getBalance?address=${address}`" + `, { method: 'GET' })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('balanceDetails').innerText = ` + "`Balance: ${data.balance} WLF`" + `;
                    document.getElementById('balanceDetails').classList.remove('error');
                    document.getElementById('balanceDetails').classList.add('response');
                })
                .catch(error => {
                    document.getElementById('balanceDetails').innerText = 'Error fetching balance.';
                    document.getElementById('balanceDetails').classList.remove('response');
                    document.getElementById('balanceDetails').classList.add('error');
                });
        });

        // Send Transaction
        document.getElementById('sendTransactionBtn').addEventListener('click', () => {
            const sender = document.getElementById('senderAddress').value;
            const receiver = document.getElementById('receiverAddress').value;
            const amount = document.getElementById('amount').value;

            const transaction = { from: sender, to: receiver, value: amount };

            fetch(` + "`${apiUrl}/eth_sendTransaction`" + `, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(transaction),
            })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('transactionStatus').innerText = ` + "`Transaction Status: ${data.result}`" + `;
                    document.getElementById('transactionStatus').classList.remove('error');
                    document.getElementById('transactionStatus').classList.add('response');
                })
                .catch(error => {
                    document.getElementById('transactionStatus').innerText = 'Error sending transaction.';
                    document.getElementById('transactionStatus').classList.remove('response');
                    document.getElementById('transactionStatus').classList.add('error');
                });
        });

        // Get Block Number
        document.getElementById('getBlockNumberBtn').addEventListener('click', () => {
            fetch(` + "`${apiUrl}/eth_blockNumber`" + `, { method: 'GET' })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('blockNumber').innerText = ` + "`Current Block Number: ${data.blockNumber}`" + `;
                    document.getElementById('blockNumber').classList.remove('error');
                    document.getElementById('blockNumber').classList.add('response');
                })
                .catch(error => {
                    document.getElementById('blockNumber').innerText = 'Error fetching block number.';
                    document.getElementById('blockNumber').classList.remove('response');
                    document.getElementById('blockNumber').classList.add('error');
                });
        });

        // Get Chain ID
        document.getElementById('getChainIdBtn').addEventListener('click', () => {
            fetch(` + "`${apiUrl}/eth_chainId`" + `, { method: 'GET' })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('chainId').innerText = ` + "`Chain ID: ${data.chainId}`" + `;
                    document.getElementById('chainId').classList.remove('error');
                    document.getElementById('chainId').classList.add('response');
                })
                .catch(error => {
                    document.getElementById('chainId').innerText = 'Error fetching chain ID.';
                    document.getElementById('chainId').classList.remove('response');
                    document.getElementById('chainId').classList.add('error');
                });
        });
    </script>

</body>
</html>`

const (
	// Network and Blockchain Configuration
	WolfEtherVersion     = "1.0.0"                  // Current version of the WolfEther blockchain
	NetworkID            = 1337                     // Unique ID for the network
	DefaultPort          = 30303                    // Default port for peer-to-peer communication
	BlockReward          = 50                       // Reward for mining a block
	DifficultyTarget     = 4                        // Proof-of-Work difficulty target
	BlockTime            = 15                       // Expected time (in seconds) per block
	MaxBlockTransactions = 100                      // Maximum number of transactions per block
	BlockchainDBPath     = "./blockchain_data.json" // Path to save blockchain data
	WolfCoinName         = "Wolf"                   // Name of the cryptocurrency
	WolfTicker           = "WLF"                    // Ticker symbol for the cryptocurrency
	WolfDecimals         = 18                       // Decimal precision for the cryptocurrency
	InitialSupply        = "1000000000000000000000000" // Total supply of WLF (1M WLF with 18 decimals)
	DefaultWalletBalance = "0.000000000001"        // Default balance for new wallets (0.0000001 WLF)
	StakingReward        = 5                        // Annual staking reward in WLF (in percentage)
	StakingPeriod        = 365                      // Staking period in days
)

var (
	blockchain   *Blockchain // Global blockchain instance
	adminWallet  common.Address
	adminBalance *big.Int
)

// Block represents a single block in the blockchain.
type Block struct {
	Header       BlockHeader    // Metadata about the block
	Transactions []*Transaction // List of transactions included in the block
	Signature    []byte         // Digital signature of the block
	Hash         []byte         // Block hash
	Nonce        uint64         // Nonce used for mining
}

// BlockHeader contains metadata for a block.
type BlockHeader struct {
	Version          uint32         // Version of the block format
	PreviousHash     []byte         // Hash of the previous block
	MerkleRoot       []byte         // Merkle root of transactions
	Timestamp        uint64         // Block creation timestamp
	Height           uint64         // Block height in the chain
	DifficultyTarget uint32         // Difficulty target for mining
	Coinbase         common.Address // Address receiving the block reward
}

// Transaction represents a transfer of value between accounts.
type Transaction struct {
	From      common.Address // Sender address
	To        common.Address // Receiver address
	Value     *big.Int       // Amount being transferred
	Nonce     uint64         // Nonce to ensure unique transactions
	Signature []byte         // Digital signature of the transaction
	CreatedAt time.Time      // Timestamp when the transaction was created
}

// Blockchain is the main structure representing the chain of blocks.
type Blockchain struct {
	chain           []*Block                    // List of all blocks
	accountState    map[common.Address]*Account // State of all accounts
	transactionPool []*Transaction              // Pending transactions
	stateMutex      sync.RWMutex                // Mutex for thread-safe access
	difficulty      *big.Int                    // Current difficulty target
	stakes          map[common.Address]*Stake   // Stake map to track user stakes
}

// Account represents the state of a single address in the blockchain.
type Account struct {
	Address     common.Address // Account address
	Balance     *big.Int       // Current balance
	Nonce       uint64         // Nonce for transaction replay protection
	StorageRoot []byte         // Root hash of account storage (optional)
	CodeHash    []byte         // Hash of account's contract code (optional)
}

// Stake represents the staking details of an account.
type Stake struct {
	Amount       *big.Int      // Amount staked by the user
	StakedAt     time.Time     // Time when the stake was made
	Rewards      *big.Int      // Rewards earned by the user
	LockDuration time.Duration // Duration for which the tokens are locked
}

// RPCHandler handles JSON-RPC requests.
// RPCHandler handles JSON-RPC requests.
type RPCHandler struct {
	blockchain *Blockchain // Blockchain instance to handle requests
}

// NewRPCHandler creates a new instance of the RPCHandler.
func NewRPCHandler(blockchain *Blockchain) *RPCHandler {
	return &RPCHandler{
		blockchain: blockchain,
	}
}

// handleGetChainID responds with the network's Chain ID.
func (rpc *RPCHandler) handleGetChainID(w http.ResponseWriter, r *http.Request) {
	response := struct {
		ChainID int `json:"chain_id"`
	}{
		ChainID: NetworkID,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGetBlock retrieves block details by height.
func (rpc *RPCHandler) handleGetBlock(w http.ResponseWriter, r *http.Request) {
	blockHeight := r.URL.Query().Get("height")
	height, err := strconv.Atoi(blockHeight)
	if err != nil {
		http.Error(w, "Invalid block height", http.StatusBadRequest)
		return
	}

	if height < 0 || height >= len(rpc.blockchain.chain) {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}

	block := rpc.blockchain.chain[height]
	response := struct {
		Height       uint64         `json:"height"`
		PreviousHash string         `json:"previous_hash"`
		Transactions []*Transaction `json:"transactions"`
	}{
		Height:       block.Header.Height,
		PreviousHash: fmt.Sprintf("%x", block.Header.PreviousHash),
		Transactions: block.Transactions,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleMetaMaskTransaction handles transactions sent from MetaMask.
func (rpc *RPCHandler) handleMetaMaskTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tx Transaction
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	hash := sha256.Sum256([]byte(fmt.Sprintf("%s%s%d", tx.From.Hex(), tx.To.Hex(), tx.Value)))
	pubKey, err := crypto.SigToPub(hash[:], tx.Signature)
	if err != nil || crypto.PubkeyToAddress(*pubKey) != tx.From {
		http.Error(w, "Invalid transaction signature", http.StatusBadRequest)
		return
	}

	rpc.blockchain.stateMutex.Lock()
	defer rpc.blockchain.stateMutex.Unlock()

	senderAccount := rpc.blockchain.accountState[tx.From]
	receiverAccount := rpc.blockchain.accountState[tx.To]

	if senderAccount == nil {
		http.Error(w, "Sender account not found", http.StatusBadRequest)
		return
	}

	if senderAccount.Balance.Cmp(tx.Value) < 0 {
		http.Error(w, "Insufficient balance", http.StatusBadRequest)
		return
	}

	if receiverAccount == nil {
		receiverAccount = &Account{
			Address: tx.To,
			Balance: big.NewInt(0),
		}
		rpc.blockchain.accountState[tx.To] = receiverAccount
	}

	senderAccount.Balance.Sub(senderAccount.Balance, tx.Value)
	receiverAccount.Balance.Add(receiverAccount.Balance, tx.Value)

	rpc.blockchain.transactionPool = append(rpc.blockchain.transactionPool, &tx)
	rpc.blockchain.saveBlockchain()

	logrus.Infof("Transaction processed: From %s To %s Value %s", tx.From.Hex(), tx.To.Hex(), tx.Value.String())

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Transaction processed successfully"))
}

// handleCreateWallet creates a new wallet and assigns default balance.
func (rpc *RPCHandler) handleCreateWallet(w http.ResponseWriter, r *http.Request) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		http.Error(w, "Failed to generate wallet", http.StatusInternalServerError)
		return
	}
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	rpc.blockchain.stateMutex.Lock()
	defer rpc.blockchain.stateMutex.Unlock()

	if _, exists := rpc.blockchain.accountState[address]; !exists {
		defaultBalance, _ := new(big.Int).SetString(DefaultWalletBalance, 10)
		rpc.blockchain.accountState[address] = &Account{
			Address: address,
			Balance: defaultBalance,
		}
	}

	response := struct {
		Address    string `json:"address"`
		PrivateKey string `json:"private_key"`
	}{
		Address:    address.Hex(),
		PrivateKey: fmt.Sprintf("%x", crypto.FromECDSA(privateKey)),
	}

	logrus.Infof("Wallet created: Address %s Default Balance %s", address.Hex(), DefaultWalletBalance)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGetBalance retrieves the balance of an address.
func (rpc *RPCHandler) handleGetBalance(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	addr := common.HexToAddress(address)

	rpc.blockchain.stateMutex.Lock()
	defer rpc.blockchain.stateMutex.Unlock()

	account, exists := rpc.blockchain.accountState[addr]
	if !exists {
		http.Error(w, "Account not found", http.StatusNotFound)
		return
	}

	response := struct {
		Balance string `json:"balance"`
	}{
		Balance: account.Balance.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleSendTransaction processes a transaction from one account to another.
func (rpc *RPCHandler) handleSendTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tx Transaction
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Verify signature
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s%s%d", tx.From.Hex(), tx.To.Hex(), tx.Value)))
	pubKey, err := crypto.SigToPub(hash[:], tx.Signature)
	if err != nil || crypto.PubkeyToAddress(*pubKey) != tx.From {
		http.Error(w, "Invalid transaction signature", http.StatusBadRequest)
		return
	}

	rpc.blockchain.stateMutex.Lock()
	defer rpc.blockchain.stateMutex.Unlock()

	// Process transaction
	senderAccount := rpc.blockchain.accountState[tx.From]
	receiverAccount := rpc.blockchain.accountState[tx.To]

	if senderAccount == nil || receiverAccount == nil {
		http.Error(w, "Account not found", http.StatusNotFound)
		return
	}

	if senderAccount.Balance.Cmp(tx.Value) < 0 {
		http.Error(w, "Insufficient balance", http.StatusBadRequest)
		return
	}

	senderAccount.Balance.Sub(senderAccount.Balance, tx.Value)
	receiverAccount.Balance.Add(receiverAccount.Balance, tx.Value)

	// Add to transaction pool
	rpc.blockchain.transactionPool = append(rpc.blockchain.transactionPool, &tx)
	rpc.blockchain.saveBlockchain()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Transaction processed successfully"))
}

// handleGetTransactionCount retrieves the nonce (transaction count) of an address.
func (rpc *RPCHandler) handleGetTransactionCount(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	addr := common.HexToAddress(address)

	rpc.blockchain.stateMutex.Lock()
	defer rpc.blockchain.stateMutex.Unlock()

	account, exists := rpc.blockchain.accountState[addr]
	if !exists {
		http.Error(w, "Account not found", http.StatusNotFound)
		return
	}

	response := struct {
		TransactionCount uint64 `json:"transaction_count"`
	}{
		TransactionCount: account.Nonce,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGetCode retrieves the code (smart contract bytecode) at a given address.
func (rpc *RPCHandler) handleGetCode(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	addr := common.HexToAddress(address)

	rpc.blockchain.stateMutex.Lock()
	defer rpc.blockchain.stateMutex.Unlock()

	account, exists := rpc.blockchain.accountState[addr]
	if !exists || len(account.CodeHash) == 0 {
		http.Error(w, "No code at this address", http.StatusNotFound)
		return
	}

	response := struct {
		Code string `json:"code"`
	}{
		Code: fmt.Sprintf("%x", account.CodeHash),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// saveBlockchain persists the blockchain state to a file.
func (bc *Blockchain) saveBlockchain() {
	data, err := json.MarshalIndent(bc, "", "  ")
	if err != nil {
		logrus.Errorf("Failed to save blockchain: %v", err)
		return
	}

	err = ioutil.WriteFile(BlockchainDBPath, data, 0644)
	if err != nil {
		logrus.Errorf("Failed to write blockchain file: %v", err)
	}
}

// loadBlockchain loads the blockchain state from a file.
func (bc *Blockchain) loadBlockchain() {
	if _, err := os.Stat(BlockchainDBPath); os.IsNotExist(err) {
		logrus.Info("Blockchain data file not found. Initializing new blockchain.")
		return
	}

	data, err := ioutil.ReadFile(BlockchainDBPath)
	if err != nil {
		logrus.Fatalf("Failed to read blockchain data file: %v", err)
	}

	err = json.Unmarshal(data, bc)
	if err != nil {
		logrus.Fatalf("Failed to parse blockchain data file: %v", err)
	}
}

// corsMiddleware handles CORS headers for cross-origin requests.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")                                              // Allow all origins
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")                            // Allow GET, POST, and OPTIONS methods
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With") // Allow necessary headers

		// Handle preflight OPTIONS request (for CORS)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// startRPCServer initializes and runs the JSON-RPC server.
func startRPCServer(blockchain *Blockchain) {
	rpcHandler := NewRPCHandler(blockchain)
	http.Handle("/eth_blockNumber", corsMiddleware(http.HandlerFunc(rpcHandler.handleGetBlock)))
	http.Handle("/eth_chainId", corsMiddleware(http.HandlerFunc(rpcHandler.handleGetChainID)))
	http.Handle("/metamask_transaction", corsMiddleware(http.HandlerFunc(rpcHandler.handleMetaMaskTransaction)))
	http.Handle("/create_wallet", corsMiddleware(http.HandlerFunc(rpcHandler.handleCreateWallet)))
	http.Handle("/eth_getBalance", corsMiddleware(http.HandlerFunc(rpcHandler.handleGetBalance)))
	http.Handle("/eth_sendTransaction", corsMiddleware(http.HandlerFunc(rpcHandler.handleSendTransaction)))
	http.Handle("/eth_getTransactionCount", corsMiddleware(http.HandlerFunc(rpcHandler.handleGetTransactionCount)))
	http.Handle("/eth_getCode", corsMiddleware(http.HandlerFunc(rpcHandler.handleGetCode)))

	logrus.Info("Starting RPC server at port 8545")
	log.Fatal(http.ListenAndServe("0.0.0.0:8545", nil)) // Listen on all interfaces
}

// initializeBlockchain sets up the blockchain, including the genesis block.
func initializeBlockchain() *Blockchain {
	blockchain := &Blockchain{
		accountState:    make(map[common.Address]*Account),
		transactionPool: []*Transaction{},
	}
	blockchain.loadBlockchain()
	if len(blockchain.chain) == 0 {
		adminWallet = common.HexToAddress("0x000000000000000000000000000000000000dead")
		adminBalance, _ = new(big.Int).SetString(InitialSupply, 10)
		blockchain.accountState[adminWallet] = &Account{
			Address: adminWallet,
			Balance: adminBalance,
		}

		genesisBlock := &Block{
			Header: BlockHeader{
				Version:          1,
				PreviousHash:     []byte{},
				Timestamp:        uint64(time.Now().Unix()),
				Height:           0,
				DifficultyTarget: DifficultyTarget,
			},
			Transactions: []*Transaction{},
		}
		blockchain.chain = append(blockchain.chain, genesisBlock)
		blockchain.saveBlockchain()
	}
	return blockchain
}

// main initializes the blockchain and starts the RPC server.
func main() {
	blockchain = initializeBlockchain()

	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
	})
	logrus.SetOutput(colorable.NewColorableStdout())
    blockchain.loadBlockchain()
	go startRPCServer(blockchain)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(indexHTML))
	})

	// Start the server
	port := ":8080"
	fmt.Printf("Starting server on port %s...\n", port)
	logrus.Info("Starting internal HTML server . . .")
	logrus.Info("Loading Modules . . .")
	logrus.Info("Server Started")
	if err := http.ListenAndServe(port, nil); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
		os.Exit(1)
			// Start periodic blockchain saving
	go func() {
		// Create a ticker that ticks every 10 seconds
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				blockchain.saveBlockchain()
				logrus.Info("Blockchain Saved")
			}
		}
	}()
		select {}
	}
}

// WolfTech Innovations: WolfEther Blockchain
// The WolfEther Blockchain is not to be misused (E.g Crime, Money laundring, scams, or any other crimes or misuse and or forms of abuse)  
// The WolfEther Blockchain is a work in progress but at a functional state and can be used to most extents
// All losses are at users fault, if you lose anything you cannot be paid for your loss if item is of value or otherwise
// As written here in the source, you hereby agree to theese terms once you use this software.
// Do not edit this if you fork this software, theese messages are important.