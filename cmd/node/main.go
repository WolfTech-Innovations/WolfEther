package main

import (
	"crypto/sha256"
	 _"embed"
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
	"github.com/WolfTech-Innovations/WolfEther/cmd/node/Bridge/Bridge"
)

const indexHTML = `WolfEther 1.0.4 Blockchain running on Port 8545`

const (
	// Network and Blockchain Configuration
	WolfEtherVersion     = "1.0.4"                  // Current version of the WolfEther blockchain
	NetworkID            = 468                   // Unique ID for the network
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

type UTXO struct {
    TxID    string
    Index   uint32
    Value   *big.Int
    Address common.Address
}


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

type RPCResponse struct {
    Result string `json:"result"`
    Error  string `json:"error,omitempty"`
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
	stakes map[common.Address]*Stake // Map for user stakes
}

type LiquidityPool struct {
    PoolTokens     *big.Int
    Token1Balance  *big.Int
    Token2Balance  *big.Int
    LiquidityProviders map[common.Address]*big.Int
}

var liquidityPool LiquidityPool

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
	    // Set the content type to application/json for MetaMask compatibility
		w.Header().Set("Content-Type", "application/json")
    
		// Return the Chain ID for WolfEther (0x1D4)
		w.Write([]byte(`{"id":1, "result":"0x1D4"}`))
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

func (rpc *RPCHandler) handleStake(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Address string `json:"address"`
		Amount  string `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	addr := common.HexToAddress(request.Address)
	amount, _ := new(big.Int).SetString(request.Amount, 10)

	rpc.blockchain.stateMutex.Lock()
	defer rpc.blockchain.stateMutex.Unlock()

	account, exists := rpc.blockchain.accountState[addr]
	if !exists || account.Balance.Cmp(amount) < 0 {
		http.Error(w, "Insufficient balance or account not found", http.StatusBadRequest)
		return
	}

	// Lock funds and record stake
	account.Balance.Sub(account.Balance, amount)
	rpc.blockchain.stakes[addr] = &Stake{Amount: amount, StakedAt: time.Now(), Rewards: big.NewInt(0)}
	rpc.blockchain.saveBlockchain()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Stake recorded"))
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

// Calculate staking rewards periodically (e.g., every block or set time interval)
func (bc *Blockchain) calculateStakingRewards() {
    for addr, stake := range bc.stakes {
        _ = addr

		// Calculate reward
        rewardAmount := new(big.Int).Mul(stake.Amount, big.NewInt(StakingReward))
        rewardAmount.Div(rewardAmount, big.NewInt(100)) // StakingReward is in percentage

        stake.Rewards.Add(stake.Rewards, rewardAmount)
    }
}


// Add liquidity to the pool
func (rpc *RPCHandler) handleAddLiquidity(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var liquidityRequest struct {
        Address string `json:"address"`
        Token1Amount string `json:"token1_amount"`
        Token2Amount string `json:"token2_amount"`
    }

    if err := json.NewDecoder(r.Body).Decode(&liquidityRequest); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    addr := common.HexToAddress(liquidityRequest.Address)
    token1Amount, _ := new(big.Int).SetString(liquidityRequest.Token1Amount, 10)
    token2Amount, _ := new(big.Int).SetString(liquidityRequest.Token2Amount, 10)

    rpc.blockchain.stateMutex.Lock()
    defer rpc.blockchain.stateMutex.Unlock()

    account, exists := rpc.blockchain.accountState[addr]
    if !exists {
        http.Error(w, "Account not found", http.StatusNotFound)
        return
    }

    // Ensure account has enough tokens
    if account.Balance.Cmp(token1Amount) < 0 || account.Balance.Cmp(token2Amount) < 0 {
        http.Error(w, "Insufficient balance", http.StatusBadRequest)
        return
    }

    // Lock the tokens into the liquidity pool
    account.Balance.Sub(account.Balance, token1Amount)
    account.Balance.Sub(account.Balance, token2Amount)

    liquidityPool.Token1Balance.Add(liquidityPool.Token1Balance, token1Amount)
    liquidityPool.Token2Balance.Add(liquidityPool.Token2Balance, token2Amount)
    liquidityPool.LiquidityProviders[addr] = new(big.Int).Add(liquidityPool.LiquidityProviders[addr], token1Amount)

    rpc.blockchain.saveBlockchain()

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Liquidity added successfully"))
}

func (handler *RPCHandler) handleGetGasPrice(w http.ResponseWriter, r *http.Request) {
    // Return zero Gwei since it's gasless
    gasPrice := "0x0"  // 0 Gwei in hex
    response := RPCResponse{Result: gasPrice}
    json.NewEncoder(w).Encode(response)
}

func (handler *RPCHandler) handleEstimateGas(w http.ResponseWriter, r *http.Request) {
    // Since it's gasless, the estimation would also be zero
    gasEstimate := "0x0"  // 0 gas in hex
    response := RPCResponse{Result: gasEstimate}
    json.NewEncoder(w).Encode(response)
}

func (handler *RPCHandler) handleCall(w http.ResponseWriter, r *http.Request) {
    var params []interface{}
    if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    mockResult := "0x0000000000000000000000000000000000000000"
    response := RPCResponse{Result: mockResult}
    json.NewEncoder(w).Encode(response)
}


// handleMetaTransaction allows users to send transactions without paying gas fees
func (rpc *RPCHandler) handleMetaTransaction(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var tx Transaction
    if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    // Signature validation and processing as usual
    hash := sha256.Sum256([]byte(fmt.Sprintf("%s%s%d", tx.From.Hex(), tx.To.Hex(), tx.Value)))
    pubKey, err := crypto.SigToPub(hash[:], tx.Signature)
    if err != nil || crypto.PubkeyToAddress(*pubKey) != tx.From {
        http.Error(w, "Invalid transaction signature", http.StatusBadRequest)
        return
    }

    // Process transaction as if gas was paid by another account (skip gas deduction)
    senderAccount := rpc.blockchain.accountState[tx.From]
    receiverAccount := rpc.blockchain.accountState[tx.To]

    if senderAccount == nil || receiverAccount == nil {
        http.Error(w, "Account not found", http.StatusNotFound)
        return
    }

    senderAccount.Balance.Sub(senderAccount.Balance, tx.Value)
    receiverAccount.Balance.Add(receiverAccount.Balance, tx.Value)

    rpc.blockchain.transactionPool = append(rpc.blockchain.transactionPool, &tx)
    rpc.blockchain.saveBlockchain()

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Meta transaction processed successfully"))
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
    http.Handle("/api/metaTransaction", corsMiddleware(http.HandlerFunc(rpcHandler.handleMetaTransaction))) // Gas-less transactions
    http.Handle("/eth_staking", corsMiddleware(http.HandlerFunc(rpcHandler.handleStake)))
    http.Handle("/eth_gasPrice", corsMiddleware(http.HandlerFunc(rpcHandler.handleGetGasPrice)))
    http.Handle("/eth_call", corsMiddleware(http.HandlerFunc(rpcHandler.handleCall)))
    http.Handle("/eth_estimateGas", corsMiddleware(http.HandlerFunc(rpcHandler.handleEstimateGas)))
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
		adminWallet = common.HexToAddress("0xWLF")
		logrus.Info(adminWallet)
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
