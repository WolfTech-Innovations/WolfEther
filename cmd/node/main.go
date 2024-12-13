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
	InitialSupply        = "1000000000000000000000" // Total supply of WLF (1,000 WLF with 18 decimals)
	DefaultWalletBalance = "100000000000000"        // Default balance for new wallets (0.0000001 WLF)
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
}

// Account represents the state of a single address in the blockchain.
type Account struct {
	Address     common.Address // Account address
	Balance     *big.Int       // Current balance
	Nonce       uint64         // Nonce for transaction replay protection
	StorageRoot []byte         // Root hash of account storage (optional)
	CodeHash    []byte         // Hash of account's contract code (optional)
}

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

// corsMiddleware adds CORS headers to HTTP responses.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
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

// startRPCServer initializes and runs the JSON-RPC server.
func startRPCServer(blockchain *Blockchain) {
	rpcHandler := NewRPCHandler(blockchain)
	http.Handle("/get_block", corsMiddleware(http.HandlerFunc(rpcHandler.handleGetBlock)))
	http.Handle("/eth_chainId", corsMiddleware(http.HandlerFunc(rpcHandler.handleGetChainID)))
	http.Handle("/metamask_transaction", corsMiddleware(http.HandlerFunc(rpcHandler.handleMetaMaskTransaction)))
	http.Handle("/create_wallet", corsMiddleware(http.HandlerFunc(rpcHandler.handleCreateWallet)))

	logrus.Info("Starting RPC server at port 8545")
	log.Fatal(http.ListenAndServe(":8545", nil))
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

	go startRPCServer(blockchain)

	select {}
}
