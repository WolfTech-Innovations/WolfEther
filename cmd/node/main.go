package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mattn/go-colorable"
	"github.com/sirupsen/logrus"
)

const (
	// Network Constants
	WolfEtherVersion     = "1.0.0"
	NetworkID            = 1337
	DefaultPort          = 30303
	BlockReward          = 50
	DifficultyTarget     = 4
	BlockTime            = 15
	MaxBlockTransactions = 100
	BlockchainDBPath     = "./blockchain_data"
)

var (
	// Simulating an in-memory "database"
	blockchain *Blockchain
)

type Block struct {
	Header       BlockHeader
	Transactions []*Transaction
	Signature    []byte
	Hash         []byte
	Nonce        uint64
}

type BlockHeader struct {
	Version          uint32
	PreviousHash     []byte
	MerkleRoot       []byte
	Timestamp        uint64
	Height           uint64
	DifficultyTarget uint32
	Coinbase         common.Address
}

type Transaction struct {
	From      common.Address
	To        common.Address
	Value     *big.Int
	Nonce     uint64
	Signature []byte
	CreatedAt time.Time
}

type Blockchain struct {
	chain           []*Block
	accountState    map[common.Address]*Account
	transactionPool []*Transaction
	stateMutex      sync.RWMutex
	difficulty      *big.Int
}

type Account struct {
	Address     common.Address
	Balance     *big.Int
	Nonce       uint64
	StorageRoot []byte
	CodeHash    []byte
}

type NetworkNode struct {
	Blockchain *Blockchain
}

type RPCHandler struct {
	blockchain *Blockchain
}

func NewRPCHandler(blockchain *Blockchain) *RPCHandler {
	return &RPCHandler{
		blockchain: blockchain,
	}
}

// Consensus and Block Addition
func (bc *Blockchain) AddBlock(block *Block) error {
	bc.stateMutex.Lock()
	defer bc.stateMutex.Unlock()

	bc.chain = append(bc.chain, block)
	for _, tx := range block.Transactions {
		if err := bc.processTransaction(tx); err != nil {
			return err
		}
	}

	logrus.WithFields(logrus.Fields{
		"block_height": block.Header.Height,
		"block_hash":   fmt.Sprintf("%x", block.Hash),
	}).Info("Added Block")
	return nil
}

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

func (rpc *RPCHandler) handleSendTransaction(w http.ResponseWriter, r *http.Request) {
	var tx Transaction
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		http.Error(w, "Invalid transaction data", http.StatusBadRequest)
		return
	}

	// Process the transaction
	err := rpc.blockchain.processTransaction(&tx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Return success response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Transaction processed"))
}

// Start the HTTP RPC server
func startRPCServer(blockchain *Blockchain) {
	rpcHandler := NewRPCHandler(blockchain)
	http.HandleFunc("/get_block", rpcHandler.handleGetBlock)
	http.HandleFunc("/send_transaction", rpcHandler.handleSendTransaction)
	logrus.Info("Starting RPC server at port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func initializeBlockchain() *Blockchain {
	genesisAccount := common.HexToAddress("0x0000000000000000000000000000000000000000")
	accountState := make(map[common.Address]*Account)
	accountState[genesisAccount] = &Account{
		Address: genesisAccount,
		Balance: big.NewInt(1000000),
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

	blockchain := &Blockchain{
		chain:           []*Block{genesisBlock},
		accountState:    accountState,
		transactionPool: []*Transaction{},
	}
	return blockchain
}

func (bc *Blockchain) mineBlock(block *Block) []byte {
	for nonce := uint64(0); ; nonce++ {
		block.Nonce = nonce
		blockHash := sha256.Sum256(bc.serializeBlock(block))
		if bc.isValidPoW(blockHash) {
			return blockHash[:]
		}
	}
}

func (bc *Blockchain) isValidPoW(blockHash [32]byte) bool {
	return true
}

func (bc *Blockchain) serializeBlock(block *Block) []byte {
	var serialized []byte
	serialized = append(serialized, block.Header.PreviousHash...)
	serialized = append(serialized, block.Header.MerkleRoot...)
	serialized = append(serialized, byte(block.Header.Timestamp))
	serialized = append(serialized, byte(block.Nonce))
	return serialized
}

// Gasless Transaction Processing (without gas fees)
func (bc *Blockchain) processTransaction(tx *Transaction) error {
	// Ensure the sender exists, create if necessary
	sender := bc.accountState[tx.From]
	if sender == nil {
		// Create the sender account with an initial balance of 0 if not found
		sender = &Account{
			Address: tx.From,
			Balance: new(big.Int), // Initial balance is 0
			Nonce:   0,            // Initial nonce
		}
		bc.accountState[tx.From] = sender
	}

	// Ensure the recipient exists, create if necessary
	recipient := bc.accountState[tx.To]
	if recipient == nil {
		// Create the recipient account with an initial balance of 0 if not found
		recipient = &Account{
			Address: tx.To,
			Balance: new(big.Int), // Initial balance 0
		}
		bc.accountState[tx.To] = recipient
	}

	// Check if the sender has enough balance for the transaction
	if sender.Balance.Cmp(tx.Value) < 0 {
		// Log the issue but don't quit
		fmt.Printf("Transaction from %s to %s failed due to insufficient funds.\n", tx.From.Hex(), tx.To.Hex())
		// Return an error indicating insufficient balance, don't stop execution
		return fmt.Errorf("insufficient balance for sender %s", tx.From.Hex())
	}

	// Update sender's balance and nonce
	sender.Balance.Sub(sender.Balance, tx.Value)
	sender.Nonce++

	// Update recipient's balance
	recipient.Balance.Add(recipient.Balance, tx.Value)

	// Log success of the transaction
	fmt.Printf("Transaction from %s to %s of value %s completed successfully.\n", tx.From.Hex(), tx.To.Hex(), tx.Value.String())

	return nil
}

// Create Block with Transactions
func (bc *Blockchain) CreateNewBlock(previousBlock *Block, transactions []*Transaction) *Block {
	block := &Block{
		Header: BlockHeader{
			Version:          1,
			PreviousHash:     previousBlock.Hash,
			Timestamp:        uint64(time.Now().Unix()),
			Height:           previousBlock.Header.Height + 1,
			DifficultyTarget: DifficultyTarget,
		},
		Transactions: transactions,
	}

	blockHash := bc.mineBlock(block)
	block.Hash = blockHash
	return block
}

// Ethereum Transaction Signing
func signTransaction(privateKey *ecdsa.PrivateKey, tx *Transaction) ([]byte, error) {
	txData := fmt.Sprintf("%s%s%s%s", tx.From.Hex(), tx.To.Hex(), tx.Value.String(), strconv.FormatUint(tx.Nonce, 10))
	hash := sha256.Sum256([]byte(txData))
	signature, err := crypto.Sign(hash[:], privateKey)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func generateWallet() (common.Address, *ecdsa.PrivateKey) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	return address, privateKey
}

func main() {
	// Initialize Blockchain
	blockchain = initializeBlockchain()

	// Set up Logging
	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
	})
	logrus.SetOutput(colorable.NewColorableStdout())

	// Start RPC Server in a goroutine so it runs asynchronously
	go startRPCServer(blockchain)

	// Generate Wallet
	address, privateKey := generateWallet()
	logrus.Infof("Generated wallet address: %s", address.Hex())

	// Create a new transaction
	tx := &Transaction{
		From:      address,
		To:        common.HexToAddress("0x0000000000000000000000000000000000000001"),
		Value:     big.NewInt(10),
		Nonce:     1,
		CreatedAt: time.Now(),
	}

	// Sign the transaction
	signature, err := signTransaction(privateKey, tx)
	if err != nil {
		logrus.Errorf("Failed to sign transaction: %v", err)
	} else {
		tx.Signature = signature
	}

	// Create and Add Block with Transaction if it was signed successfully
	if tx.Signature != nil {
		// Get the last block from the blockchain (this will be the most recent block)
		previousBlock := blockchain.chain[len(blockchain.chain)-1]

		// Create a new block with the transaction
		block := blockchain.CreateNewBlock(previousBlock, []*Transaction{tx})

		// Add the newly created block to the blockchain
		err = blockchain.AddBlock(block)
		if err != nil {
			logrus.Errorf("Failed to add block: %v", err)
		}
	}

	// Verbose Output on Blockchain State
	logrus.Info("Blockchain State:")
	for _, block := range blockchain.chain {
		logrus.Infof("Block Height: %d", block.Header.Height)
		for _, tx := range block.Transactions {
			logrus.Infof("Transaction from %s to %s: %s", tx.From.Hex(), tx.To.Hex(), tx.Value.String())
		}
	}

	// Block the main goroutine to keep the program running forever
	select {}
}
