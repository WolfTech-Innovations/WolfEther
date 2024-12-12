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
	// Network Constants
	WolfEtherVersion     = "1.0.0"
	NetworkID            = 1337
	DefaultPort          = 30303
	BlockReward          = 50
	DifficultyTarget     = 4
	BlockTime            = 15
	MaxBlockTransactions = 100
	BlockchainDBPath     = "./blockchain_data.json"
	WolfCoinName         = "Wolf"
	WolfTicker           = "WLF"
	WolfDecimals         = 18
)

var (
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

type RPCHandler struct {
	blockchain *Blockchain
}

func NewRPCHandler(blockchain *Blockchain) *RPCHandler {
	return &RPCHandler{
		blockchain: blockchain,
	}
}

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

func (rpc *RPCHandler) handleGetChainID(w http.ResponseWriter, r *http.Request) {
	response := struct {
		ChainID int `json:"chain_id"`
	}{
		ChainID: NetworkID,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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

func (rpc *RPCHandler) handleGaslessTransaction(w http.ResponseWriter, r *http.Request) {
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

	rpc.blockchain.transactionPool = append(rpc.blockchain.transactionPool, &tx)
	rpc.blockchain.saveBlockchain()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Transaction received"))
}

func (rpc *RPCHandler) handleNativeTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tx Transaction
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
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

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Transaction processed successfully"))
}

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

func startRPCServer(blockchain *Blockchain) {
	rpcHandler := NewRPCHandler(blockchain)
	http.Handle("/get_block", corsMiddleware(http.HandlerFunc(rpcHandler.handleGetBlock)))
	http.Handle("/get_chain_id", corsMiddleware(http.HandlerFunc(rpcHandler.handleGetChainID)))
	http.Handle("/gasless_transaction", corsMiddleware(http.HandlerFunc(rpcHandler.handleGaslessTransaction)))
	http.Handle("/native_transaction", corsMiddleware(http.HandlerFunc(rpcHandler.handleNativeTransaction)))

	logrus.Info("Starting RPC server at port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func initializeBlockchain() *Blockchain {
	blockchain := &Blockchain{
		accountState:    make(map[common.Address]*Account),
		transactionPool: []*Transaction{},
	}
	blockchain.loadBlockchain()
	if len(blockchain.chain) == 0 {
		genesisAccount := common.HexToAddress("0x0000000000000000000000000000000000000000")
		blockchain.accountState[genesisAccount] = &Account{
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
		blockchain.chain = append(blockchain.chain, genesisBlock)
		blockchain.saveBlockchain()
	}
	return blockchain
}

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
