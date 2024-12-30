package bridge

import (
	"fmt"
	"log"
	"math/big"
	"sync"
)

// Transaction represents a blockchain transaction.
type Transaction struct {
	From         string
	To           string
	Amount       *big.Int
	Token        string
	ContractCall *ContractCall
}

// ContractCall represents a call to a smart contract.
type ContractCall struct {
	ContractAddress string
	Method          string
	Args            []interface{}
}


type Blockchain interface {
	GetLatestBlockHash() string
	ValidateTransaction(tx *Transaction) bool
	AddBlock(transactions []*Transaction, proposer string) error
	GetBalance(address string, token string) (*big.Int, error)
	ProcessBridgedTransaction(tx *Transaction) error
}

type BridgeManager struct {
	SourceChain      Blockchain
	DestinationChain Blockchain
	Mutex            sync.Mutex
}

func NewBridgeManager(src Blockchain, dest Blockchain) *BridgeManager {
	return &BridgeManager{
		SourceChain:      src,
		DestinationChain: dest,
	}
}

func (bm *BridgeManager) BridgeTransaction(tx *Transaction) error {
	bm.Mutex.Lock()
	defer bm.Mutex.Unlock()

	log.Printf("Bridging transaction from %s to %s: %+v", bm.SourceChain, bm.DestinationChain, tx)

	// Validate transaction on the source chain
	if !bm.SourceChain.ValidateTransaction(tx) {
		return fmt.Errorf("source chain validation failed for transaction: %+v", tx)
	}

	// Process the transaction on the destination chain
	if err := bm.DestinationChain.ProcessBridgedTransaction(tx); err != nil {
		return fmt.Errorf("failed to process transaction on destination chain: %v", err)
	}

	log.Printf("Transaction successfully bridged: %+v", tx)
	return nil
}

func (bm *BridgeManager) SynchronizeChains() error {
	bm.Mutex.Lock()
	defer bm.Mutex.Unlock()

	log.Printf("Synchronizing source (%s) and destination (%s) chains", bm.SourceChain, bm.DestinationChain)

	// Ensure source and destination chains have matching states
	sourceLatestHash := bm.SourceChain.GetLatestBlockHash()
	destLatestHash := bm.DestinationChain.GetLatestBlockHash()

	if sourceLatestHash != destLatestHash {
		return fmt.Errorf("chain state mismatch: source %s, destination %s", sourceLatestHash, destLatestHash)
	}

	log.Println("Chains synchronized successfully")
	return nil
}
