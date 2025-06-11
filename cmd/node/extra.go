package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// ================= NFT STRUCTURES =================
type NFT struct {
	ID       string `json:"id"`
	Owner    string `json:"owner"`
	Metadata string `json:"metadata"`
}

var (
	nftStore = make(map[string]NFT)
	nftLock  sync.Mutex
)

// ================= GOVERNANCE STRUCTURES =================
type Proposal struct {
	ID           string         `json:"id"`
	Title        string         `json:"title"`
	Description  string         `json:"description"`
	Deadline     int64          `json:"deadline"`
	VotesFor     int            `json:"votes_for"`
	VotesAgainst int            `json:"votes_against"`
	Voters       map[string]bool `json:"voters"`
}

var (
	govStore = make(map[string]*Proposal)
	govLock  sync.Mutex
)

// ================= NFT FUNCTIONS =================
func MintNFT(owner, metadata string) NFT {
	nftLock.Lock()
	defer nftLock.Unlock()

	hash := sha256.Sum256([]byte(metadata + time.Now().String() + string(rand.Int())))
	id := hex.EncodeToString(hash[:])[:12]

	nft := NFT{
		ID:       id,
		Owner:    owner,
		Metadata: metadata,
	}
	nftStore[id] = nft
	return nft
}

func TransferNFT(id, newOwner string) bool {
	nftLock.Lock()
	defer nftLock.Unlock()

	nft, ok := nftStore[id]
	if !ok {
		return false
	}
	nft.Owner = newOwner
	nftStore[id] = nft
	return true
}

func GetNFT(id string) (NFT, bool) {
	nftLock.Lock()
	defer nftLock.Unlock()

	nft, ok := nftStore[id]
	return nft, ok
}

// ================= GOVERNANCE FUNCTIONS =================
func CreateProposal(title, description string, durationSeconds int64) *Proposal {
	govLock.Lock()
	defer govLock.Unlock()

	idHash := sha256.Sum256([]byte(title + time.Now().String()))
	id := hex.EncodeToString(idHash[:])[:12]

	p := &Proposal{
		ID:          id,
		Title:       title,
		Description: description,
		Deadline:    time.Now().Unix() + durationSeconds,
		Voters:      make(map[string]bool),
	}
	govStore[id] = p
	return p
}

func VoteProposal(id, voter string, support bool) bool {
	govLock.Lock()
	defer govLock.Unlock()

	p, ok := govStore[id]
	if !ok || time.Now().Unix() > p.Deadline || p.Voters[voter] {
		return false
	}
	if support {
		p.VotesFor++
	} else {
		p.VotesAgainst++
	}
	p.Voters[voter] = true
	return true
}

func GetProposal(id string) (*Proposal, bool) {
	govLock.Lock()
	defer govLock.Unlock()

	p, ok := govStore[id]
	return p, ok
}

// ================= RPC HANDLERS =================
func RegisterExtraRPC() {
	http.HandleFunc("/nft/mint", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Owner    string `json:"owner"`
			Metadata string `json:"metadata"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		nft := MintNFT(req.Owner, req.Metadata)
		json.NewEncoder(w).Encode(nft)
	})

	http.HandleFunc("/nft/transfer", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID       string `json:"id"`
			NewOwner string `json:"new_owner"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		ok := TransferNFT(req.ID, req.NewOwner)
		json.NewEncoder(w).Encode(map[string]bool{"success": ok})
	})

	http.HandleFunc("/nft/get", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		nft, ok := GetNFT(id)
		if !ok {
			http.Error(w, "NFT not found", 404)
			return
		}
		json.NewEncoder(w).Encode(nft)
	})

	http.HandleFunc("/gov/create", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Duration    int64  `json:"duration"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		p := CreateProposal(req.Title, req.Description, req.Duration)
		json.NewEncoder(w).Encode(p)
	})

	http.HandleFunc("/gov/vote", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     string `json:"id"`
			Voter  string `json:"voter"`
			Support bool  `json:"support"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		ok := VoteProposal(req.ID, req.Voter, req.Support)
		json.NewEncoder(w).Encode(map[string]bool{"success": ok})
	})

	http.HandleFunc("/gov/get", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		p, ok := GetProposal(id)
		if !ok {
			http.Error(w, "Proposal not found", 404)
			return
		}
		json.NewEncoder(w).Encode(p)
	})
} 
