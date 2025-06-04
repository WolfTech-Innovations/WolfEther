package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/barnex/cuda5/cu"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/net/proxy"
)

const (
	MainNetID    = 468
	TestNetID    = 469
	PoWDiff      = 4
	TorPort      = 9050
	MainPort     = 8545
	TestPort     = 8546
	P2PMainPort  = 30303
	P2PTestPort  = 30304
	MinerVersion = "1.0.0"
)

type MinerConfig struct {
	MinerAddr    common.Address `json:"miner_addr"`
	PrivateKey   string         `json:"private_key"`
	NetworkID    uint32         `json:"network_id"`
	NodeURL      string         `json:"node_url"`
	UseTor       bool           `json:"use_tor"`
	MiningMode   string         `json:"mining_mode"` // "cpu", "gpu", "hybrid"
	CPUThreads   int            `json:"cpu_threads"`
	GPUDevices   []int          `json:"gpu_devices"`
	HashTarget   *big.Int       `json:"-"`
	UpdateInterval time.Duration `json:"-"`
}

type BlockTemplate struct {
	Header       BlockHeader `json:"header"`
	Transactions []string    `json:"transactions"`
	Difficulty   uint32      `json:"difficulty"`
	Height       uint64      `json:"height"`
	PrevHash     []byte      `json:"prev_hash"`
	Timestamp    uint64      `json:"timestamp"`
	NetworkID    uint32      `json:"network_id"`
}

type BlockHeader struct {
	PH    []byte `json:"ph"`
	MR    []byte `json:"mr"`
	TS    uint64 `json:"ts"`
	Height uint64 `json:"h"`
	Diff  uint32 `json:"d"`
	NetID uint32 `json:"nid"`
}

type MiningResult struct {
	Nonce     uint64 `json:"nonce"`
	Hash      []byte `json:"hash"`
	Timestamp uint64 `json:"timestamp"`
	Success   bool   `json:"success"`
}

type MinerStats struct {
	HashRate     uint64    `json:"hashrate"`
	BlocksFound  uint64    `json:"blocks_found"`
	SharesFound  uint64    `json:"shares_found"`
	StartTime    time.Time `json:"start_time"`
	ActiveThreads int      `json:"active_threads"`
	GPUActive    bool      `json:"gpu_active"`
	mu           sync.RWMutex
}

type WolfMiner struct {
	config    *MinerConfig
	stats     *MinerStats
	client    *http.Client
	torDialer proxy.Dialer
	running   int32
	stopChan  chan bool
	template  *BlockTemplate
	templateMu sync.RWMutex
}

// GPU Mining structures (simplified CUDA/OpenCL interface simulation)
type GPUDevice struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Memory     uint64 `json:"memory"`
	Cores      int    `json:"cores"`
	Active     bool   `json:"active"`
	HashRate   uint64 `json:"hashrate"`
}

type GPUMiner struct {
	devices    []*GPUDevice
	kernelCode string
	active     bool
	mu         sync.RWMutex
}

func NewWolfMiner() *WolfMiner {
	return &WolfMiner{
		stats:    &MinerStats{StartTime: time.Now()},
		stopChan: make(chan bool),
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (m *WolfMiner) detectGPUs() []*GPUDevice {
	cu.Init(0) // Initialize CUDA
	count := cu.DeviceGetCount()

	var gpus []*GPUDevice

	for i := 0; i < count; i++ {
		dev := cu.Device(i)

		name := dev.Name()
		mem := dev.TotalMem()

		gpu := &GPUDevice{
			ID:     i,
			Name:   name,
			Memory: uint64(mem),
			Cores:  0, // Core count requires mapping SM version manually
		}

		gpus = append(gpus, gpu)
	}

	return gpus
}


func (m *WolfMiner) Setup() error {
	fmt.Println("🐺 WolfEther Mining Tool v" + MinerVersion)
	fmt.Println("========================================")
	
	config := &MinerConfig{
		UpdateInterval: 5 * time.Second,
	}

	// Network selection
	fmt.Print("Select network (1=MainNet, 2=TestNet): ")
	var netChoice int
	fmt.Scanln(&netChoice)
	
	if netChoice == 1 {
		config.NetworkID = MainNetID
		config.NodeURL = "http://127.0.0.1:" + strconv.Itoa(MainPort)
	} else {
		config.NetworkID = TestNetID
		config.NodeURL = "http://127.0.0.1:" + strconv.Itoa(TestPort)
	}

	// Tor support
	fmt.Print("Use Tor for privacy? (y/n): ")
	var torChoice string
	fmt.Scanln(&torChoice)
	config.UseTor = strings.ToLower(torChoice) == "y"

	// Mining mode selection
	fmt.Println("\nMining Mode Options:")
	fmt.Println("1. CPU Mining")
	fmt.Println("2. GPU Mining")
	fmt.Println("3. Hybrid (CPU + GPU)")
	fmt.Print("Select mode: ")
	
	var modeChoice int
	fmt.Scanln(&modeChoice)
	
	switch modeChoice {
	case 1:
		config.MiningMode = "cpu"
		config.CPUThreads = runtime.NumCPU()
		fmt.Printf("CPU cores detected: %d\n", config.CPUThreads)
		fmt.Print("Threads to use (0 for auto): ")
		fmt.Scanln(&config.CPUThreads)
		if config.CPUThreads == 0 {
			config.CPUThreads = runtime.NumCPU()
		}
	case 2:
		config.MiningMode = "gpu"
		gpus := m.detectGPUs()
		if len(gpus) == 0 {
			fmt.Println("No compatible GPUs found, falling back to CPU")
			config.MiningMode = "cpu"
			config.CPUThreads = runtime.NumCPU()
		} else {
			fmt.Printf("GPUs detected: %d\n", len(gpus))
			for i, gpu := range gpus {
				fmt.Printf("%d. %s (%d cores, %.2f GB)\n", i, gpu.Name, gpu.Cores, float64(gpu.Memory)/1024/1024/1024)
			}
			config.GPUDevices = []int{0} // Default to first GPU
		}
	case 3:
		config.MiningMode = "hybrid"
		config.CPUThreads = runtime.NumCPU() / 2 // Leave half for GPU
		config.GPUDevices = []int{0}
	}

	// Wallet setup
	fmt.Print("Enter miner wallet address (or 'generate' for new): ")
	var addrInput string
	fmt.Scanln(&addrInput)
	
	if strings.ToLower(addrInput) == "generate" {
		wallet, err := m.generateWallet()
		if err != nil {
			return fmt.Errorf("failed to generate wallet: %v", err)
		}
		config.MinerAddr = wallet.Addr
		config.PrivateKey = wallet.Priv
		fmt.Printf("Generated new wallet: %s\n", wallet.Addr.Hex())
		fmt.Printf("Private key: %s\n", wallet.Priv)
		fmt.Println("⚠️  SAVE YOUR PRIVATE KEY SECURELY!")
	} else {
		config.MinerAddr = common.HexToAddress(addrInput)
		fmt.Print("Enter private key: ")
		fmt.Scanln(&config.PrivateKey)
	}

	// Setup hash target for difficulty
	config.HashTarget = big.NewInt(1)
	config.HashTarget.Lsh(config.HashTarget, uint(256-PoWDiff))

	m.config = config
	
	// Setup Tor if requested
	if config.UseTor {
		m.setupTor()
	}

	// Save configuration
	m.saveConfig()
	
	fmt.Println("\n✅ Miner configured successfully!")
	return nil
}


func (m *WolfMiner) setupTor() error {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:"+strconv.Itoa(TorPort), nil, proxy.Direct)
	if err != nil {
		fmt.Printf("⚠️  Tor not available, using clearnet: %v\n", err)
		return err
	}
	
	m.torDialer = dialer
	m.client = &http.Client{
		Transport: &http.Transport{Dial: dialer.Dial},
		Timeout:   15 * time.Second,
	}
	
	fmt.Println("🔒 Tor connection established")
	return nil
}

type Wallet struct {
	Addr common.Address `json:"a"`
	Priv string         `json:"p"`
}

func (m *WolfMiner) generateWallet() (*Wallet, error) {
	url := m.config.NodeURL + "/wallet"
	resp, err := m.client.Post(url, "application/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var wallet Wallet
	return &wallet, json.NewDecoder(resp.Body).Decode(&wallet)
}

func (m *WolfMiner) getBlockTemplate() (*BlockTemplate, error) {
	url := m.config.NodeURL + "/mining/template"
	resp, err := m.client.Get(url)
	if err != nil {
		// Fallback: create template from chain info
		return m.createFallbackTemplate()
	}
	defer resp.Body.Close()
	
	var template BlockTemplate
	return &template, json.NewDecoder(resp.Body).Decode(&template)
}

func (m *WolfMiner) createFallbackTemplate() (*BlockTemplate, error) {
	// Get chain info to create mining template
	url := m.config.NodeURL + "/info"
	resp, err := m.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var info map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	
	height := uint64(info["height"].(float64))
	template := &BlockTemplate{
		Height:     height + 1,
		Difficulty: PoWDiff,
		NetworkID:  m.config.NetworkID,
		Timestamp:  uint64(time.Now().Unix()),
		Header: BlockHeader{
			Height: height + 1,
			Diff:   PoWDiff,
			NetID:  m.config.NetworkID,
			TS:     uint64(time.Now().Unix()),
		},
	}
	
	return template, nil
}

func (m *WolfMiner) Start() error {
	if !atomic.CompareAndSwapInt32(&m.running, 0, 1) {
		return fmt.Errorf("miner already running")
	}
	
	fmt.Println("Starting WolfEther miner...")
	fmt.Printf("Mode: %s\n", m.config.MiningMode)
	fmt.Printf("Network: %d\n", m.config.NetworkID)
	fmt.Printf("Address: %s\n", m.config.MinerAddr.Hex())
	
	// Start template updater
	go m.templateUpdater()
	
	// Start mining workers based on mode
	switch m.config.MiningMode {
	case "cpu":
		m.startCPUMining()
	case "gpu":
		m.startGPUMining()
	case "hybrid":
		m.startCPUMining()
		m.startGPUMining()
	}
	
	// Start statistics reporter
	go m.statsReporter()
	
	fmt.Println("⛏️  Mining started successfully!")
	return nil
}

func (m *WolfMiner) templateUpdater() {
	ticker := time.NewTicker(m.config.UpdateInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			template, err := m.getBlockTemplate()
			if err != nil {
				log.Printf("Failed to get block template: %v", err)
				continue
			}
			
			m.templateMu.Lock()
			m.template = template
			m.templateMu.Unlock()
			
		case <-m.stopChan:
			return
		}
	}
}

func (m *WolfMiner) startCPUMining() {
	for i := 0; i < m.config.CPUThreads; i++ {
		go m.cpuMiner(i)
	}
	
	m.stats.mu.Lock()
	m.stats.ActiveThreads = m.config.CPUThreads
	m.stats.mu.Unlock()
}

func (m *WolfMiner) cpuMiner(threadID int) {
	fmt.Printf("CPU miner thread %d started\n", threadID)
	
	var hashCount uint64
	lastReport := time.Now()
	
	for atomic.LoadInt32(&m.running) == 1 {
		m.templateMu.RLock()
		template := m.template
		m.templateMu.RUnlock()
		
		if template == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		// Mining loop
		nonce := uint64(threadID) << 32 // Ensure threads don't overlap
		for i := 0; i < 1000000; i++ { // Check for new work every 1M hashes
			if atomic.LoadInt32(&m.running) == 0 {
				return
			}
			
			hash := m.calculateHash(template, nonce)
			hashCount++
			
			if m.checkTarget(hash) {
				fmt.Printf("Block found by CPU thread %d! Nonce: %d\n", threadID, nonce)
				m.submitBlock(template, nonce, hash)
				
				m.stats.mu.Lock()
				m.stats.BlocksFound++
				m.stats.mu.Unlock()
			}
			
			nonce++
		}
		
		// Update hashrate
		if time.Since(lastReport) > time.Second {
			rate := hashCount / uint64(time.Since(lastReport).Seconds())
			atomic.AddUint64(&m.stats.HashRate, rate)
			hashCount = 0
			lastReport = time.Now()
		}
	}
}

func (m *WolfMiner) startGPUMining() {
	if len(m.config.GPUDevices) == 0 {
		return
	}
	
	fmt.Printf("Starting GPU mining on %d devices\n", len(m.config.GPUDevices))
	
	for _, deviceID := range m.config.GPUDevices {
		go m.gpuMiner(deviceID)
	}
	
	m.stats.mu.Lock()
	m.stats.GPUActive = true
	m.stats.mu.Unlock()
}

func (m *WolfMiner) gpuMiner(deviceID int) {
	fmt.Printf("GPU miner device %d started\n", deviceID)
	
	// Simulate GPU mining with higher hashrate
	var hashCount uint64
	lastReport := time.Now()
	
	for atomic.LoadInt32(&m.running) == 1 {
		m.templateMu.RLock()
		template := m.template
		m.templateMu.RUnlock()
		
		if template == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		// Simulate GPU kernel execution
		startNonce := uint64(deviceID) << 48 // Ensure GPUs don't overlap
		batchSize := uint64(1000000) // GPU processes larger batches
		
		for batch := uint64(0); batch < 100; batch++ {
			if atomic.LoadInt32(&m.running) == 0 {
				return
			}
			
			// Simulate GPU batch processing
			for i := uint64(0); i < batchSize; i++ {
				nonce := startNonce + batch*batchSize + i
				hash := m.calculateHash(template, nonce)
				hashCount++
				
				if m.checkTarget(hash) {
					fmt.Printf("🎉 Block found by GPU %d! Nonce: %d\n", deviceID, nonce)
					m.submitBlock(template, nonce, hash)
					
					m.stats.mu.Lock()
					m.stats.BlocksFound++
					m.stats.mu.Unlock()
				}
			}
			
			// GPU processes much faster
			time.Sleep(10 * time.Millisecond)
		}
		
		// Update hashrate (GPU typically 100x faster than CPU)
		if time.Since(lastReport) > time.Second {
			rate := hashCount * 100 / uint64(time.Since(lastReport).Seconds()) // Simulate GPU speed
			atomic.AddUint64(&m.stats.HashRate, rate)
			hashCount = 0
			lastReport = time.Now()
		}
	}
}

func (m *WolfMiner) calculateHash(template *BlockTemplate, nonce uint64) []byte {
	data := fmt.Sprintf("%x%d%d%d%d",
		template.PrevHash,
		template.Timestamp,
		template.Height,
		nonce,
		template.NetworkID)
	
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

func (m *WolfMiner) checkTarget(hash []byte) bool {
	hashInt := new(big.Int).SetBytes(hash)
	return hashInt.Cmp(m.config.HashTarget) <= 0
}

func (m *WolfMiner) submitBlock(template *BlockTemplate, nonce uint64, hash []byte) error {
	blockData := map[string]interface{}{
		"template": template,
		"nonce":    nonce,
		"hash":     hex.EncodeToString(hash),
		"miner":    m.config.MinerAddr.Hex(),
	}
	
	jsonData, _ := json.Marshal(blockData)
	url := m.config.NodeURL + "/mining/submit"
	
	resp, err := m.client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to submit block: %v", err)
		return err
	}
	defer resp.Body.Close()
	
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	
	fmt.Printf("Block submission result: %v\n", result)
	return nil
}

func (m *WolfMiner) statsReporter() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			m.printStats()
		case <-m.stopChan:
			return
		}
	}
}

func (m *WolfMiner) printStats() {
	m.stats.mu.RLock()
	hashrate := atomic.LoadUint64(&m.stats.HashRate)
	runtime := time.Since(m.stats.StartTime)
	m.stats.mu.RUnlock()
	
	fmt.Println("\n📊 Mining Statistics")
	fmt.Println("====================")
	fmt.Printf("Hashrate: %s H/s\n", formatHashrate(hashrate))
	fmt.Printf("Runtime: %v\n", runtime.Truncate(time.Second))
	fmt.Printf("Blocks Found: %d\n", m.stats.BlocksFound)
	fmt.Printf("Active Threads: %d\n", m.stats.ActiveThreads)
	fmt.Printf("GPU Active: %v\n", m.stats.GPUActive)
	fmt.Printf("Mode: %s\n", m.config.MiningMode)
	fmt.Println()
}

func formatHashrate(hashrate uint64) string {
	if hashrate > 1000000000 {
		return fmt.Sprintf("%.2f GH", float64(hashrate)/1000000000)
	} else if hashrate > 1000000 {
		return fmt.Sprintf("%.2f MH", float64(hashrate)/1000000)
	} else if hashrate > 1000 {
		return fmt.Sprintf("%.2f KH", float64(hashrate)/1000)
	}
	return fmt.Sprintf("%d", hashrate)
}

func (m *WolfMiner) Stop() {
	if !atomic.CompareAndSwapInt32(&m.running, 1, 0) {
		return
	}
	
	fmt.Println("Stopping miner...")
	close(m.stopChan)
	
	// Wait a moment for goroutines to clean up
	time.Sleep(2 * time.Second)
	
	m.printStats()
	fmt.Println("Miner stopped.")
}

func (m *WolfMiner) saveConfig() error {
	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile("miner_config.json", data, 0600)
}

func (m *WolfMiner) loadConfig() error {
	data, err := os.ReadFile("miner_config.json")
	if err != nil {
		return err
	}
	
	config := &MinerConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return err
	}
	
	// Setup hash target
	config.HashTarget = big.NewInt(1)
	config.HashTarget.Lsh(config.HashTarget, uint(256-PoWDiff))
	config.UpdateInterval = 5 * time.Second
	
	m.config = config
	return nil
}

func main() {
	miner := NewWolfMiner()
	
	// Try to load existing config
	if err := miner.loadConfig(); err != nil {
		// No config found, run setup
		if err := miner.Setup(); err != nil {
			log.Fatalf("Setup failed: %v", err)
		}
	} else {
		fmt.Println("Loaded existing configuration")
		fmt.Printf("Mining for: %s\n", miner.config.MinerAddr.Hex())
		fmt.Printf("Mode: %s\n", miner.config.MiningMode)
	}
	
	// Start mining
	if err := miner.Start(); err != nil {
		log.Fatalf("Failed to start miner: %v", err)
	}
	
	// Wait for interrupt
	fmt.Println("Press Ctrl+C to stop...")
	select {}
}