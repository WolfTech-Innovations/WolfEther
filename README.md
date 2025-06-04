# WolfEther - Anonymous P2P Blockchain Network

**WolfEther** is a privacy-focused, fee-less hybrid blockchain that combines Proof-of-Work and Proof-of-Stake consensus with integrated Lightning Network channels - all running over Tor for maximum anonymity.

## Key Features

### Privacy & Security First
- **Full Tor Integration** - All P2P communication routed through Tor hidden services
- **Encrypted Wallets** - AES-256-GCM encryption for private keys
- **Anonymous Transactions** - No transaction fees, no KYC, complete privacy
- **DDoS Protection** - Built-in rate limiting and bot detection

### Lightning Fast
- **Integrated Lightning Network** - Instant off-chain transactions
- **Encrypted Channels** - Privacy-preserving payment channels
- **Multi-Asset Support** - Lightning channels for custom tokens
- **15-second Block Times** - Near-instant on-chain confirmations

### Token Economy
- **Custom Token Creation** - Deploy your own coins for 10,000 units
- **ERC-20 Compatible** - Standard token interface
- **Mintable Tokens** - Optional token minting capabilities
- **Cross-Chain Bridge** - BTC to ETH conversion support

### Dual Network Architecture
- **MainNet** (Port 8545) - Production network for real value
- **TestNet** (Port 8546) - Development network for testing
- **Isolated P2P** - Separate discovery for each network
- **Single Binary** - Both networks from one executable

## Quick Start

### Prerequisites
```bash
# Install Tor
sudo apt-get install tor
# Start Tor service
sudo systemctl start tor
```

### Installation
```bash
git clone https://github.com/Wolftech-Innovations/WolfEther
cd WolfEther
go mod tidy
go build -o wolfether main.go
```

### Run Node
```bash
# Starts both MainNet (8545) and TestNet (8546)
./wolfether
```

## API Reference

### Wallet Operations
```bash
# Create new wallet
curl http://localhost:8545/wallet

# Restore wallet from mnemonic
curl -X POST http://localhost:8545/restore \
  -d '{"mnemonic":"your twelve word mnemonic phrase here"}'

# Check balance
curl "http://localhost:8545/balance?address=0x..."

# Check token balance
curl "http://localhost:8545/balance?address=0x...&token=0x..."
```

### Token Creation
```bash
# Deploy custom token (costs 10,000 units)
curl -X POST http://localhost:8545/token/create \
  -d '{
    "name": "MyToken",
    "symbol": "MTK", 
    "maxSupply": "1000000",
    "mintable": true,
    "privKey": "your_private_key"
  }'

# List all tokens
curl http://localhost:8545/tokens
```

### Lightning Network
```bash
# Open payment channel
curl -X POST http://localhost:8545/channel/open \
  -d '{
    "peer1": "0x...",
    "peer2": "0x...",
    "amount1": "1000",
    "amount2": "1000"
  }'

# Send Lightning payment
curl -X POST http://localhost:8545/channel/transfer \
  -d '{
    "channel_id": "channel_id_here",
    "from": "0x...",
    "amount": "100"
  }'
```

### Staking
```bash
# Stake tokens to become validator
curl -X POST http://localhost:8545/stake \
  -d '{
    "address": "0x...",
    "amount": "1000"
  }'
```

## Architecture

### Consensus Mechanism
- **Hybrid PoW/PoS** - Alternating block production
- **Even Blocks**: Proof-of-Work mining
- **Odd Blocks**: Proof-of-Stake validation
- **Reputation System** - Validators scored by performance

### Privacy Features
- **Tor Hidden Services** - All nodes accessible via .onion addresses
- **Anonymous Discovery** - P2P node discovery through Tor
- **Encrypted Communications** - All network traffic encrypted
- **No Transaction Fees** - Completely fee-less network

### Security Model
- **Cryptographic Signatures** - All blocks and transactions signed
- **Nonce Verification** - Prevents replay attacks
- **Balance Validation** - Prevents double-spending
- **Reputation Scoring** - Malicious node detection

## Configuration

### Network Constants
```go
MainNetID = 468        // Main network identifier
TestNetID = 469        // Test network identifier
BlockReward = 50       // Block mining reward
PoWDiff = 4           // Proof-of-Work difficulty
PoSStake = 1000       // Minimum stake for validation
BlockTime = 15        // Block time in seconds
CoinCreateCost = 10000 // Cost to create custom token
```

### Tor Configuration
```bash
# Default Tor SOCKS5 proxy
TorPort = 9050

# Automatic .onion address generation
# Format: [32-char-hash].onion
```

## Development

### Build from Source
```bash
go mod init wolfether
go get github.com/btcsuite/btcd/btcec/v2
go get github.com/btcsuite/btcd/btcutil/hdkeychain
go get github.com/btcsuite/btcd/chaincfg
go get github.com/ethereum/go-ethereum/common
go get github.com/ethereum/go-ethereum/crypto
go get github.com/tyler-smith/go-bip39
go get golang.org/x/net/proxy
go build -ldflags="-s -w" -o wolfether main.go
```

### Testing
```bash
# Test on TestNet (port 8546)
curl http://localhost:8546/info

# Create test wallet
curl http://localhost:8546/wallet
```

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
6. **Open a Node** - Help strengthen the network by running a WolfEther node

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This software is experimental and provided "as is". Use at your own risk. Not audited for production use. The developers are not responsible for any loss of funds or security breaches.

---

*Built with ❤️ for privacy, freedom, and decentralization*