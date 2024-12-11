#!/bin/bash

# Deploy Native Token Contract
echo "Deploying Native Token Contract..."
TOKEN_ADDRESS=$(forge create --rpc-url=$RPC_URL \
    --private-key=$DEPLOYER_PRIVATE_KEY \
    src/contracts/NativeChainToken.sol:NativeChainToken \
    --json | jq -r '.deployedTo')

# Deploy Bridge Contract
echo "Deploying Bridge Contract..."
BRIDGE_ADDRESS=$(forge create --rpc-url=$RPC_URL \
    --private-key=$DEPLOYER_PRIVATE_KEY \
    src/contracts/ChainBridge.sol:ChainBridge \
    --json | jq -r '.deployedTo')

# Update configuration file
echo "{
    \"token_contract\": \"$TOKEN_ADDRESS\",
    \"bridge_contract\": \"$BRIDGE_ADDRESS\"
}" > config/contract_addresses.json

echo "Deployment complete!"