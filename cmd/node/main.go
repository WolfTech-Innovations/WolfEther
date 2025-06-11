package main
import("os";"crypto/rand";"crypto/sha256";"crypto/aes";"crypto/cipher";_"crypto/hmac";"crypto/subtle";"encoding/hex";"encoding/json";"fmt";"log";"math/big";_"net";"net/http";"strconv";"strings";"sync";"time";"github.com/btcsuite/btcd/btcutil/hdkeychain";"github.com/btcsuite/btcd/chaincfg";"github.com/ethereum/go-ethereum/common";"github.com/ethereum/go-ethereum/crypto";"github.com/tyler-smith/go-bip39";"golang.org/x/net/proxy";_"golang.org/x/crypto/scrypt";"golang.org/x/time/rate")

const(MainNetID=468;TestNetID=469;BlockReward=50;PoWDiff=4;PoSStake=1000;BlockTime=15;TorPort=9050;MainPort=8545;TestPort=8546;P2PMainPort=30303;P2PTestPort=30304;MaxTxPerBlock=50;MinStakeTime=24*time.Hour;MaxNodes=1000;RepDecayTime=7*24*time.Hour;MaxMsgSize=1024*64)

type Block struct{H BlockHeader`json:"h"`;Txs[]*Tx`json:"t"`;Hash[]byte`json:"hash"`;Nonce uint64`json:"n"`;Miner common.Address`json:"m"`;Sig[]byte`json:"sig"`;Merkle[]byte`json:"merkle"`}
type BlockHeader struct{PH[]byte`json:"ph"`;MR[]byte`json:"mr"`;TS uint64`json:"ts"`;Height uint64`json:"h"`;Diff uint32`json:"d"`;NetID uint32`json:"nid"`;Version uint32`json:"v"`}
type Tx struct{From,To common.Address`json:"f,t"`;Value*big.Int`json:"v"`;Nonce uint64`json:"n"`;Sig[]byte`json:"s"`;Type string`json:"type"`;Data[]byte`json:"data"`;Fee*big.Int`json:"fee"`;TS uint64`json:"ts"`}
type Account struct{Addr common.Address`json:"a"`;Bal,Stake*big.Int`json:"b,s"`;Nonce uint64`json:"n"`;StakeAt time.Time`json:"sa"`;LastActivity time.Time`json:"la"`}
type Validator struct{Addr common.Address`json:"a"`;Stake,Rewards*big.Int`json:"s,r"`;Active bool`json:"active"`;RepScore uint32`json:"rep"`;StakedAt time.Time`json:"staked"`;Violations uint32`json:"violations"`}
type P2PNode struct{ID string`json:"id"`;OnionAddr string`json:"onion"`;LastSeen time.Time`json:"ls"`;Height,NetID uint64`json:"h,nid"`;Rep uint32`json:"rep"`;FirstSeen time.Time`json:"fs"`;CircuitID string`json:"cid"`}
type Circuit struct{ID string;Hops[]string;Created time.Time;LastUsed time.Time;Keys map[string][]byte}
type Message struct{Type string`json:"type"`;Data[]byte`json:"data"`;CircuitID string`json:"cid"`;LayerCount int`json:"layers"`;Timestamp int64`json:"ts"`;Nonce string`json:"nonce"`}
type Blockchain struct{Chain[]*Block`json:"c"`;Accounts map[common.Address]*Account`json:"a"`;TxPool[]*Tx`json:"tp"`;Validators map[common.Address]*Validator`json:"v"`;Nodes map[string]*P2PNode`json:"n"`;Circuits map[string]*Circuit;mu sync.RWMutex;nodeID,onionAddr string;netID uint32;torDialer proxy.Dialer;privKey[]byte;repSystem*ReputationSystem;rateLimiter*rate.Limiter}
type ReputationSystem struct{scores map[string]*NodeRep;mu sync.RWMutex}
type NodeRep struct{Score float64;LastUpdate time.Time;Interactions uint64;SuccessRate float64}
type RPC struct{bc*Blockchain;limiters map[string]*rate.Limiter;mu sync.RWMutex}

func NewBlockchain(netID uint32)*Blockchain{nodeKey:=make([]byte,32);rand.Read(nodeKey);bc:=&Blockchain{Accounts:make(map[common.Address]*Account),TxPool:[]*Tx{},Validators:make(map[common.Address]*Validator),Nodes:make(map[string]*P2PNode),Circuits:make(map[string]*Circuit),nodeID:genSecureNodeID(),netID:netID,privKey:nodeKey,repSystem:&ReputationSystem{scores:make(map[string]*NodeRep)},rateLimiter:rate.NewLimiter(rate.Every(100*time.Millisecond),10)};bc.setupTor();bc.createGenesis();go bc.cleanupRoutine();return bc}

func genSecureNodeID()string{b:=make([]byte,32);rand.Read(b);hash:=sha256.Sum256(b);return hex.EncodeToString(hash[:])}

func(bc*Blockchain)setupTor(){dialer,err:=proxy.SOCKS5("tcp","127.0.0.1:"+strconv.Itoa(TorPort),nil,proxy.Direct);if err!=nil{log.Printf("Tor setup failed, using direct connection with warning");bc.torDialer=proxy.Direct;return};bc.torDialer=dialer;bc.onionAddr=bc.generateSecureOnionAddr()}

func(bc*Blockchain)generateSecureOnionAddr()string{seed:=append(bc.privKey,[]byte(bc.nodeID)...);hash:=sha256.Sum256(seed);return hex.EncodeToString(hash[:16])+".onion"}

func(bc*Blockchain)createGenesis(){admin:=common.HexToAddress("0x0001");supply,_:=new(big.Int).SetString("1000000000000000000000000",10);bc.Accounts[admin]=&Account{Addr:admin,Bal:supply,Stake:big.NewInt(0),LastActivity:time.Now()};genesis:=&Block{H:BlockHeader{PH:make([]byte,32),TS:uint64(time.Now().Unix()),Height:0,Diff:PoWDiff,NetID:bc.netID,Version:1},Txs:[]*Tx{},Nonce:0};genesis.Merkle=bc.calcMerkleRoot(genesis.Txs);genesis.Hash=bc.calcBlockHash(genesis);bc.signBlock(genesis,admin);bc.Chain=append(bc.Chain,genesis)}

func(bc*Blockchain)calcMerkleRoot(txs[]*Tx)[]byte{if len(txs)==0{return make([]byte,32)};hashes:=make([][]byte,len(txs));for i,tx:=range txs{hashes[i]=bc.txHash(tx)};for len(hashes)>1{if len(hashes)%2==1{hashes=append(hashes,hashes[len(hashes)-1])};newHashes:=make([][]byte,len(hashes)/2);for i:=0;i<len(hashes);i+=2{combined:=append(hashes[i],hashes[i+1]...);hash:=sha256.Sum256(combined);newHashes[i/2]=hash[:]};hashes=newHashes};if len(hashes)==0{return make([]byte,32)};return hashes[0]}

func(bc*Blockchain)calcBlockHash(b*Block)[]byte{data:=fmt.Sprintf("%x%x%d%d%d%d%d%d",b.H.PH,b.Merkle,b.H.TS,b.H.Height,b.Nonce,b.H.NetID,b.H.Version,len(b.Txs));hash:=sha256.Sum256([]byte(data));return hash[:]}

func(bc*Blockchain)signBlock(b*Block,minerAddr common.Address){hash:=bc.calcBlockHash(b);privKey,_:=crypto.GenerateKey();sig,_:=crypto.Sign(hash,privKey);b.Sig=sig;b.Miner=minerAddr}

func(bc*Blockchain)verifyBlock(b*Block)bool{if len(b.Sig)==0||b.H.Version<1{return false};if b.H.Height>0{prev:=bc.Chain[b.H.Height-1];if subtle.ConstantTimeCompare(b.H.PH,prev.Hash)!=1{return false};if b.H.TS<=prev.H.TS||b.H.TS>uint64(time.Now().Add(2*time.Hour).Unix()){return false}};merkle:=bc.calcMerkleRoot(b.Txs);if subtle.ConstantTimeCompare(b.Merkle,merkle)!=1{return false};hash:=bc.calcBlockHash(b);pubKey,err:=crypto.SigToPub(hash,b.Sig);return err==nil&&pubKey!=nil}

func(bc*Blockchain)minePoW(b*Block){target:=big.NewInt(1);target.Lsh(target,uint(256-PoWDiff));for{b.Nonce++;hash:=bc.calcBlockHash(b);hashInt:=big.NewInt(0);hashInt.SetBytes(hash);if hashInt.Cmp(target)==-1{b.Hash=hash;break}}}

func(bc*Blockchain)selectPoSValidator()common.Address{eligible:=[]common.Address{};totalWeight:=big.NewInt(0);minStakeTime:=time.Now().Add(-MinStakeTime);for addr,val:=range bc.Validators{if val.Active&&val.Stake.Cmp(big.NewInt(PoSStake))>=0&&val.RepScore>70&&val.StakedAt.Before(minStakeTime)&&val.Violations<3{eligible=append(eligible,addr);weight:=new(big.Int).Mul(val.Stake,big.NewInt(int64(val.RepScore)));totalWeight.Add(totalWeight,weight)}};if len(eligible)==0||totalWeight.Cmp(big.NewInt(0))==0{return common.Address{}};randBytes:=make([]byte,8);rand.Read(randBytes);randInt:=new(big.Int).SetBytes(randBytes);target:=new(big.Int).Mod(randInt,totalWeight);current:=big.NewInt(0);for _,addr:=range eligible{val:=bc.Validators[addr];weight:=new(big.Int).Mul(val.Stake,big.NewInt(int64(val.RepScore)));current.Add(current,weight);if current.Cmp(target)>=0{return addr}};return common.Address{}}

func(bc*Blockchain)AddBlock(){bc.mu.Lock();defer bc.mu.Unlock();if len(bc.TxPool)==0{return};last:=bc.Chain[len(bc.Chain)-1];validTxs:=bc.selectValidTxs();if len(validTxs)==0{return};newBlock:=&Block{H:BlockHeader{PH:last.Hash,TS:uint64(time.Now().Unix()),Height:last.H.Height+1,Diff:PoWDiff,NetID:bc.netID,Version:1},Txs:validTxs};newBlock.Merkle=bc.calcMerkleRoot(newBlock.Txs);if newBlock.H.Height%2==0{bc.minePoW(newBlock);newBlock.Miner=common.HexToAddress("0x0001")}else{validator:=bc.selectPoSValidator();if validator==(common.Address{}){return};newBlock.Hash=bc.calcBlockHash(newBlock);newBlock.Miner=validator};bc.signBlock(newBlock,newBlock.Miner);if!bc.verifyBlock(newBlock){return};bc.Chain=append(bc.Chain,newBlock);bc.removeTxsFromPool(newBlock.Txs);bc.processRewards(newBlock);bc.processTxs(newBlock.Txs);go bc.broadcastBlock(newBlock)}

func(bc*Blockchain)selectValidTxs()[]*Tx{valid:=[]*Tx{};seen:=make(map[common.Address]uint64);for _,tx:=range bc.TxPool{if len(valid)>=MaxTxPerBlock{break};if bc.validateTxStrict(tx,seen){valid=append(valid,tx);seen[tx.From]=tx.Nonce}};return valid}

func(bc*Blockchain)removeTxsFromPool(processed[]*Tx){processedMap:=make(map[string]bool);for _,tx:=range processed{processedMap[hex.EncodeToString(bc.txHash(tx))]=true};newPool:=[]*Tx{};for _,tx:=range bc.TxPool{if!processedMap[hex.EncodeToString(bc.txHash(tx))]{newPool=append(newPool,tx)}};bc.TxPool=newPool}

func(bc*Blockchain)processRewards(b*Block){reward:=big.NewInt(BlockReward);fee:=big.NewInt(0);for _,tx:=range b.Txs{fee.Add(fee,tx.Fee)};totalReward:=new(big.Int).Add(reward,fee);if miner,ok:=bc.Accounts[b.Miner];ok{miner.Bal.Add(miner.Bal,totalReward);miner.LastActivity=time.Now();if val,exists:=bc.Validators[b.Miner];exists{val.RepScore=min(val.RepScore+1,100);val.Rewards.Add(val.Rewards,totalReward)}}}

func(bc*Blockchain)processTxs(txs[]*Tx){for _,tx:=range txs{bc.ProcessTx(tx)}}

func(bc*Blockchain)AddTx(tx*Tx)error{bc.mu.Lock();defer bc.mu.Unlock();if!bc.rateLimiter.Allow(){return fmt.Errorf("rate limited")};if!bc.validateTxStrict(tx,nil){return fmt.Errorf("invalid transaction")};if len(bc.TxPool)>=1000{return fmt.Errorf("transaction pool full")};bc.TxPool=append(bc.TxPool,tx);go bc.broadcastTx(tx);return nil}

func(bc*Blockchain)validateTxStrict(tx*Tx,pending map[common.Address]uint64)bool{if tx.Value==nil||tx.Fee==nil||tx.Value.Sign()<0||tx.Fee.Sign()<0{return false};if len(tx.Data)>MaxMsgSize||tx.TS==0{return false};if time.Unix(int64(tx.TS),0).After(time.Now().Add(time.Hour)){return false};sender,ok:=bc.Accounts[tx.From];if!ok{return false};expectedNonce:=sender.Nonce+1;if pending!=nil{if pNonce,exists:=pending[tx.From];exists{expectedNonce=pNonce+1}};if tx.Nonce!=expectedNonce{return false};total:=new(big.Int).Add(tx.Value,tx.Fee);if sender.Bal.Cmp(total)<0{return false};hash:=bc.txHash(tx);pubKey,err:=crypto.SigToPub(hash,tx.Sig);if err!=nil||crypto.PubkeyToAddress(*pubKey)!=tx.From{return false};return true}

func(bc*Blockchain)txHash(tx*Tx)[]byte{data:=fmt.Sprintf("%s%s%s%d%s%s%d",tx.From.Hex(),tx.To.Hex(),tx.Value.String(),tx.Nonce,tx.Type,tx.Fee.String(),tx.TS);if len(tx.Data)>0{data+=hex.EncodeToString(tx.Data)};hash:=sha256.Sum256([]byte(data));return hash[:]}

func(bc*Blockchain)ProcessTx(tx*Tx){sender:=bc.Accounts[tx.From];receiver:=bc.Accounts[tx.To];if receiver==nil{receiver=&Account{Addr:tx.To,Bal:big.NewInt(0),Stake:big.NewInt(0),LastActivity:time.Now()};bc.Accounts[tx.To]=receiver};total:=new(big.Int).Add(tx.Value,tx.Fee);sender.Bal.Sub(sender.Bal,total);receiver.Bal.Add(receiver.Bal,tx.Value);sender.Nonce++;sender.LastActivity=time.Now();receiver.LastActivity=time.Now()}

func(bc*Blockchain)Stake(addr common.Address,amt*big.Int)error{bc.mu.Lock();defer bc.mu.Unlock();acc,ok:=bc.Accounts[addr];if!ok||acc.Bal.Cmp(amt)<0{return fmt.Errorf("insufficient balance")};if amt.Cmp(big.NewInt(PoSStake))<0{return fmt.Errorf("minimum stake not met")};acc.Bal.Sub(acc.Bal,amt);acc.Stake.Add(acc.Stake,amt);acc.StakeAt=time.Now();if val,ok:=bc.Validators[addr];ok{val.Stake.Add(val.Stake,amt)}else{bc.Validators[addr]=&Validator{Addr:addr,Stake:new(big.Int).Set(amt),Active:true,Rewards:big.NewInt(0),RepScore:75,StakedAt:time.Now(),Violations:0}};return nil}
func(bc*Blockchain)createCircuit()string{if len(bc.Nodes)<3{return""};nodes:=make([]*P2PNode,0,len(bc.Nodes));for _,node:=range bc.Nodes{if node.Rep>60&&time.Since(node.LastSeen)<5*time.Minute{nodes=append(nodes,node)}};if len(nodes)<3{return""};selected:=make([]*P2PNode,3);indices:=make([]int,len(nodes));for i:=range indices{indices[i]=i};for i:=0;i<3&&len(indices)>0;i++{randBytes:=make([]byte,4);rand.Read(randBytes);idx:=int(new(big.Int).SetBytes(randBytes).Uint64())%len(indices);selected[i]=nodes[indices[idx]];indices=append(indices[:idx],indices[idx+1:]...)};circuitID:=genSecureNodeID();hops:=make([]string,3);keys:=make(map[string][]byte);for i,node:=range selected{if node==nil{continue};hops[i]=node.ID;key:=make([]byte,32);rand.Read(key);keys[node.ID]=key};bc.Circuits[circuitID]=&Circuit{ID:circuitID,Hops:hops,Created:time.Now(),LastUsed:time.Now(),Keys:keys};return circuitID}
func(bc*Blockchain)encryptMessage(msg*Message,circuitID string)[]byte{circuit,ok:=bc.Circuits[circuitID];if!ok{return nil};data,_:=json.Marshal(msg);for i:=len(circuit.Hops)-1;i>=0;i--{key:=circuit.Keys[circuit.Hops[i]];data=bc.encryptLayer(data,key)};return data}

func(bc*Blockchain)encryptLayer(data,key[]byte)[]byte{block,_:=aes.NewCipher(key);gcm,_:=cipher.NewGCM(block);nonce:=make([]byte,gcm.NonceSize());rand.Read(nonce);return gcm.Seal(nonce,nonce,data,nil)}

func(bc*Blockchain)broadcastTx(tx*Tx){msg:=&Message{Type:"tx",Data:nil,CircuitID:"",LayerCount:0,Timestamp:time.Now().Unix(),Nonce:genSecureNodeID()};if data,err:=json.Marshal(tx);err==nil{msg.Data=data;bc.broadcastMessage(msg)}}

func(bc*Blockchain)broadcastBlock(b*Block){msg:=&Message{Type:"block",Data:nil,CircuitID:"",LayerCount:0,Timestamp:time.Now().Unix(),Nonce:genSecureNodeID()};if data,err:=json.Marshal(b);err==nil{msg.Data=data;bc.broadcastMessage(msg)}}

func(bc*Blockchain)broadcastMessage(msg*Message){circuitID:=bc.createCircuit();if circuitID==""{return};msg.CircuitID=circuitID;encrypted:=bc.encryptMessage(msg,circuitID);bc.sendToCircuit(encrypted,circuitID)}

func(bc*Blockchain)sendToCircuit(data[]byte,circuitID string){circuit,ok:=bc.Circuits[circuitID];if!ok||len(circuit.Hops)==0{return};firstHop:=circuit.Hops[0];if node,exists:=bc.Nodes[firstHop];exists&&bc.torDialer!=nil{port:=P2PMainPort;if bc.netID==TestNetID{port=P2PTestPort};if conn,err:=bc.torDialer.Dial("tcp",node.OnionAddr+":"+strconv.Itoa(port));err==nil{conn.Write(data);conn.Close();circuit.LastUsed=time.Now()}}}

func(bc*Blockchain)cleanupRoutine(){ticker:=time.NewTicker(10*time.Minute);for range ticker.C{bc.mu.Lock();now:=time.Now();for id,circuit:=range bc.Circuits{if now.Sub(circuit.LastUsed)>30*time.Minute{delete(bc.Circuits,id)}};for id,node:=range bc.Nodes{if now.Sub(node.LastSeen)>RepDecayTime{if node.Rep>10{node.Rep-=10}else{delete(bc.Nodes,id)}}};bc.mu.Unlock()}}

func(rs*ReputationSystem)UpdateScore(nodeID string,success bool){rs.mu.Lock();defer rs.mu.Unlock();rep,ok:=rs.scores[nodeID];if!ok{rep=&NodeRep{Score:50.0,LastUpdate:time.Now(),Interactions:0,SuccessRate:0.5};rs.scores[nodeID]=rep};rep.Interactions++;if success{rep.SuccessRate=(rep.SuccessRate*float64(rep.Interactions-1)+1.0)/float64(rep.Interactions)}else{rep.SuccessRate=(rep.SuccessRate*float64(rep.Interactions-1))/float64(rep.Interactions)};rep.Score=rep.SuccessRate*100;rep.LastUpdate=time.Now()}

func generateMnemonic()string{entropy,_:=bip39.NewEntropy(256);mnemonic,_:=bip39.NewMnemonic(entropy);return mnemonic}

func createWalletFromMnemonic(mnemonic,passphrase string)*Wallet{seed:=bip39.NewSeed(mnemonic,passphrase);masterKey,_:=hdkeychain.NewMaster(seed,&chaincfg.MainNetParams);path:="m/44'/60'/0'/0/0";childKey,_:=masterKey.Derive(hdkeychain.HardenedKeyStart+44);childKey,_=childKey.Derive(hdkeychain.HardenedKeyStart+60);childKey,_=childKey.Derive(hdkeychain.HardenedKeyStart+0);childKey,_=childKey.Derive(0);childKey,_=childKey.Derive(0);privKey,_:=childKey.ECPrivKey();ethPriv:=crypto.ToECDSAUnsafe(privKey.Serialize());addr:=crypto.PubkeyToAddress(ethPriv.PublicKey);return&Wallet{Addr:addr,Priv:hex.EncodeToString(crypto.FromECDSA(ethPriv)),Mnemonic:mnemonic,Path:path}}

type Wallet struct{Addr common.Address`json:"a"`;Priv string`json:"-"`;Mnemonic string`json:"-"`;Path string`json:"path"`}

func(w*Wallet)SignTx(tx*Tx,passphrase string)error{privKey,err:=crypto.HexToECDSA(w.Priv);if err!=nil{return err};hash:=sha256.Sum256([]byte(fmt.Sprintf("%s%s%s%d%s%s%d",tx.From.Hex(),tx.To.Hex(),tx.Value.String(),tx.Nonce,tx.Type,tx.Fee.String(),tx.TS)));sig,err:=crypto.Sign(hash[:],privKey);if err!=nil{return err};tx.Sig=sig;return nil}

func(rpc*RPC)getRateLimiter(ip string)*rate.Limiter{rpc.mu.Lock();defer rpc.mu.Unlock();if rpc.limiters==nil{rpc.limiters=make(map[string]*rate.Limiter)};limiter,ok:=rpc.limiters[ip];if!ok{limiter=rate.NewLimiter(rate.Every(time.Second),5);rpc.limiters[ip]=limiter};return limiter}

func(rpc*RPC)security(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r*http.Request){ip:=strings.Split(r.RemoteAddr,":")[0];if!rpc.getRateLimiter(ip).Allow(){http.Error(w,"Rate Limited",429);return};if strings.Contains(strings.ToLower(r.Header.Get("User-Agent")),"bot")||len(r.Header.Get("X-Forwarded-For"))>100{http.Error(w,"Forbidden",403);return};next.ServeHTTP(w,r)})}

func(rpc*RPC)handleBalance(w http.ResponseWriter,r*http.Request){addr:=common.HexToAddress(r.URL.Query().Get("address"));if addr==(common.Address{}){http.Error(w,"Invalid address",400);return};rpc.bc.mu.RLock();acc:=rpc.bc.Accounts[addr];rpc.bc.mu.RUnlock();bal:="0";if acc!=nil{bal=acc.Bal.String()};json.NewEncoder(w).Encode(map[string]string{"balance":bal})}

func(rpc*RPC)handleSendTx(w http.ResponseWriter,r*http.Request){var tx Tx;if err:=json.NewDecoder(r.Body).Decode(&tx);err!=nil{http.Error(w,"Invalid JSON",400);return};tx.TS=uint64(time.Now().Unix());if err:=rpc.bc.AddTx(&tx);err!=nil{http.Error(w,err.Error(),400);return};json.NewEncoder(w).Encode(map[string]string{"status":"ok","hash":hex.EncodeToString(rpc.bc.txHash(&tx))})}

func(rpc*RPC)handleStake(w http.ResponseWriter,r*http.Request){var req struct{Address,Amount string};if err:=json.NewDecoder(r.Body).Decode(&req);err!=nil{http.Error(w,"Invalid JSON",400);return};addr:=common.HexToAddress(req.Address);amt,ok:=new(big.Int).SetString(req.Amount,10);if!ok{http.Error(w,"Invalid amount",400);return};if err:=rpc.bc.Stake(addr,amt);err!=nil{http.Error(w,err.Error(),400);return};json.NewEncoder(w).Encode(map[string]string{"status":"staked"})}

func(rpc*RPC)handleCreateWallet(w http.ResponseWriter,r*http.Request){var req struct{Passphrase string};json.NewDecoder(r.Body).Decode(&req);mnemonic:=generateMnemonic();wallet:=createWalletFromMnemonic(mnemonic,req.Passphrase);rpc.bc.mu.Lock();rpc.bc.Accounts[wallet.Addr]=&Account{Addr:wallet.Addr,Bal:big.NewInt(1000000000000000000),Stake:big.NewInt(0),LastActivity:time.Now()};rpc.bc.mu.Unlock();response:=map[string]interface{}{"address":wallet.Addr.Hex(),"path":wallet.Path};json.NewEncoder(w).Encode(response)}

func(rpc*RPC)handleInfo(w http.ResponseWriter,r*http.Request){rpc.bc.mu.RLock();info:=map[string]interface{}{"height":len(rpc.bc.Chain),"network_id":rpc.bc.netID,"validators":len(rpc.bc.Validators),"accounts":len(rpc.bc.Accounts),"nodes":len(rpc.bc.Nodes),"circuits":len(rpc.bc.Circuits),"node_id":rpc.bc.nodeID,"onion_addr":rpc.bc.onionAddr,"tor_enabled":rpc.bc.torDialer!=nil};rpc.bc.mu.RUnlock();json.NewEncoder(w).Encode(info)}

func cors(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r*http.Request){w.Header().Set("Access-Control-Allow-Origin","*");w.Header().Set("Access-Control-Allow-Methods","GET,POST,OPTIONS");w.Header().Set("Access-Control-Allow-Headers","Content-Type");w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("X-Frame-Options","DENY");w.Header().Set("X-XSS-Protection","1; mode=block");w.Header().Set("Strict-Transport-Security","max-age=31536000; includeSubDomains");if r.Method=="OPTIONS"{w.WriteHeader(204);return};next.ServeHTTP(w,r)})}

func min(a,b uint32)uint32{if a<b{return a};return b}

func startNetwork(netID uint32,port int){bc:=NewBlockchain(netID);rpc:=&RPC{bc:bc};go func(){ticker:=time.NewTicker(time.Duration(BlockTime)*time.Second);for range ticker.C{bc.AddBlock()}}();mux:=http.NewServeMux();routes:=map[string]http.HandlerFunc{"/balance":rpc.handleBalance,"/send":rpc.handleSendTx,"/stake":rpc.handleStake,"/wallet":rpc.handleCreateWallet,"/info":rpc.handleInfo};for path,handler:=range routes{mux.Handle(path,cors(rpc.security(http.HandlerFunc(handler))))};netName:="MainNet";if netID==TestNetID{netName="TestNet"};log.Printf("Starting %s on port %d",netName,port);log.Fatal(http.ListenAndServe(":"+strconv.Itoa(port),mux))}

func main(){netID:=uint32(MainNetID);port:=MainPort;if len(os.Args)>1&&os.Args[1]=="testnet"{netID=TestNetID;port=TestPort};log.Printf("Initializing WolfEther blockchain node...");startNetwork(netID,port)}

