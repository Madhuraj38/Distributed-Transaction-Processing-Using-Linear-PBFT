package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type Transaction struct {
	SeqId    int
	Sender   string
	Receiver string
	Amount   int
}

type TransactionSet struct {
	SetNumber        int
	Transactions     []Transaction
	LiveServers      []int
	ByzantineServers []int
}

type ClientRequest struct {
	ClientID    string
	Transaction Transaction
	Timestamp   int64
	Signature   []byte
}

type Response struct {
	ViewNumber int
	Timestamp  int64
	ClientID   string
	ReplicaID  int
	Result     string
	Success    bool
}
type SignedResponse struct {
	Reply     Response
	Signature []byte
}

var logger *log.Logger
var peers = []string{"localhost:8001", "localhost:8002", "localhost:8003", "localhost:8004", "localhost:8005", "localhost:8006", "localhost:8007"}
var clientIDs = []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J"}
var leaderPort = peers[0]
var suite = bn256.NewSuite()

const (
	initialBalance = 10
	f              = 2
	clientTimeout  = 2000 * time.Millisecond
)

type Dispatcher struct {
	clients map[string]*Client
}

type Client struct {
	id string
	// leaderPort  string
	balance     int
	responseMap map[string][]Response
	timer       *time.Timer
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	replicaKeys map[int]*rsa.PublicKey
	mu          sync.Mutex
	replyCh     chan bool
}

func NewClient(id string, leaderPort string, privateKey *rsa.PrivateKey, replicaKeys map[int]*rsa.PublicKey) *Client {
	return &Client{
		id:          id,
		balance:     initialBalance,
		privateKey:  privateKey,
		publicKey:   &privateKey.PublicKey,
		replicaKeys: replicaKeys,
		responseMap: make(map[string][]Response),
		replyCh:     make(chan bool),
	}
}

func StartListener(dispatcher *Dispatcher) {
	rpc.Register(dispatcher)
	listener, err := net.Listen("tcp", "localhost:9000")
	if err != nil {
		logger.Fatalf("Failed to listen on port 9000: %v", err)
	}
	// defer listener.Close()

	logger.Println("Dispatcher listening on localhost:9000")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				logger.Printf("Error accepting connection: %v", err)
				continue
			}
			go rpc.ServeConn(conn)
		}
	}()
}

func (c *Client) startTimer(request ClientRequest) {
	if c.timer != nil {
		c.timer.Stop()
	}
	logger.Printf("[clientTimer] Timer started/reset for client %s for request %d", c.id, request.Transaction.SeqId)
	c.timer = time.AfterFunc(clientTimeout, func() {
		logger.Printf("[clientTimer] Timer expired for client %s on request %d, broadcasting request", c.id, request.Transaction.SeqId)
		c.broadcastTransaction(request)
	})
}

func (d *Dispatcher) RegisterClient(client *Client) {
	d.clients[client.id] = client
}

func (c *Client) SignRequest(request *ClientRequest) error {
	dataToSign := fmt.Sprintf("%s%v%v", request.ClientID, request.Transaction, request.Timestamp)
	hash := sha256.Sum256([]byte(dataToSign))
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, 0, hash[:])
	if err != nil {
		return err
	}
	request.Signature = signature
	return nil
}

func VerifyRequestSignature(request *ClientRequest, clientPublicKey *rsa.PublicKey) bool {
	dataToVerify := fmt.Sprintf("%s%v%v", request.ClientID, request.Transaction, request.Timestamp)
	hash := sha256.Sum256([]byte(dataToVerify))
	err := rsa.VerifyPKCS1v15(clientPublicKey, 0, hash[:], request.Signature)
	return err == nil
}

func (c *Client) SendRequest(transaction Transaction, pbftReplicas []*PBFT) {
	timestamp := time.Now().UnixNano()

	request := ClientRequest{
		ClientID:    c.id,
		Transaction: transaction,
		Timestamp:   timestamp,
	}

	err := c.SignRequest(&request)
	if err != nil {
		logger.Printf("Error signing request: %v", err)
		return
	}

	logger.Printf("request sent from client %s to leader %s \n", c.id, leaderPort)
	call(leaderPort, "PBFT.HandleRequest", request, nil)
	c.startTimer(request)

	if <-c.replyCh {
		logger.Printf("Client %s: Transaction %v completed successfully.", c.id, transaction)
		c.timer.Stop()
	}
}

func (c *Client) broadcastTransaction(request ClientRequest) {
	// for _, peerPort := range peers {
	// 	go func(port string) {
	call(leaderPort, "PBFT.HandleRequest", request, nil)
	c.startTimer(request)
	// 	}(peerPort)
	// }
}

func (d *Dispatcher) HandleReply(signedReply SignedResponse, reply *bool) error {
	clientID := signedReply.Reply.ClientID
	client, exists := d.clients[clientID]

	if !exists {
		logger.Printf("No registered client with ID %s", clientID)
		*reply = false
		return fmt.Errorf("client ID not found")
	}
	return client.HandleClientReply(signedReply, reply)
}

func (c *Client) HandleClientReply(signedReply SignedResponse, reply1 *bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	reply := signedReply.Reply
	logger.Printf("Client %s received reply from replica %d", reply.ClientID, reply.ReplicaID)
	replicaPubKey, exists := c.replicaKeys[reply.ReplicaID]
	if !exists {
		logger.Printf("Unknown replica ID: %d", reply.ReplicaID)
		return fmt.Errorf("unknown replica ID")
	}

	dataToVerify := fmt.Sprintf("%d%d%s%d%s%t", reply.ViewNumber, reply.Timestamp, reply.ClientID, reply.ReplicaID, reply.Result, reply.Success)
	hash := sha256.Sum256([]byte(dataToVerify))
	err := rsa.VerifyPKCS1v15(replicaPubKey, 0, hash[:], signedReply.Signature)
	if err != nil {
		logger.Printf("Invalid signature from replica %d: %v", reply.ReplicaID, err)
		return fmt.Errorf("invalid signature")
	}

	requestID := fmt.Sprintf("%s_%d", reply.ClientID, reply.Timestamp)
	c.responseMap[requestID] = append(c.responseMap[requestID], reply)

	if len(c.responseMap[requestID]) >= f+1 {
		successReplies := 0
		failedReplies := 0
		var result string
		for _, r := range c.responseMap[requestID] {
			if r.Success {
				successReplies++
				result = r.Result
			} else {
				failedReplies++
			}
		}

		if successReplies >= (f+1) || failedReplies >= (f+1) {
			logger.Printf("Client %s received %d successful replies : %s", c.id, successReplies, result)
			newLeaderPort := peers[reply.ViewNumber%len(peers)]
			if newLeaderPort != leaderPort {
				fmt.Printf("Client %s updating leader to %s for view %d\n", c.id, newLeaderPort, reply.ViewNumber)
				leaderPort = newLeaderPort
			}

			delete(c.responseMap, requestID)
			c.replyCh <- true
		}
	}
	*reply1 = true
	return nil
}

func initLogger() {
	file, err := os.OpenFile("pbft.log", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	logger = log.New(file, "LOG: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func ParseTransactionsFromCSV(filename string) ([]TransactionSet, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var transactionSets []TransactionSet
	var currentSet TransactionSet

	for i, record := range records {
		if i == 0 {
			record[0] = strings.TrimPrefix(record[0], "\ufeff")
		}

		if record[0] != "" {
			setNumber, _ := strconv.Atoi(record[0])
			if setNumber != currentSet.SetNumber {
				if currentSet.SetNumber != 0 {
					transactionSets = append(transactionSets, currentSet)
				}
				currentSet = TransactionSet{
					SetNumber:        setNumber,
					LiveServers:      parseServerList(record[2]),
					ByzantineServers: parseServerList(record[3]),
				}
			}
		}

		tx := parseTransaction(record[1])
		currentSet.Transactions = append(currentSet.Transactions, tx)
	}

	if currentSet.SetNumber != 0 {
		transactionSets = append(transactionSets, currentSet)
	}

	return transactionSets, nil
}

func parseTransaction(input string) Transaction {
	input = strings.Trim(input, "()")
	parts := strings.Split(input, ",")
	amount, _ := strconv.Atoi(strings.TrimSpace(parts[2]))
	return Transaction{
		Sender:   strings.TrimSpace(parts[0]),
		Receiver: strings.TrimSpace(parts[1]),
		Amount:   amount,
	}
}

func parseServerList(input string) []int {
	input = strings.Trim(input, "[]")
	serverStrings := strings.Split(input, ",")
	var servers []int

	for _, server := range serverStrings {
		server = strings.TrimSpace(server)
		if len(server) > 1 && server[0] == 'S' {
			if num, err := strconv.Atoi(server[1:]); err == nil {
				servers = append(servers, num-1)
			}
		}
	}

	return servers
}

func GenerateKeys(numReplicas int) (map[string]*rsa.PrivateKey, map[string]*rsa.PublicKey, map[int]*rsa.PrivateKey, map[int]*rsa.PublicKey) {
	clientPrivateKeys := make(map[string]*rsa.PrivateKey)
	clientPublicKeys := make(map[string]*rsa.PublicKey)
	replicaPrivateKeys := make(map[int]*rsa.PrivateKey)
	replicaPublicKeys := make(map[int]*rsa.PublicKey)

	for _, clientID := range clientIDs {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			logger.Fatalf("Failed to generate key for %s: %v", clientID, err)
		}
		clientPrivateKeys[clientID] = privateKey
		clientPublicKeys[clientID] = &privateKey.PublicKey
	}

	for i := 0; i < numReplicas; i++ {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			logger.Fatalf("Failed to generate key for Replica%d: %v", i, err)
		}
		replicaPrivateKeys[i] = privateKey
		replicaPublicKeys[i] = &privateKey.PublicKey
	}

	return clientPrivateKeys, clientPublicKeys, replicaPrivateKeys, replicaPublicKeys
}

func processTransactionSet(set TransactionSet, clients map[string]*Client, pbftReplicas []*PBFT) {
	txByClient := make(map[string][]Transaction)

	for _, tx := range set.Transactions {
		clientIndex := tx.Sender
		txByClient[clientIndex] = append(txByClient[clientIndex], tx)
	}
	fmt.Println("Processing...")
	for clientIndex, transactions := range txByClient {
		go func(clientID string, transactions []Transaction) {
			for _, tx := range transactions {
				clients[clientID].SendRequest(tx, pbftReplicas)
			}
		}(clientIndex, transactions)
	}
}

func PrintAllDB(replicas []*PBFT) {

	fmt.Printf("Server")
	for _, clientID := range clientIDs {
		fmt.Printf("\t%s", clientID)
	}
	fmt.Println()

	for i, replica := range replicas {
		balances := replica.PrintDB()
		fmt.Printf("S%d", i+1)
		for _, clientID := range clientIDs {
			fmt.Printf("\t%d", balances[clientID])
		}
		fmt.Println()
	}
}

func PrintAllLog(replicas []*PBFT) {
	fmt.Println("\n\nLogs of all replicas:")

	for i, replica := range replicas {
		logEntries := replica.PrintLog()
		fmt.Printf("Replica S%d:\n", i+1)
		for _, entry := range logEntries {
			fmt.Println(entry)
		}
		fmt.Println()
	}
}

func PrintAllStatus(replicas []*PBFT, sequenceNum int) {
	fmt.Printf("Status of transaction with sequence number %d across all replicas:\n", sequenceNum)
	fmt.Printf("Server")
	for i := range replicas {
		fmt.Printf(" S%d", i+1)
	}
	fmt.Println()

	fmt.Printf("Status")
	for _, replica := range replicas {
		status := replica.PrintStatus(sequenceNum)
		fmt.Printf(" %s", status)
	}
	fmt.Println()
}

func PrintAllView(replicas []*PBFT) {
	fmt.Println("\nNew View Log of all replicas:")

	for _, replica := range replicas {
		replica.PrintView()
	}
}

func main() {

	initLogger()

	transactionSets, err := ParseTransactionsFromCSV("test(Lab2 - PBFT).csv")
	if err != nil {
		logger.Fatalf("Error parsing transactions: %v", err)
	}
	var testCaseNum int
	for {
		fmt.Print("Enter test case number (1-10) to process PBFT: ")
		_, err := fmt.Scanln(&testCaseNum)
		if err != nil {
			fmt.Printf("Invalid input. Please enter a number between 1 and 10.")
			continue
		}
		if testCaseNum >= 1 && testCaseNum <= 10 {
			break
		} else {
			fmt.Println("Please enter a number between 1 and 10.")
		}
	}

	numReplicas := len(peers)

	clients := make(map[string]*Client)
	pbftReplicas := make([]*PBFT, numReplicas)
	liveservers := make(map[int]bool)
	dispatcher := &Dispatcher{clients: make(map[string]*Client)}
	secret := suite.G2().Scalar().Pick(suite.RandomStream())
	threshold := 2*f + 1
	priPoly := share.NewPriPoly(suite.G2(), threshold, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	replicaShares := priPoly.Shares(numReplicas)

	thresholdN := 3*f + 1
	priPolyN := share.NewPriPoly(suite.G2(), thresholdN, secret, suite.RandomStream())
	pubPolyN := priPolyN.Commit(suite.G2().Point().Base())
	replicaSharesN := priPolyN.Shares(numReplicas)

	clientPrivateKeys, clientPublicKeys, replicaPrivateKeys, replicaPublicKeys := GenerateKeys(numReplicas)

	for _, clientID := range clientIDs {
		clients[clientID] = NewClient(clientID, peers[0], clientPrivateKeys[clientID], replicaPublicKeys)
		dispatcher.RegisterClient(clients[clientID])
	}
	StartListener(dispatcher)
	for i := 0; i < numReplicas; i++ {
		pbftReplicas[i] = NewPBFTServer(i, 0, peers, replicaPrivateKeys[i], clientPublicKeys, replicaPublicKeys, replicaShares[i], pubPoly, replicaSharesN[i], pubPolyN)
		pbftReplicas[i].privateKey = replicaPrivateKeys[i]
		liveservers[i] = false
		pbftReplicas[i].InitializeBalances(clientIDs, initialBalance)
	}

	reader := bufio.NewReader(os.Stdin)

	set := transactionSets[testCaseNum-1]

	for _, replicaID := range set.LiveServers {
		liveservers[replicaID] = true
	}

	for _, replicaID := range set.ByzantineServers {
		pbftReplicas[replicaID].byzantine = true
	}

	for i := 0; i < numReplicas; i++ {
		if !liveservers[i] {
			logger.Printf("liveserver %d is %t so killing", i+1, liveservers[i])
			pbftReplicas[i].Kill()
		}
	}
	fmt.Printf("Started processing transactions of set %d\n", set.SetNumber)
	processTransactionSet(set, clients, pbftReplicas)

	// }
	time.Sleep(10 * time.Second)
	fmt.Println("\nAll transactions in the set have been processed.")
	fmt.Println("Press Enter to view results...")
	reader.ReadString('\n')
	PrintAllDB(pbftReplicas)
	PrintAllLog(pbftReplicas)
	PrintAllStatus(pbftReplicas, 1)
	PrintAllView(pbftReplicas)
	for i := 0; i < numReplicas; i++ {
		pbftReplicas[i].Kill()
	}
}
