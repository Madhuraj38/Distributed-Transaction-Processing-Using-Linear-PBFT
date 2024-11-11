// pbft.go
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	// "log"
	"net"
	"net/rpc"

	// "os"
	// "strings"
	"sync"

	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

type PBFT struct {
	mu        sync.Mutex
	view      int
	primaryID int
	// checkpointSeq int
	sequenceNum         int
	executedSeq         int
	replicaID           int
	byzantine           bool
	peers               []string
	dead                bool
	l                   net.Listener
	privateKey          *rsa.PrivateKey
	publicKey           *rsa.PublicKey
	clientKeys          map[string]*rsa.PublicKey
	replicaKeys         map[int]*rsa.PublicKey
	transactionLog      []string
	statusMap           map[int]string
	balances            map[string]int
	priPoly             *share.PriShare
	publicPoly          *share.PubPoly
	priPolyN            *share.PriShare
	publicPolyN         *share.PubPoly
	prepareMessages     map[int][][]byte
	prepareMessagesN    map[int][][]byte
	commitMessages      map[int][][]byte
	thresholdSignatures map[int][]byte
	pendingResponses    map[int]*Response
	pendingTrans        int
	requestData         map[int]SignedPrePrepareMessage
	newViewLogMessages  []NewViewMessage
	viewChangeMessages  map[int][]ViewChangeMessage
	timer1              *time.Timer
	timer2              *time.Timer
	isActiveTimer       bool
	viewChangeTriggered bool
	lastReplies         map[string]bool
}

type SignedPrePrepareMessage struct {
	View      int
	Sequence  int
	Digest    []byte
	ClientReq ClientRequest
}

type PrePrepareMessage struct {
	SignedMessage SignedPrePrepareMessage
	Signature     []byte
}

type SignedPrepareMessage struct {
	View     int
	Sequence int
	Digest   []byte
}

type PrepareMessage struct {
	SignedMessage   SignedPrepareMessage
	Signature       []byte
	SignatureShare  []byte
	SignatureShareN []byte
	ReplicaID       int
}

type SignedCommitMessage struct {
	View     int
	Sequence int
	Digest   []byte
}

type CommitMessage struct {
	SignedMessage  SignedCommitMessage
	Signature      []byte
	SignatureShare []byte
	ReplicaID      int
}

type SignedCombinedMessage struct {
	View     int
	Sequence int
	Digest   []byte
}

type CombinedMessage struct {
	SignedMessage      SignedCombinedMessage
	Signature          []byte
	ThresholdSignature []byte
	ThresholdLength    int
}

type SignedViewChangeMessage struct {
	View      int
	ReplicaID int
	SeqNum    int
	Prepare   []PrepareMessage
}

type ViewChangeMessage struct {
	SignedMessage SignedViewChangeMessage
	Signature     []byte
}

type SignedNewViewMessage struct {
	View                int
	ValidViewChanges    []ViewChangeMessage
	OutstandingRequests []PrePrepareMessage
}

type NewViewMessage struct {
	SignedMessage SignedNewViewMessage
	Signature     []byte
}

const (
	H = 100
)

func (pbft *PBFT) PrePrepare(request ClientRequest, sequenceNumber int) {
	pbft.mu.Lock()
	logger.Printf("[PrePrepare] Replica %d (Primary) received client request for sequence %d", pbft.replicaID, sequenceNumber)
	logEntry := fmt.Sprintf("Replica %d (Primary) Received Client request ", pbft.replicaID)
	pbft.transactionLog = append(pbft.transactionLog, logEntry)
	digest := sha256.Sum256([]byte(fmt.Sprintf("%v%v%s%x", request.Transaction, request.Timestamp, request.ClientID, request.Signature)))

	signedMessage := SignedPrePrepareMessage{
		View:      pbft.view,
		Sequence:  sequenceNumber,
		Digest:    digest[:],
		ClientReq: request,
	}

	signature, err := SignStruct(signedMessage, pbft.privateKey)
	if err != nil {
		pbft.mu.Unlock()
		return
	}
	prePrepareMsg := PrePrepareMessage{
		SignedMessage: signedMessage,
		Signature:     signature,
	}
	pbft.mu.Unlock()
	for _, peer := range pbft.peers {
		// if peer != pbft.peers[pbft.primaryID] {
		logger.Printf("[PrePrepare] Replica %d (Primary) sending PrePrepare to port %s for sequence %d", pbft.replicaID, peer, sequenceNumber)
		var reply bool
		go call(peer, "PBFT.HandlePrePrepare", prePrepareMsg, &reply)
		// }
	}
}

func (pbft *PBFT) HandlePrePrepare(msg PrePrepareMessage, reply *bool) error {
	pbft.mu.Lock()
	if pbft.viewChangeTriggered {
		pbft.mu.Unlock()
		return nil
	}
	logger.Printf("[HandlePrePrepare] Replica %d received PrePrepare for sequence %d", pbft.replicaID, msg.SignedMessage.Sequence)

	if !VerifyStructSignature(msg.SignedMessage, msg.Signature, pbft.replicaKeys[pbft.primaryID]) {
		logger.Printf("Replica %d failed to verify pre-prepare message from primary", pbft.replicaID)
		pbft.mu.Unlock()
		return fmt.Errorf("invalid signature on pre-prepare message")
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%v%v%s%x", msg.SignedMessage.ClientReq.Transaction, msg.SignedMessage.ClientReq.Timestamp, msg.SignedMessage.ClientReq.ClientID, msg.SignedMessage.ClientReq.Signature)))

	if !bytes.Equal(msg.SignedMessage.Digest, digest[:]) || msg.SignedMessage.View != pbft.view || (msg.SignedMessage.Sequence < 0 || msg.SignedMessage.Sequence > H) {
		pbft.mu.Unlock()
		return nil
	}

	requestMessage := SignedPrePrepareMessage{
		View:      msg.SignedMessage.View,
		Sequence:  msg.SignedMessage.Sequence,
		Digest:    msg.SignedMessage.Digest,
		ClientReq: msg.SignedMessage.ClientReq,
	}
	pbft.requestData[msg.SignedMessage.Sequence] = requestMessage

	logEntry := fmt.Sprintf("Received PRE-PREPARE for sequence %d from primary with view %d", msg.SignedMessage.Sequence, msg.SignedMessage.View)
	pbft.transactionLog = append(pbft.transactionLog, logEntry)
	pbft.statusMap[msg.SignedMessage.Sequence] = "PP"

	if pbft.byzantine {
		logger.Printf("[HandlePrePrepare] [Byzantine] Replica %d not Preparing messages for sequence %d", pbft.replicaID, msg.SignedMessage.Sequence)
		pbft.mu.Unlock()
		return nil
	}
	signedMessage := SignedPrepareMessage{
		View:     msg.SignedMessage.View,
		Sequence: msg.SignedMessage.Sequence,
		Digest:   msg.SignedMessage.Digest,
	}
	primary := pbft.peers[pbft.primaryID]

	signature, err := SignStruct(signedMessage, pbft.privateKey)
	if err != nil {
		pbft.mu.Unlock()
		return err
	}
	messageHash, _ := HashMessage(signedMessage)
	signatureShare, err := tbls.Sign(suite, pbft.priPoly, messageHash)
	if err != nil {
		logger.Printf("Error generating signature share: %v", err)
		pbft.mu.Unlock()
		return err
	}
	signatureShareN, err := tbls.Sign(suite, pbft.priPolyN, messageHash)
	if err != nil {
		logger.Printf("Error generating signature share: %v", err)
		pbft.mu.Unlock()
		return err
	}
	prepareMsg := PrepareMessage{
		SignedMessage:   signedMessage,
		Signature:       signature,
		SignatureShare:  signatureShare,
		SignatureShareN: signatureShareN,
		ReplicaID:       pbft.replicaID,
	}
	logger.Printf("[HandlePrePrepare] Replica %d sending Prepare message for sequence %d", pbft.replicaID, msg.SignedMessage.Sequence)
	if !pbft.isActiveTimer {
		pbft.isActiveTimer = true
		pbft.mu.Unlock()
		pbft.startTimer1()
	} else {
		pbft.mu.Unlock()
	}
	var reply1 bool
	go call(primary, "PBFT.CollectPrepare", prepareMsg, &reply1)
	*reply = true
	return nil
}

func (pbft *PBFT) CollectPrepare(msg PrepareMessage, reply *bool) error {
	pbft.mu.Lock()
	if pbft.viewChangeTriggered {
		pbft.mu.Unlock()
		return nil
	}
	logger.Printf("[CollectPrepare] Primary received Prepare for sequence %d from replica %d", msg.SignedMessage.Sequence, msg.ReplicaID)

	if pbft.byzantine {
		logger.Printf("[CollectPrepare] [Byzantine] Leader %d found not preparing messages for sequence %d", pbft.replicaID, msg.SignedMessage.Sequence)
		pbft.mu.Unlock()
		return nil
	}
	if !VerifyStructSignature(msg.SignedMessage, msg.Signature, pbft.replicaKeys[msg.ReplicaID]) {
		logger.Printf("Replica %d failed to verify prepare message to primary", pbft.replicaID)
		pbft.mu.Unlock()
		return fmt.Errorf("invalid signature on prepare message")
	}

	if msg.SignedMessage.View != pbft.view || msg.SignedMessage.Sequence < 0 || msg.SignedMessage.Sequence > H {
		pbft.mu.Unlock()
		return nil
	}

	pbft.prepareMessages[msg.SignedMessage.Sequence] = append(pbft.prepareMessages[msg.SignedMessage.Sequence], msg.SignatureShare)
	pbft.prepareMessagesN[msg.SignedMessage.Sequence] = append(pbft.prepareMessagesN[msg.SignedMessage.Sequence], msg.SignatureShareN)
	thresholdLength := len(pbft.prepareMessages[msg.SignedMessage.Sequence])
	thresholdLengthN := len(pbft.prepareMessagesN[msg.SignedMessage.Sequence])
	if thresholdLength == 2*f+1 || thresholdLengthN == 3*f+1 {
		logger.Printf("[CollectPrepare] Primary has enough Prepare messages to generate threshold signature for sequence %d", msg.SignedMessage.Sequence)

		messageHash, _ := HashMessage(msg.SignedMessage)
		// logger.Printf("Hash message %v for sequence %d", messageHash, msg.SignedMessage.Sequence)
		var thresholdSignature []byte
		var length int
		if thresholdLength == 2*f+1 {
			thresholdSign, err := tbls.Recover(suite, pbft.publicPoly, messageHash, pbft.prepareMessages[msg.SignedMessage.Sequence], 2*f+1, len(pbft.peers))
			pbft.thresholdSignatures[msg.SignedMessage.Sequence] = thresholdSign
			thresholdSignature = thresholdSign
			length = thresholdLength
			if err != nil {
				logger.Printf("Failed to recover threshold signature: %v", err)
				pbft.mu.Unlock()
				return fmt.Errorf("threshold signature recovery failed")
			}
		}
		if thresholdLengthN == 3*f+1 {
			thresholdSign, err := tbls.Recover(suite, pbft.publicPolyN, messageHash, pbft.prepareMessagesN[msg.SignedMessage.Sequence], 3*f+1, len(pbft.peers))
			thresholdSignature = thresholdSign
			length = thresholdLengthN
			if err != nil {
				logger.Printf("Failed to recover threshold signature: %v", err)
				pbft.mu.Unlock()
				return fmt.Errorf("threshold signature recovery failed")
			}
		}
		// logger.Printf("Threshold signature for sequence %d: %x", msg.SignedMessage.Sequence, thresholdSignature)

		signedMessage := SignedCombinedMessage{
			View:     msg.SignedMessage.View,
			Sequence: msg.SignedMessage.Sequence,
			Digest:   msg.SignedMessage.Digest,
		}
		signature, _ := SignStruct(signedMessage, pbft.privateKey)

		combinedMsg := CombinedMessage{
			SignedMessage:      signedMessage,
			ThresholdSignature: thresholdSignature,
			ThresholdLength:    length,
			Signature:          signature,
		}
		logger.Printf("[CollectPrepare] Sending Combined Prepare message for sequence %d to all replicas", msg.SignedMessage.Sequence)
		pbft.mu.Unlock()
		for _, peer := range pbft.peers {
			if peer != pbft.peers[pbft.primaryID] {
				var reply1 bool
				go call(peer, "PBFT.HandleCombinedPrepare", combinedMsg, &reply1)
			} else {
				var reply1 bool
				pbft.HandleCombinedPrepare(combinedMsg, &reply1)
			}
		}
	} else {
		pbft.mu.Unlock()
	}

	*reply = true
	return nil
}

func (pbft *PBFT) HandleCombinedPrepare(msg CombinedMessage, reply *bool) error {
	pbft.mu.Lock()
	if pbft.viewChangeTriggered {
		pbft.mu.Unlock()
		return nil
	}
	logger.Printf("[HandleCombinedPrepare] Replica %d received Combined Prepare for sequence %d", pbft.replicaID, msg.SignedMessage.Sequence)
	logEntry := fmt.Sprintf("Received PREPARE for sequence %d from replica %d with view %d", msg.SignedMessage.Sequence, pbft.primaryID, msg.SignedMessage.View)
	pbft.transactionLog = append(pbft.transactionLog, logEntry)

	if pbft.byzantine {
		logger.Printf("[HandleCombinedPrepare] [Byzantine] Replica %d wont send commit message for sequence %d", pbft.replicaID, msg.SignedMessage.Sequence)
		pbft.mu.Unlock()
		return nil
	}

	if !VerifyStructSignature(msg.SignedMessage, msg.Signature, pbft.replicaKeys[pbft.primaryID]) {
		logger.Printf("Replica %d failed to verify combined prepare message from primary", pbft.replicaID)
		pbft.mu.Unlock()
		return fmt.Errorf("invalid signature on prepared message")
	}

	verifyPrepareMessage := SignedPrepareMessage{
		View:     pbft.requestData[msg.SignedMessage.Sequence].View,
		Sequence: pbft.requestData[msg.SignedMessage.Sequence].Sequence,
		Digest:   pbft.requestData[msg.SignedMessage.Sequence].Digest,
	}

	messageVerifyHash, _ := HashMessage(verifyPrepareMessage)
	// logger.Printf("Signature on Replica %d for sequence %d : %v", pbft.replicaID, msg.SignedMessage.Sequence, msg.ThresholdSignature)
	// logger.Printf("Verify Hash message %v on replica %d for sequence %d", messageVerifyHash, pbft.replicaID, msg.SignedMessage.Sequence)
	// logger.Printf("Verify prepare message %v on replica %d for sequence %d", verifyPrepareMessage, pbft.replicaID, msg.SignedMessage.Sequence)
	if msg.ThresholdLength == 3*f+1 {
		err := bls.Verify(suite, pbft.publicPolyN.Commit(), messageVerifyHash, msg.ThresholdSignature)
		if err != nil {
			logger.Printf("Replica %d failed to verify threshold signature on combined prepare message for sequence %d : %v", pbft.replicaID, msg.SignedMessage.Sequence, err)
			pbft.mu.Unlock()
			return fmt.Errorf("invalid threshold signature on combined prepare message")
		}
		pbft.pendingTrans++
		pbft.statusMap[msg.SignedMessage.Sequence] = "C"
		logger.Printf("[HandleCombinedPrepare] Replica %d has 3f+1 signatures moving to execution phase for sequence %d", pbft.replicaID, msg.SignedMessage.Sequence)
		pbft.mu.Unlock()
		go pbft.ExecuteRequest(msg)
		pbft.mu.Lock()
	} else {
		err := bls.Verify(suite, pbft.publicPoly.Commit(), messageVerifyHash, msg.ThresholdSignature)
		if err != nil {
			logger.Printf("Replica %d failed to verify threshold signature on combined prepare message for sequence %d : %v", pbft.replicaID, msg.SignedMessage.Sequence, err)
			pbft.mu.Unlock()
			return fmt.Errorf("invalid threshold signature on combined prepare message")
		}

		if msg.SignedMessage.View != pbft.view || msg.SignedMessage.Sequence < 0 || msg.SignedMessage.Sequence > H || pbft.statusMap[msg.SignedMessage.Sequence] != "PP" {
			pbft.mu.Unlock()
			return nil
		}
		pbft.pendingTrans++
		pbft.statusMap[msg.SignedMessage.Sequence] = "P"

		signedMessage := SignedCommitMessage{
			View:     msg.SignedMessage.View,
			Sequence: msg.SignedMessage.Sequence,
			Digest:   msg.SignedMessage.Digest,
		}

		signature, _ := SignStruct(signedMessage, pbft.privateKey)
		messageHash, _ := HashMessage(signedMessage)
		signatureShare, err := tbls.Sign(suite, pbft.priPoly, messageHash)
		if err != nil {
			logger.Printf("Error generating signature share: %v", err)
			pbft.mu.Unlock()
			return err
		}
		commitMsg := CommitMessage{
			SignedMessage:  signedMessage,
			Signature:      signature,
			SignatureShare: signatureShare,
			ReplicaID:      pbft.replicaID,
		}
		logger.Printf("[HandleCombinedPrepare] Replica %d moving to Commit phase for sequence %d", pbft.replicaID, msg.SignedMessage.Sequence)
		primary := pbft.peers[pbft.primaryID]
		pbft.mu.Unlock()
		var reply1 bool
		go call(primary, "PBFT.CollectCommit", commitMsg, &reply1)
		pbft.mu.Lock()
	}
	pbft.mu.Unlock()
	*reply = true
	return nil
}

func (pbft *PBFT) CollectCommit(msg CommitMessage, reply *bool) error {
	pbft.mu.Lock()
	if pbft.viewChangeTriggered {
		pbft.mu.Unlock()
		return nil
	}
	requestKey := fmt.Sprintf("%s:%d", pbft.requestData[msg.SignedMessage.Sequence].ClientReq.ClientID, pbft.requestData[msg.SignedMessage.Sequence].ClientReq.Timestamp)
	if pbft.lastReplies[requestKey] {
		logger.Printf("Replica %d execution aborted because of transaction complete for sequence number %d", pbft.replicaID, msg.SignedMessage.Sequence)
		pbft.mu.Unlock()
		return nil
	}
	logger.Printf("[CollectCommit] Primary received Commit for sequence %d from replica %d", msg.SignedMessage.Sequence, msg.ReplicaID)
	if pbft.byzantine {
		logger.Printf("[CollectCommit] [Byzantine] Leader %d not sending commit messages for sequence %d", pbft.replicaID, msg.SignedMessage.Sequence)
		pbft.mu.Unlock()
		return nil
	}
	if !VerifyStructSignature(msg.SignedMessage, msg.Signature, pbft.replicaKeys[msg.ReplicaID]) {
		logger.Printf("Replica %d failed to verify combined prepare message from primary", pbft.replicaID)
		pbft.mu.Unlock()
		return fmt.Errorf("invalid signature on commit message")
	}

	if msg.SignedMessage.View != pbft.view || msg.SignedMessage.Sequence < 0 || msg.SignedMessage.Sequence > H {
		pbft.mu.Unlock()
		return nil
	}

	pbft.commitMessages[msg.SignedMessage.Sequence] = append(pbft.commitMessages[msg.SignedMessage.Sequence], msg.SignatureShare)

	if len(pbft.commitMessages[msg.SignedMessage.Sequence]) == 2*f+1 {
		logger.Printf("[CollectCommit] Primary has enough Commit messages to generate threshold signature for sequence %d", msg.SignedMessage.Sequence)

		messageHash, _ := HashMessage(msg.SignedMessage)
		thresholdSignature, err := tbls.Recover(suite, pbft.publicPoly, messageHash, pbft.commitMessages[msg.SignedMessage.Sequence], 2*f+1, len(pbft.peers))

		if err != nil {
			logger.Printf("Failed to recover threshold signature: %v", err)
			pbft.mu.Unlock()
			return fmt.Errorf("threshold signature recovery failed")
		}

		signedMessage := SignedCombinedMessage{
			View:     msg.SignedMessage.View,
			Sequence: msg.SignedMessage.Sequence,
			Digest:   msg.SignedMessage.Digest,
		}
		signature, _ := SignStruct(signedMessage, pbft.privateKey)

		combinedCommitMsg := CombinedMessage{
			SignedMessage:      signedMessage,
			ThresholdSignature: thresholdSignature,
			Signature:          signature,
		}

		logger.Printf("[CollectCommit] Sending Combined Commit message for sequence %d to all replicas", msg.SignedMessage.Sequence)
		pbft.mu.Unlock()
		for _, peer := range pbft.peers {
			if peer != pbft.peers[pbft.primaryID] {
				var reply1 bool
				go call(peer, "PBFT.HandleFinalCommit", combinedCommitMsg, &reply1)
			} else {
				var reply1 bool
				pbft.HandleFinalCommit(combinedCommitMsg, &reply1)
			}
		}
	} else {
		pbft.mu.Unlock()
	}

	*reply = true
	return nil
}

func (pbft *PBFT) HandleFinalCommit(msg CombinedMessage, reply *bool) error {
	pbft.mu.Lock()
	if pbft.viewChangeTriggered {
		pbft.mu.Unlock()
		return nil
	}
	logger.Printf("[HandleFinalCommit] Replica %d received Combined Commit for sequence %d", pbft.replicaID, msg.SignedMessage.Sequence)
	logEntry := fmt.Sprintf("Received final COMMIT for sequence %d from primary with view %d", msg.SignedMessage.Sequence, msg.SignedMessage.View)
	pbft.transactionLog = append(pbft.transactionLog, logEntry)
	if pbft.byzantine {
		logger.Printf("[HandleFinalCommit] [Byzantine] Replica %d not executing operation for sequence %d", pbft.replicaID, msg.SignedMessage.Sequence)
		pbft.mu.Unlock()
		return nil
	}
	if !VerifyStructSignature(msg.SignedMessage, msg.Signature, pbft.replicaKeys[pbft.primaryID]) {
		logger.Printf("Replica %d failed to verify combined commit message from primary", pbft.replicaID)
		pbft.mu.Unlock()
		return fmt.Errorf("invalid signature on commited message")
	}

	verifyCommitMessage := SignedCommitMessage{
		View:     pbft.requestData[msg.SignedMessage.Sequence].View,
		Sequence: pbft.requestData[msg.SignedMessage.Sequence].Sequence,
		Digest:   pbft.requestData[msg.SignedMessage.Sequence].Digest,
	}
	messageVerifyHash, _ := HashMessage(verifyCommitMessage)
	// logger.Printf("Signature on Replica %d for sequence %d : %v", pbft.replicaID, msg.SignedMessage.Sequence, msg.ThresholdSignature)
	// logger.Printf("Verify Hash message %v on replica %d for sequence %d", messageVerifyHash, pbft.replicaID, msg.SignedMessage.Sequence)
	err := bls.Verify(suite, pbft.publicPoly.Commit(), messageVerifyHash, msg.ThresholdSignature)
	if err != nil {
		logger.Printf("Replica %d failed to verify threshold signature on combined commit message for sequence %d : %v", pbft.replicaID, msg.SignedMessage.Sequence, err)
		pbft.mu.Unlock()
		return fmt.Errorf("invalid threshold signature on combined commit message")
	}

	if msg.SignedMessage.View != pbft.view || msg.SignedMessage.Sequence < 0 || msg.SignedMessage.Sequence > H || pbft.statusMap[msg.SignedMessage.Sequence] != "P" {
		pbft.mu.Unlock()
		return nil
	}

	pbft.statusMap[msg.SignedMessage.Sequence] = "C"
	logger.Printf("[HandleFinalCommit] Replica %d moving to Execution phase for sequence %d", pbft.replicaID, msg.SignedMessage.Sequence)
	pbft.mu.Unlock()
	pbft.ExecuteRequest(msg)
	*reply = true
	return nil
}

func (pbft *PBFT) ExecuteRequest(msg CombinedMessage) {
	pbft.mu.Lock()
	if pbft.viewChangeTriggered {
		pbft.mu.Unlock()
		return
	}
	logger.Printf("Replica %d executing request with sequence number %d", pbft.replicaID, msg.SignedMessage.Sequence)

	// if msg.SignedMessage.Sequence == pbft.executedSeq+1 {
	message, exists := pbft.requestData[msg.SignedMessage.Sequence]
	if !exists {
		logger.Printf("Request data not found for sequence %d", msg.SignedMessage.Sequence)
		pbft.mu.Unlock()
		return
	}
	requestKey := fmt.Sprintf("%s:%d", message.ClientReq.ClientID, message.ClientReq.Timestamp)
	if pbft.lastReplies[requestKey] {
		logger.Printf("Replica %d execution aborted because of transaction complete for sequence number %d", pbft.replicaID, msg.SignedMessage.Sequence)
		pbft.mu.Unlock()
		return
	}
	tx := message.ClientReq.Transaction

	response := Response{
		ViewNumber: pbft.view,
		ReplicaID:  pbft.replicaID,
		Timestamp:  message.ClientReq.Timestamp,
		ClientID:   message.ClientReq.ClientID,
	}

	if pbft.balances[tx.Sender] >= tx.Amount {
		pbft.balances[tx.Sender] -= tx.Amount
		pbft.balances[tx.Receiver] += tx.Amount
		response.Result = fmt.Sprintf("Transaction executed: %s -> %s for %d", tx.Sender, tx.Receiver, tx.Amount)
		response.Success = true
		logEntry := fmt.Sprintf("Transaction executed: %s -> %s for %d", tx.Sender, tx.Receiver, tx.Amount)
		pbft.transactionLog = append(pbft.transactionLog, logEntry)
	} else {
		response.Result = fmt.Sprintf("Transaction failed due to insufficient balance: %s -> %s for %d", tx.Sender, tx.Receiver, tx.Amount)
		response.Success = false
		logEntry := fmt.Sprintf("Transaction failed: %s -> %s for %d", tx.Sender, tx.Receiver, tx.Amount)
		pbft.transactionLog = append(pbft.transactionLog, logEntry)
	}
	dataToVerify := fmt.Sprintf("%d%d%s%d%s%t", response.ViewNumber, response.Timestamp, response.ClientID, response.ReplicaID, response.Result, response.Success)
	hash := sha256.Sum256([]byte(dataToVerify))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, pbft.privateKey, 0, hash[:])
	signedResponse := SignedResponse{
		Reply:     response,
		Signature: signature,
	}
	pbft.statusMap[msg.SignedMessage.Sequence] = "E"

	pbft.lastReplies[requestKey] = true
	pbft.executedSeq = msg.SignedMessage.Sequence
	pbft.pendingTrans--
	if pbft.pendingTrans > 0 {
		pbft.isActiveTimer = true
		pbft.mu.Unlock()
		pbft.startTimer1()
		// pbft.mu.Lock()
	} else {
		if pbft.isActiveTimer {
			pbft.isActiveTimer = false
			pbft.mu.Unlock()
			pbft.stopTimer1()
		} else {
			pbft.mu.Unlock()
		}
	}
	// pbft.mu.Unlock()
	go call("localhost:9000", "Dispatcher.HandleReply", signedResponse, nil)
}

func (pbft *PBFT) StartViewChange() {
	pbft.mu.Lock()
	pbft.viewChangeTriggered = true

	pbft.view++
	pbft.primaryID = pbft.view % len(pbft.peers)
	// pbft.viewChangeMessages = make(map[int][]ViewChangeMessage)
	logger.Printf("[StartViewChange] Replica %d initiating view change to view %d", pbft.replicaID, pbft.view)

	var prepareSet []PrepareMessage
	for seq, req := range pbft.requestData {
		if (seq > pbft.executedSeq) && (pbft.statusMap[seq] != "PP" && pbft.statusMap[seq] != "X") {
			message := SignedPrepareMessage{
				View:     req.View,
				Sequence: req.Sequence,
				Digest:   req.Digest,
			}
			prepareSet = append(prepareSet, PrepareMessage{SignedMessage: message, Signature: pbft.thresholdSignatures[seq]})
		}
	}

	viewChange := SignedViewChangeMessage{
		View:      pbft.view,
		ReplicaID: pbft.replicaID,
		SeqNum:    pbft.executedSeq,
		Prepare:   prepareSet,
	}
	viewChangeMessage := ViewChangeMessage{
		SignedMessage: viewChange,
	}
	viewChangeMessage.Signature, _ = SignStruct(viewChange, pbft.privateKey)
	pbft.mu.Unlock()
	for _, peer := range pbft.peers {
		if peer != pbft.peers[pbft.replicaID] {
			var reply bool
			go call(peer, "PBFT.HandleViewChange", viewChangeMessage, &reply)
		}
	}

}

func (pbft *PBFT) HandleViewChange(msg ViewChangeMessage, reply *bool) error {
	pbft.mu.Lock()
	// defer pbft.mu.Unlock()
	logger.Printf("[HandleViewChange] Replica %d received ViewChange message for view %d from replica %d", pbft.replicaID, msg.SignedMessage.View, msg.SignedMessage.ReplicaID)

	if !VerifyStructSignature(msg.SignedMessage, msg.Signature, pbft.replicaKeys[msg.SignedMessage.ReplicaID]) {
		logger.Printf("Replica %d received invalid view change signature from replica %d", pbft.replicaID, msg.SignedMessage.ReplicaID)
		pbft.mu.Unlock()
		return fmt.Errorf("invalid view change message")
	}

	pbft.viewChangeMessages[msg.SignedMessage.View] = append(pbft.viewChangeMessages[msg.SignedMessage.View], msg)
	// logger.Printf("[HandleViewChange] Replica %d has length of ViewChange messages for view %d is %d", pbft.replicaID, msg.SignedMessage.View, len(pbft.viewChangeMessages[msg.SignedMessage.View]))
	if len(pbft.viewChangeMessages[msg.SignedMessage.View]) == 2*f+1 {
		pbft.mu.Unlock()
		pbft.startTimer2()
		pbft.mu.Lock()
	}

	if pbft.replicaID == msg.SignedMessage.View%len(pbft.peers) && len(pbft.viewChangeMessages[msg.SignedMessage.View]) == f+1 {
		if pbft.byzantine {
			logger.Printf("[HandleViewChange] Replica %d (primary) is byzantine unable to send New View message for view %d", pbft.replicaID, msg.SignedMessage.View)
			pbft.mu.Unlock()
			return nil
		} else {
			logger.Printf("[HandleViewChange] Replica %d (primary) received sufficient ViewChange messages for view %d, starting new view", pbft.replicaID, msg.SignedMessage.View)
			pbft.mu.Unlock()
			pbft.StartNewView(msg.SignedMessage.View)
			pbft.mu.Lock()
		}
	}
	pbft.mu.Unlock()
	*reply = true
	return nil
}

func (pbft *PBFT) StartNewView(view int) {
	pbft.mu.Lock()
	logger.Printf("[StartNewView] Replica %d starting new view %d", pbft.replicaID, view)
	uniqueSequences := make(map[string]bool)
	var preprepareSet []PrePrepareMessage
	for _, msg := range pbft.viewChangeMessages[view] {
		for _, prepare := range msg.SignedMessage.Prepare {
			key := fmt.Sprintf("%d_%d", prepare.SignedMessage.View, prepare.SignedMessage.Sequence)
			if uniqueSequences[key] {
				continue
			}
			messageVerifyHash, _ := HashMessage(prepare.SignedMessage)
			err := bls.Verify(suite, pbft.publicPoly.Commit(), messageVerifyHash, prepare.Signature)
			if err != nil {
				continue
			}
			message := SignedPrePrepareMessage{
				View:     view,
				Sequence: prepare.SignedMessage.Sequence,
				Digest:   prepare.SignedMessage.Digest,
			}
			preprepareMessage := PrePrepareMessage{
				SignedMessage: message,
			}
			preprepareMessage.Signature, _ = SignStruct(message, pbft.privateKey)
			preprepareSet = append(preprepareSet, preprepareMessage)
			uniqueSequences[key] = true
		}
	}
	// } else {
	// 	message := SignedPrePrepareMessage{
	// 		View:     view,
	// 		Sequence: pbft.sequenceNum,
	// 		Digest:   nil,
	// 	}
	// 	preprepareMessage := PrePrepareMessage{
	// 		SignedMessage: message,
	// 	}
	// 	preprepareMessage.Signature, _ = SignStruct(message, pbft.privateKey)
	// 	preprepareSet = append(preprepareSet, preprepareMessage)
	// }

	newViewMsg := SignedNewViewMessage{
		View:                view,
		ValidViewChanges:    pbft.viewChangeMessages[view],
		OutstandingRequests: preprepareSet,
	}
	viewMsg := NewViewMessage{
		SignedMessage: newViewMsg,
	}
	viewMsg.Signature, _ = SignStruct(newViewMsg, pbft.privateKey)
	// logEntry := pbft.formatNewViewMessage(view, pbft.viewChangeMessages[view], preprepareSet)
	pbft.newViewLogMessages = append(pbft.newViewLogMessages, viewMsg)
	pbft.mu.Unlock()

	for _, peer := range pbft.peers {
		var reply bool
		logger.Printf("[StartNewView] Sending NewView message for view %d to port %s", view, peer)
		if peer != pbft.peers[pbft.replicaID] {
			go call(peer, "PBFT.HandleNewView", viewMsg, &reply)
		} else {
			pbft.HandleNewView(viewMsg, &reply)
		}
	}
}

func (pbft *PBFT) HandleNewView(msg NewViewMessage, reply *bool) error {
	pbft.mu.Lock()
	// defer pbft.mu.Unlock()
	logger.Printf("[HandleNewView] Replica %d received NewView message for view %d", pbft.replicaID, msg.SignedMessage.View)

	if !VerifyStructSignature(msg.SignedMessage, msg.Signature, pbft.replicaKeys[msg.SignedMessage.View%len(pbft.peers)]) {
		logger.Printf("Replica %d received invalid NewView signature from primary %d", pbft.replicaID, pbft.primaryID)
		pbft.mu.Unlock()
		return fmt.Errorf("invalid new view message")
	}

	logger.Printf("[HandleNewView] Replica %d accepted NewView for view %d", pbft.replicaID, msg.SignedMessage.View)
	pbft.view = msg.SignedMessage.View
	pbft.primaryID = pbft.view % len(pbft.peers)
	pbft.viewChangeTriggered = false
	leaderPort = pbft.peers[pbft.primaryID]

	if len(msg.SignedMessage.OutstandingRequests) == 0 {
		logger.Printf("[HandleNewView] Zero PrePrepare messages to process in view %d", pbft.view)
		pbft.mu.Unlock()
		return nil
	}
	pbft.mu.Unlock()

	for _, preprepare := range msg.SignedMessage.OutstandingRequests {
		if !VerifyStructSignature(preprepare.SignedMessage, preprepare.Signature, pbft.replicaKeys[pbft.primaryID]) {
			logger.Printf("Replica %d received invalid preprepare signature from primary %d in new view", pbft.replicaID, pbft.primaryID)
			continue
		}
		if preprepare.SignedMessage.View == pbft.view {
			logger.Printf("[HandleNewView] Processing outstanding PrePrepare for sequence %d in view %d", preprepare.SignedMessage.Sequence, pbft.view)
			// pbft.mu.Unlock()
			pbft.stopTimer2()
			var reply bool
			pbft.HandlePrePrepare(preprepare, &reply)
			// pbft.mu.Lock()
		}
	}
	*reply = true
	return nil
}

func (pbft *PBFT) startTimer1() {
	if pbft.timer1 != nil {
		pbft.timer1.Stop()
	}
	logger.Printf("[startTimer1] Timer1 started/reset for replica %d in view %d", pbft.replicaID, pbft.view)
	pbft.timer1 = time.AfterFunc(3*time.Second, func() {
		logger.Printf("[startTimer1] Timer1 expired for replica %d in view %d, initiating view change", pbft.replicaID, pbft.view)
		pbft.StartViewChange()
	})
}

func (pbft *PBFT) startTimer2() {
	if pbft.timer2 != nil {
		pbft.timer2.Stop()
	}
	logger.Printf("[startTimer2] Timer2 started/reset for replica %d in view %d", pbft.replicaID, pbft.view)
	pbft.timer2 = time.AfterFunc(3*time.Second, func() {
		logger.Printf("[startTimer2] Timer2 expired for replica %d, indicating new view has not been received in time. initiating view change", pbft.replicaID)
		pbft.StartViewChange()
	})
}

func (pbft *PBFT) stopTimer1() {
	if pbft.timer1 != nil {
		logger.Printf("[stopTimer1] Timer1 stopped for replica %d", pbft.replicaID)
		pbft.timer1.Stop()
	}
}

func (pbft *PBFT) stopTimer2() {
	if pbft.timer2 != nil {
		logger.Printf("[stopTimer2] Timer2 stopped for replica %d", pbft.replicaID)
		pbft.timer2.Stop()
	}
}

func (pbft *PBFT) HandleRequest(request ClientRequest, reply *bool) error {
	pbft.mu.Lock()
	if pbft.viewChangeTriggered {
		pbft.mu.Unlock()
		return nil
	}

	if pbft.view != pbft.primaryID {
		primary := pbft.peers[pbft.primaryID]
		pbft.mu.Unlock()
		go call(primary, "PBFT.HandleRequest", request, nil)
		return nil
	}
	clientPublicKey := pbft.clientKeys[request.ClientID]

	if !VerifyRequestSignature(&request, clientPublicKey) {
		pbft.mu.Unlock()
		return nil
	}

	logger.Printf("leader is %d and transaction is %v and view number is %d and timestamp is %v \n", pbft.primaryID, request.Transaction, pbft.view, request.Timestamp)
	currentSeq := pbft.sequenceNum
	pbft.sequenceNum++
	pbft.mu.Unlock()
	pbft.PrePrepare(request, currentSeq)

	return nil
}

func SignStruct(data interface{}, privateKey *rsa.PrivateKey) ([]byte, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data to JSON: %w", err)
	}

	hash := sha256.Sum256(jsonData)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, 0, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature, nil
}

func VerifyStructSignature(data interface{}, signature []byte, publicKey *rsa.PublicKey) bool {
	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.Printf("failed to marshal data to JSON: %v", err)
		return false
	}

	hash := sha256.Sum256(jsonData)

	err = rsa.VerifyPKCS1v15(publicKey, 0, hash[:], signature)
	if err != nil {
		logger.Printf("signature verification failed: %v", err)
		return false
	}

	return true
}

func HashMessage(data interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data to JSON: %w", err)
	}
	hash := sha256.Sum256(jsonData)
	return hash[:], nil
}

func NewPBFTServer(replicaID, primaryID int, peers []string, privateKey *rsa.PrivateKey, clientKeys map[string]*rsa.PublicKey,
	replicaKeys map[int]*rsa.PublicKey, replicaShare *share.PriShare, publicPoly *share.PubPoly, replicaShareN *share.PriShare, publicPolyN *share.PubPoly) *PBFT {
	// db, err := initDB(replicaID)
	// if err != nil {
	// 	logger.Fatalf("Database initialization failed: %v", err)
	// }

	pbft := &PBFT{}
	pbft.mu = sync.Mutex{}
	pbft.view = 0
	pbft.primaryID = primaryID
	// pbft.checkpointSeq = 0
	pbft.sequenceNum = 1
	pbft.executedSeq = 0
	pbft.peers = peers
	// pbft.db = db
	pbft.replicaID = replicaID
	pbft.byzantine = false
	pbft.privateKey = privateKey
	pbft.publicKey = &privateKey.PublicKey
	pbft.clientKeys = clientKeys
	pbft.replicaKeys = replicaKeys
	pbft.prepareMessages = make(map[int][][]byte)
	pbft.prepareMessagesN = make(map[int][][]byte)
	pbft.commitMessages = make(map[int][][]byte)
	pbft.priPoly = replicaShare
	pbft.publicPoly = publicPoly
	pbft.priPolyN = replicaShareN
	pbft.publicPolyN = publicPolyN
	pbft.pendingResponses = make(map[int]*Response)
	pbft.statusMap = make(map[int]string)
	pbft.transactionLog = []string{}
	pbft.requestData = make(map[int]SignedPrePrepareMessage)
	pbft.pendingTrans = 0
	pbft.thresholdSignatures = make(map[int][]byte)
	pbft.viewChangeMessages = make(map[int][]ViewChangeMessage)
	pbft.newViewLogMessages = []NewViewMessage{}
	pbft.viewChangeTriggered = false
	pbft.lastReplies = make(map[string]bool)
	pbft.isActiveTimer = false

	rpcs := rpc.NewServer()
	rpcs.Register(pbft)

	l, e := net.Listen("tcp", peers[replicaID])
	if e != nil {
		logger.Fatal("listen error:", e)
	}
	pbft.l = l

	go func() {
		for {
			if !pbft.dead {
				conn, err := pbft.l.Accept()
				if err == nil && !pbft.dead {
					go rpcs.ServeConn(conn)
				} else if err != nil && !pbft.dead {
					logger.Printf("Paxos(%v) accept: %v\n", replicaID, err.Error())
				}
			}
		}
	}()

	return pbft
}

func (pbft *PBFT) InitializeBalances(clientIDs []string, initialBalance int) {
	pbft.balances = make(map[string]int)
	for _, clientID := range clientIDs {
		pbft.balances[clientID] = initialBalance
	}
}

func (pbft *PBFT) PrintDB() map[string]int {
	balancesCopy := make(map[string]int)
	for clientID, balance := range pbft.balances {
		balancesCopy[clientID] = balance
	}
	return balancesCopy
}

func (pbft *PBFT) PrintLog() []string {
	logCopy := make([]string, len(pbft.transactionLog))
	copy(logCopy, pbft.transactionLog)
	return logCopy
}

func (pbft *PBFT) PrintStatus(sequenceNum int) string {
	status, exists := pbft.statusMap[sequenceNum]
	if !exists {
		status = "X"
	}
	return status
}

func (pbft *PBFT) PrintView() {
	fmt.Printf("Replica %d: Displaying all NEW-VIEW messages:\n", pbft.replicaID)
	for _, newViewMsg := range pbft.newViewLogMessages {
		fmt.Printf("  NEW-VIEW for View %d\n", newViewMsg.SignedMessage.View)
		fmt.Println("    View-Change Messages:")
		for _, viewChange := range newViewMsg.SignedMessage.ValidViewChanges {
			fmt.Printf("      View-Change from Replica %d: View=%d, Sequence=%d\n",
				viewChange.SignedMessage.ReplicaID, viewChange.SignedMessage.View, viewChange.SignedMessage.SeqNum)
			for _, prepare := range viewChange.SignedMessage.Prepare {
				fmt.Printf("        Prepare: Sequence=%d, Digest=%x\n", prepare.SignedMessage.Sequence, prepare.SignedMessage.Digest)
			}
		}
		fmt.Println("    Outstanding Requests (PrePrepare Messages):")
		for _, preprepare := range newViewMsg.SignedMessage.OutstandingRequests {
			fmt.Printf("      PrePrepare: View=%d, Sequence=%d, Digest=%x\n",
				preprepare.SignedMessage.View, preprepare.SignedMessage.Sequence, preprepare.SignedMessage.Digest)
		}
		fmt.Println("  -----")
	}
}

func (pbft *PBFT) Kill() {
	pbft.mu.Lock()
	defer pbft.mu.Unlock()
	pbft.dead = true
	if pbft.l != nil {
		pbft.l.Close()
	}
	logger.Printf("Server %d set to inactive", pbft.replicaID+1)
}

func call(srv string, name string, args interface{}, reply interface{}) bool {
	c, err := rpc.Dial("tcp", srv)
	if err != nil {
		logger.Printf("Failed to connect to peer %s: %v", srv, err)
		return false
	}
	defer c.Close()
	err = c.Call(name, args, reply)
	if err != nil {
		logger.Println(err)
		return false
	}
	return true
}
