package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	flowcrypto "github.com/onflow/flow-go-sdk/crypto"
)

func HighSSignatureDemo() {
	fmt.Println("*** High-S Signature Demo ***")
	fmt.Println()
	// We use Secp256k1 curve
	curve := ethcrypto.S256()

	halfCurveOrder := new(big.Int).Div(curve.Params().N, big.NewInt(2))

	seed := make([]byte, flowcrypto.MinSeedLength)
	_, err := rand.Read(seed)
	if err != nil {
		return
	}
	privateKey, err := flowcrypto.GeneratePrivateKey(flowcrypto.ECDSA_secp256k1, seed)

	msg := []byte("hello world")
	hashAlgo := flowcrypto.SHA2_256
	hasher, err := flowcrypto.NewHasher(hashAlgo)
	if err != nil {
		panic(err)
	}
	digest := hasher.ComputeHash(msg)

	signerAlice := flowcrypto.NewInMemorySigner(privateKey, hashAlgo)
	// Generate a high-S signature
	var sig []byte
	var r, s *big.Int
	for {

		sig, err = signerAlice.Sign(msg)
		if err != nil {
			panic(err)
		}
		rBytes := sig[:len(sig)/2]
		sBytes := sig[len(sig)/2:]

		r = new(big.Int).SetBytes(rBytes)
		s = new(big.Int).SetBytes(sBytes)
		// low-S signature's s value should be less than N/2
		// We aim to generate a high-s one here
		if s.Cmp(halfCurveOrder) >= 0 {
			break
		}
	}
	fmt.Printf("get high-s signature %s\n", hex.EncodeToString(sig))
	isValid, err := privateKey.PublicKey().Verify(sig, msg, hasher)
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature(high-s) is valid on flow?: %v\n", isValid)

	highSSigIsValid := ethcrypto.VerifySignature(privateKey.PublicKey().EncodeCompressed(), digest[:], sig)
	fmt.Printf("signature(high-s) is valid on ethereum?: %v\n", highSSigIsValid)

	trickR, trickS := TrickSig(r, s, curve)
	trickSig := append(trickR.Bytes(), trickS.Bytes()...)
	lowSSigIsValid := ethcrypto.VerifySignature(privateKey.PublicKey().EncodeCompressed(), digest[:], trickSig)
	fmt.Printf("trick signature(low-s) is valid on ethereum?: %v\n", lowSSigIsValid)
	fmt.Println()
}
