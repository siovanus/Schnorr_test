package main

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	numSigners = 30
	m          = 21
)

func main() {
	// First generate the set of signers along with their public keys.
	signerKeys := make([]*btcec.PrivateKey, numSigners)
	signSet := make([]*btcec.PublicKey, numSigners)
	for i := 0; i < numSigners; i++ {
		privKey, err := btcec.NewPrivateKey()
		if err != nil {
			panic(fmt.Sprintf("unable to gen priv key: %v", err))
		}

		pubKey := privKey.PubKey()

		signerKeys[i] = privKey
		signSet[i] = pubKey
	}

	timeStart := time.Now()
	indexs := combineResult(numSigners, m)
	result := findByIndexs(signSet, indexs)
	timeEnd := time.Now()
	fmt.Println("count:", len(result))
	//fmt.Println("result:", result)
	fmt.Println("time consume:", timeEnd.Sub(timeStart))
}
