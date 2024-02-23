package main

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
)

const (
	numSigners  = 7
	m           = 5
	numCommitee = 4
)

func main() {
	// First generate the set of multisign signers
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

	// Generate four commitee signers
	cSignerKeys := make([]*btcec.PrivateKey, numCommitee)
	cSignSet := make([]*btcec.PublicKey, numCommitee)
	for i := 0; i < numCommitee; i++ {
		privKey, err := btcec.NewPrivateKey()
		if err != nil {
			panic(fmt.Sprintf("unable to gen priv key: %v", err))
		}

		pubKey := privKey.PubKey()

		cSignerKeys[i] = privKey
		cSignSet[i] = pubKey
	}

	timeStart := time.Now()

	// C(numSigners, m)
	indexs := combineResult(numSigners, m)
	signerCombList := findByIndexs(signSet, indexs)

	// Aggregate each combination, so we get aggregate key list
	aggregatedKeyList := make([]*btcec.PublicKey, len(signerCombList))
	for idx, signerComb := range signerCombList {
		aggregatedKey, _, _, err := musig2.AggregateKeys(signerComb, false)
		if err != nil {
			panic(fmt.Sprintf("musig2.AggregateKeys error: %v", err))
		}
		aggregatedKeyList[idx] = aggregatedKey.FinalKey
	}

	// Gen all keys aggregate, use as internal key according to BIP341: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
	aggregatedAllKeys, _, _, err := musig2.AggregateKeys(append(cSignSet, signSet...), false)
	if err != nil {
		panic(fmt.Sprintf("all keys musig2.AggregateKeys error: %v", err))
	}

	// Gen taproot from aggregate key list

	fmt.Println(aggregatedAllKeys)
	timeEnd := time.Now()
	fmt.Println("time consume:", timeEnd.Sub(timeStart))
}
