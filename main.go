package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	numSigners   = 7
	m            = 5
	numCommitees = 4
	nodeWIFs     = "node_wifs.txt"
	commiteeWIFs = "commitee_wifs.txt"
)

type Comb struct {
	Pubs   []*btcec.PublicKey
	Indexs []int
}

type AggregateComb struct {
	Agg    *musig2.AggregateKey
	Indexs []int
}

var net = chaincfg.TestNet3Params
var Method string

func init() {
	flag.StringVar(&Method, "m", "", "choose method to run:\n"+
		"  -m genKeypairs\n"+
		"  -m genTaprootAddress\n"+
		"  -m sendTx\ns")
	flag.Parse()
}

func main() {
	switch Method {
	case "genKeypairs":
		GeneratePrivateKeysInFile(numSigners, nodeWIFs)
		GeneratePrivateKeysInFile(numCommitees, commiteeWIFs)
	case "TestSingleSignTaproot":
		// Read commitee signers
		cSignerKeys := make([]*btcec.PrivateKey, numCommitees)
		cSignSet := make([]*btcec.PublicKey, numCommitees)
		// open file
		f2, err := os.Open(commiteeWIFs)
		if err != nil {
			panic(fmt.Sprintf("os.Open commitee wif error: %v", err))
		}
		// remember to close the file at the end of the program
		defer f2.Close()
		// read the file line by line using scanner
		scanner2 := bufio.NewScanner(f2)
		idx := 0
		for scanner2.Scan() {
			wif, err := btcutil.DecodeWIF(scanner2.Text())
			if err != nil {
				panic(fmt.Sprintf("btcutil.DecodeWIF error: %v", err))
			}

			cSignerKeys[idx] = wif.PrivKey
			cSignSet[idx] = wif.PrivKey.PubKey()
			idx++
		}
		aggregatedCommiteeKeys, _, _, err := musig2.AggregateKeys(cSignSet, false)
		if err != nil {
			panic(fmt.Sprintf("commitee keys musig2.AggregateKeys error: %v", err))
		}
		tapLeafs := make([]txscript.TapLeaf, len(cSignSet))
		for idx, pk := range cSignSet {
			builder := txscript.NewScriptBuilder()
			builder.AddData(schnorr.SerializePubKey(pk))
			builder.AddOp(txscript.OP_CHECKSIG)
			script, err := builder.Script()
			if err != nil {
				panic(fmt.Sprintf("builder.Script() error: %v", err))
			}
			tapLeaf := txscript.NewBaseTapLeaf(script)
			tapLeafs[idx] = tapLeaf
		}
		tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeafs...)
		rootHash := tapScriptTree.RootNode.TapHash()
		taprootOutputKey := txscript.ComputeTaprootOutputKey(
			aggregatedCommiteeKeys.FinalKey, rootHash[:],
		)
		address, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootOutputKey), &net)
		if err != nil {
			panic(fmt.Sprintf("btcutil.NewAddressTaproot error: %v", err))
		}
		fmt.Println("single sign taproot address is: ", address.EncodeAddress())

		// Build raw tx and sign
		rawTx := BuildSingleSignRawTx()
		ctrlBlock := tapScriptTree.LeafMerkleProofs[0].ToControlBlock(aggregatedCommiteeKeys.FinalKey)
		builder := txscript.NewScriptBuilder()
		builder.AddData(schnorr.SerializePubKey(cSignSet[0]))
		builder.AddOp(txscript.OP_CHECKSIG)
		script, err := builder.Script()
		if err != nil {
			panic(fmt.Sprintf("builder.Script() error: %v", err))
		}
		tapLeaf := txscript.NewBaseTapLeaf(script)
		sig := SignTapscriptRawTransaction(rawTx, tapLeaf, cSignerKeys[0])
		ctrlBlockBytes, err := ctrlBlock.ToBytes()
		if err != nil {
			panic(fmt.Sprintf("ctrlBlock.ToBytes error: %v", err))
		}
		rawTx.TxIn[0].Witness = wire.TxWitness{sig, script, ctrlBlockBytes}

		// send tx
		var rpcConfig = &rpcclient.ConnConfig{
			Host:         "bitcoin-testnet-archive.allthatnode.com",
			User:         "",
			Pass:         "test",
			HTTPPostMode: true,  // Bitcoin core only supports HTTP POST mode
			DisableTLS:   false, // Bitcoin core does not provide TLS by default
		}
		client, err := rpcclient.New(rpcConfig, nil)
		if err != nil {
			panic(fmt.Sprintf("rpcclient.New error: %v", err))
		}
		defer client.Shutdown()

		// Get the current block count.
		blockCount, err := client.GetBlockCount()
		if err != nil {
			panic(fmt.Sprintf("rpcclient.New error: %v", err))
		}
		fmt.Println("lastest block count: ", blockCount)

		hash, err := client.SendRawTransaction(rawTx, true)
		if err != nil {
			panic(fmt.Sprintf("client.SendRawTransaction error: %v", err))
		}
		// 867331d735469623406fae8618eafa013ef48af1b031c228ca0068212a92425a
		fmt.Println("send tx success: ", hash.String())

	case "TestMultiSignTaproot":
		// First read the set of node signers
		signerKeys := make([]*btcec.PrivateKey, numSigners)
		signSet := make([]*btcec.PublicKey, numSigners)
		// open file
		f1, err := os.Open(nodeWIFs)
		if err != nil {
			panic(fmt.Sprintf("os.Open node wif error: %v", err))
		}
		// remember to close the file at the end of the program
		defer f1.Close()
		// read the file line by line using scanner
		scanner1 := bufio.NewScanner(f1)
		idx := 0
		for scanner1.Scan() {
			wif, err := btcutil.DecodeWIF(scanner1.Text())
			if err != nil {
				panic(fmt.Sprintf("btcutil.DecodeWIF error: %v", err))
			}

			signerKeys[idx] = wif.PrivKey
			signSet[idx] = wif.PrivKey.PubKey()
			idx++
		}

		// Read commitee signers
		cSignerKeys := make([]*btcec.PrivateKey, numCommitees)
		cSignSet := make([]*btcec.PublicKey, numCommitees)
		// open file
		f2, err := os.Open(commiteeWIFs)
		if err != nil {
			panic(fmt.Sprintf("os.Open commitee wif error: %v", err))
		}
		// remember to close the file at the end of the program
		defer f2.Close()
		// read the file line by line using scanner
		scanner2 := bufio.NewScanner(f2)
		idx = 0
		for scanner2.Scan() {
			wif, err := btcutil.DecodeWIF(scanner2.Text())
			if err != nil {
				panic(fmt.Sprintf("btcutil.DecodeWIF error: %v", err))
			}

			cSignerKeys[idx] = wif.PrivKey
			cSignSet[idx] = wif.PrivKey.PubKey()
			idx++
		}

		timeStart := time.Now()

		// C(numSigners, m)
		indexs := combineResult(numSigners, m)
		signerCombList := findByIndexs(signSet, indexs)

		// Aggregate each combination, so we get aggregate key list
		aggregatedCombList := make([]*AggregateComb, len(signerCombList))
		for idx, signerComb := range signerCombList {
			aggregatedKey, _, _, err := musig2.AggregateKeys(signerComb.Pubs, false)
			if err != nil {
				panic(fmt.Sprintf("musig2.AggregateKeys error: %v", err))
			}
			aggregatedComb := &AggregateComb{
				Agg:    aggregatedKey,
				Indexs: signerComb.Indexs,
			}
			aggregatedCombList[idx] = aggregatedComb
		}
		// sort
		sort.SliceStable(aggregatedCombList, func(i, j int) bool {
			return hex.EncodeToString(schnorr.SerializePubKey(aggregatedCombList[i].Agg.FinalKey)) <
				hex.EncodeToString(schnorr.SerializePubKey(aggregatedCombList[j].Agg.FinalKey))
		})

		// Aggregate commitee keys
		aggregatedCommiteeKeys, _, _, err := musig2.AggregateKeys(cSignSet, false)
		if err != nil {
			panic(fmt.Sprintf("commitee keys musig2.AggregateKeys error: %v", err))
		}

		// Gen all keys aggregate, use as internal key according to BIP341: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
		aggregatedAllKeys, _, _, err := musig2.AggregateKeys(append(cSignSet, signSet...), false)
		if err != nil {
			panic(fmt.Sprintf("all keys musig2.AggregateKeys error: %v", err))
		}

		// Gen taproot tree from aggregate key list
		tapLeafs := make([]txscript.TapLeaf, len(aggregatedCombList))
		for idx, aggregatedComb := range aggregatedCombList {
			aggregatedKey := aggregatedComb.Agg
			builder := txscript.NewScriptBuilder()
			builder.AddData(schnorr.SerializePubKey(aggregatedCommiteeKeys.FinalKey))
			builder.AddOp(txscript.OP_CHECKSIG)
			builder.AddData(schnorr.SerializePubKey(aggregatedKey.FinalKey))
			builder.AddOp(txscript.OP_CHECKSIGADD)
			builder.AddInt64(2)
			builder.AddOp(txscript.OP_NUMEQUAL)
			script, err := builder.Script()
			if err != nil {
				panic(fmt.Sprintf("builder.Script() error: %v", err))
			}
			tapLeaf := txscript.NewBaseTapLeaf(script)
			tapLeafs[idx] = tapLeaf
		}
		tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeafs...)
		rootHash := tapScriptTree.RootNode.TapHash()
		taprootOutputKey := txscript.ComputeTaprootOutputKey(
			aggregatedAllKeys.FinalKey, rootHash[:],
		)
		address, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootOutputKey), &net)
		if err != nil {
			panic(fmt.Sprintf("btcutil.NewAddressTaproot error: %v", err))
		}

		fmt.Println("multi sign taproot address is: ", address.EncodeAddress())
		timeEnd := time.Now()
		fmt.Println("construct taproot time consume:", timeEnd.Sub(timeStart))

		// // Build raw tx and sign
		// rawTx := BuildMultiSignRawTx()

		// ctrlBlock := tapScriptTree.LeafMerkleProofs[0].ToControlBlock(aggregatedCommiteeKeys.FinalKey)
		// builder := txscript.NewScriptBuilder()
		// builder.AddData(schnorr.SerializePubKey(cSignSet[0]))
		// builder.AddOp(txscript.OP_CHECKSIG)
		// script, err := builder.Script()
		// if err != nil {
		// 	panic(fmt.Sprintf("builder.Script() error: %v", err))
		// }
		// tapLeaf := txscript.NewBaseTapLeaf(script)
		// sig := SignTapscriptRawTransaction(rawTx, tapLeaf, cSignerKeys[0])
		// ctrlBlockBytes, err := ctrlBlock.ToBytes()
		// if err != nil {
		// 	panic(fmt.Sprintf("ctrlBlock.ToBytes error: %v", err))
		// }
		// rawTx.TxIn[0].Witness = wire.TxWitness{sig, script, ctrlBlockBytes}

		// // send tx
		// var rpcConfig = &rpcclient.ConnConfig{
		// 	Host:         "bitcoin-testnet-archive.allthatnode.com",
		// 	User:         "",
		// 	Pass:         "test",
		// 	HTTPPostMode: true,  // Bitcoin core only supports HTTP POST mode
		// 	DisableTLS:   false, // Bitcoin core does not provide TLS by default
		// }
		// client, err := rpcclient.New(rpcConfig, nil)
		// if err != nil {
		// 	panic(fmt.Sprintf("rpcclient.New error: %v", err))
		// }
		// defer client.Shutdown()

		// // Get the current block count.
		// blockCount, err := client.GetBlockCount()
		// if err != nil {
		// 	panic(fmt.Sprintf("rpcclient.New error: %v", err))
		// }
		// fmt.Println("lastest block count: ", blockCount)

		// hash, err := client.SendRawTransaction(rawTx, true)
		// if err != nil {
		// 	panic(fmt.Sprintf("client.SendRawTransaction error: %v", err))
		// }

		// fmt.Println("send tx success: ", hash.String())
	}
}
